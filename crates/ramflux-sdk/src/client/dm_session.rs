// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

/// Read-only recv-commit evidence returned by [`RamfluxClient::recv_commit_fingerprint`]. Gated
/// behind the `itest-fingerprint` feature (realnet integration tests only; T21-A2a / CTRL-028).
#[cfg(feature = "itest-fingerprint")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvCommitFingerprint {
    /// Checkpoint event id of the main-conversation recv session, or `None` if none is committed.
    pub main_recv_checkpoint: Option<String>,
    /// Checkpoint event id of the attachment key-slot recv session, or `None` if none is committed.
    pub slot_recv_checkpoint: Option<String>,
    /// The durable gateway receive cursor for this device's inbox.
    pub receive_cursor: u64,
}

impl RamfluxClient {
    pub(crate) fn load_dm_session(
        &self,
        conversation_id: &str,
        direction: &str,
    ) -> Result<ramflux_crypto::DmSession, SdkError> {
        let checkpoint_name = dm_session_checkpoint_name(conversation_id, direction);
        if let Some(event_id) = self.projection_checkpoint(&checkpoint_name)?
            && let Some(bytes) = self.event_body(&event_id)?
        {
            let snapshot: ramflux_crypto::DmSessionSnapshot = serde_json::from_slice(&bytes)?;
            return Ok(ramflux_crypto::DmSession::from_snapshot(snapshot)?);
        }
        Err(SdkError::LocalBus(format!(
            "missing DM session for {conversation_id} direction {direction}"
        )))
    }

    pub(crate) async fn load_or_create_send_dm_session(
        &self,
        engine: &mut GatewaySessionEngine,
        message: &GatewayDirectMessage,
    ) -> Result<(ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>), SdkError> {
        if let Ok(session) = self.load_dm_session(&message.conversation_id, "send") {
            return Ok((session, None));
        }
        let recipient_device_id = message.recipient_device_id.as_deref().ok_or_else(|| {
            SdkError::LocalBus(
                "recipient_device_id is required to bootstrap a new X3DH DM session".to_owned(),
            )
        })?;
        let recipient_bundle =
            engine.fetch_prekey_bundle(recipient_device_id).await?.bundle.ok_or_else(|| {
                SdkError::LocalBus(format!("missing prekey bundle for {recipient_device_id}"))
            })?;
        self.create_send_dm_session_from_bundle(
            message,
            recipient_device_id,
            recipient_bundle,
            &engine.config.device_id,
        )
    }

    pub(crate) fn load_or_create_send_dm_session_with_prekey_url(
        &self,
        message: &GatewayDirectMessage,
        prekey_url: Option<&str>,
        own_device_id: &str,
    ) -> Result<(ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>), SdkError> {
        if let Ok(session) = self.load_dm_session(&message.conversation_id, "send") {
            return Ok((session, None));
        }
        let recipient_device_id = message.recipient_device_id.as_deref().ok_or_else(|| {
            SdkError::LocalBus(
                "recipient_device_id is required to bootstrap a new X3DH DM session".to_owned(),
            )
        })?;
        let prekey_url = prekey_url.ok_or_else(|| {
            SdkError::LocalBus("prekey_http_url is required to fetch recipient prekeys".to_owned())
        })?;
        let recipient_bundle =
            sdk_fetch_prekey_bundle(prekey_url, recipient_device_id)?.bundle.ok_or_else(|| {
                SdkError::LocalBus(format!("missing prekey bundle for {recipient_device_id}"))
            })?;
        self.create_send_dm_session_from_bundle(
            message,
            recipient_device_id,
            recipient_bundle,
            own_device_id,
        )
    }

    pub(crate) fn create_send_dm_session_from_bundle(
        &self,
        message: &GatewayDirectMessage,
        recipient_device_id: &str,
        recipient_bundle: ramflux_crypto::PrekeyBundle,
        own_device_id: &str,
    ) -> Result<(ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>), SdkError> {
        let own_state = self.load_x3dh_private_state(own_device_id)?;
        let own_identity = X25519KeyPair::from_seed(own_state.identity_seed);
        let ephemeral = X25519KeyPair::random()?;
        let bundle_hash = prekey_bundle_hash(&recipient_bundle)?;
        let initiator_device_id_hash = dm_device_id_hash(own_device_id);
        let recipient_device_id_hash = dm_device_id_hash(recipient_device_id);
        let output = ramflux_crypto::x3dh_initiator(&X3dhInitiatorInput {
            initiator_identity: &own_identity,
            initiator_ephemeral: &ephemeral,
            initiator_device_id_hash,
            recipient_device_id_hash,
            recipient_bundle: &recipient_bundle,
            associated_data: dm_associated_data(&message.conversation_id),
            prekey_bundle_hash: &bundle_hash,
            initial_ratchet_public: ephemeral.public,
        })?;
        let session = ramflux_crypto::DmSession::initiator_with_remote_ratchet(
            output.root_seed,
            initiator_device_id_hash,
            recipient_device_id_hash,
            output.bootstrap_transcript_hash,
            &ephemeral,
            recipient_bundle.signed_prekey,
        )?;
        let header = SdkDmX3dhHeader {
            initiator_identity_public: own_identity.public,
            initiator_ephemeral_public: ephemeral.public,
            initiator_device_id_hash,
            recipient_device_id_hash,
            recipient_device_id: recipient_device_id.to_owned(),
            recipient_signed_prekey_id: recipient_bundle.signed_prekey_id,
            recipient_one_time_prekey_id: recipient_bundle.one_time_prekey_id,
            prekey_bundle_hash: bundle_hash,
            bootstrap_transcript_hash: output.bootstrap_transcript_hash,
            session_id: session.session_id.clone(),
        };
        Ok((session, Some(header)))
    }

    pub(crate) fn load_or_create_recv_dm_session(
        &self,
        conversation_id: &str,
        header: Option<&SdkDmX3dhHeader>,
    ) -> Result<ramflux_crypto::DmSession, SdkError> {
        if let Ok(session) = self.load_dm_session(conversation_id, "recv") {
            return Ok(session);
        }
        let header = header.ok_or_else(|| {
            SdkError::LocalBus(format!(
                "missing X3DH header for new inbound DM session {conversation_id}"
            ))
        })?;
        let own_state = self.load_x3dh_private_state(&header.recipient_device_id)?;
        if own_state.signed_prekey_id != header.recipient_signed_prekey_id {
            return Err(SdkError::LocalBus(format!(
                "signed prekey id mismatch for {}",
                header.recipient_device_id
            )));
        }
        let identity = X25519KeyPair::from_seed(own_state.identity_seed);
        let signed_prekey = X25519KeyPair::from_seed(own_state.signed_prekey_seed);
        let output = ramflux_crypto::x3dh_recipient(&X3dhRecipientInput {
            recipient_identity: &identity,
            recipient_signed_prekey: &signed_prekey,
            recipient_one_time_prekey: None,
            initiator_identity_public: header.initiator_identity_public,
            initiator_ephemeral_public: header.initiator_ephemeral_public,
            initiator_device_id_hash: header.initiator_device_id_hash,
            recipient_device_id_hash: header.recipient_device_id_hash,
            recipient_signed_prekey_id: &header.recipient_signed_prekey_id,
            recipient_one_time_prekey_id: header.recipient_one_time_prekey_id.as_deref(),
            associated_data: dm_associated_data(conversation_id),
            prekey_bundle_hash: &header.prekey_bundle_hash,
            initial_ratchet_public: header.initiator_ephemeral_public,
        })?;
        if output.bootstrap_transcript_hash != header.bootstrap_transcript_hash {
            return Err(SdkError::LocalBus("X3DH bootstrap transcript hash mismatch".to_owned()));
        }
        ramflux_crypto::DmSession::recipient_with_local_ratchet(
            output.root_seed,
            header.recipient_device_id_hash,
            header.initiator_device_id_hash,
            output.bootstrap_transcript_hash,
            &signed_prekey,
        )
        .map_err(SdkError::from)
    }

    pub(crate) fn persist_dm_session(
        &self,
        conversation_id: &str,
        envelope_id: &str,
        direction: &str,
        session: &ramflux_crypto::DmSession,
    ) -> Result<(), SdkError> {
        self.persist_dm_session_snapshot(
            conversation_id,
            envelope_id,
            direction,
            &session.snapshot(),
        )
    }

    pub(crate) fn persist_dm_session_snapshot(
        &self,
        conversation_id: &str,
        envelope_id: &str,
        direction: &str,
        snapshot: &ramflux_crypto::DmSessionSnapshot,
    ) -> Result<(), SdkError> {
        let event_id = dm_session_event_id(conversation_id, direction, envelope_id);
        self.append_event(&event_id, "dm.ratchet_session", &serde_json::to_vec(snapshot)?)?;
        self.set_projection_checkpoint(
            &dm_session_checkpoint_name(conversation_id, direction),
            &event_id,
        )
    }

    /// Read-only introspection for realnet integration tests (T21-A2a / CTRL-028), gated behind the
    /// `itest-fingerprint` feature so it is never compiled into production binaries. Returns the
    /// main-conversation recv session checkpoint, the attachment key-slot recv session checkpoint,
    /// and the gateway receive cursor, so a test can assert that a failed attachment import advances
    /// none of them and a successful retry advances all of them. It exposes no control or mutation
    /// surface — every field is derived from existing read-only projection/cursor lookups.
    #[cfg(feature = "itest-fingerprint")]
    pub fn recv_commit_fingerprint(
        &self,
        conversation_id: &str,
        object_id: &str,
        recipient_device_id: &str,
        target_delivery_id: &str,
    ) -> Result<RecvCommitFingerprint, SdkError> {
        let slot_conversation_id =
            dm_attachment_slot_conversation_id(conversation_id, object_id, recipient_device_id);
        Ok(RecvCommitFingerprint {
            main_recv_checkpoint: self
                .projection_checkpoint(&dm_session_checkpoint_name(conversation_id, "recv"))?,
            slot_recv_checkpoint: self.projection_checkpoint(&dm_session_checkpoint_name(
                &slot_conversation_id,
                "recv",
            ))?,
            receive_cursor: self.gateway_receive_cursor(target_delivery_id)?,
        })
    }

    /// T21-A2a / CTRL-028: reports whether the persisted recv session checkpoint already covers
    /// `envelope_id`. When true, the entry's ratchet advanced and every side effect committed, so a
    /// receive cursor that lagged behind can be safely caught up without re-decrypting. When false,
    /// the recv session was not committed for this envelope (fresh entry, or a crash after a partial
    /// side-effect write) and the ciphertext must be re-decrypted.
    pub(crate) fn recv_session_checkpoint_at(
        &self,
        conversation_id: &str,
        envelope_id: &str,
    ) -> Result<bool, SdkError> {
        let expected = dm_session_event_id(conversation_id, "recv", envelope_id);
        Ok(self.projection_checkpoint(&dm_session_checkpoint_name(conversation_id, "recv"))?
            == Some(expected))
    }

    pub(crate) fn load_x3dh_private_state(
        &self,
        device_id: &str,
    ) -> Result<SdkX3dhPrivateState, SdkError> {
        let checkpoint = x3dh_private_checkpoint_name(device_id);
        let event_id = self.projection_checkpoint(&checkpoint)?.ok_or_else(|| {
            SdkError::LocalBus(format!("missing X3DH private state for {device_id}"))
        })?;
        let bytes = self
            .event_body(&event_id)?
            .ok_or_else(|| SdkError::LocalBus(format!("missing X3DH private event {event_id}")))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[cfg(test)]
mod t24b1_client_db_reopen_tests {
    use super::*;

    fn temp_root(test_name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir()
            .join(format!("ramflux-sdk-t24b1-{test_name}-{}-{nanos}", std::process::id()))
    }

    fn open_client(root: &std::path::Path, create: bool) -> Result<RamfluxClient, SdkError> {
        let mut client = RamfluxClient::new();
        client.open_account_index(root)?;
        if create {
            client.create_account("acct", "principal")?;
        }
        client.unlock_account("acct", b"t24b1-reopen-secret")?;
        Ok(client)
    }

    #[test]
    fn dm_snapshots_checkpoints_and_cursor_survive_client_db_reopen() -> Result<(), SdkError> {
        let root = temp_root("snapshot-checkpoint-cursor");
        let client = open_client(&root, true)?;
        let mut send =
            ramflux_crypto::DmSession::initiator([0x11; 32], [0x12; 32], [0x13; 32], [0x14; 32])?;
        let _ciphertext = send.encrypt(b"advance-send", b"conv-reopen")?;
        let send_snapshot = send.snapshot();
        client.persist_dm_session("conv-reopen", "env-send-1", "send", &send)?;

        let recv =
            ramflux_crypto::DmSession::recipient([0x21; 32], [0x22; 32], [0x23; 32], [0x24; 32])?;
        let recv_snapshot = recv.snapshot();
        client.persist_dm_session("conv-reopen", "env-recv-1", "recv", &recv)?;
        client.persist_gateway_receive_cursor("delivery-reopen", 41)?;
        drop(client);

        let reopened = open_client(&root, false)?;
        let loaded_send = reopened.load_dm_session("conv-reopen", "send")?.snapshot();
        let loaded_recv = reopened.load_dm_session("conv-reopen", "recv")?.snapshot();
        assert!(
            serde_json::to_vec(&loaded_send)? == serde_json::to_vec(&send_snapshot)?,
            "send ratchet snapshot must survive a real DB reopen"
        );
        assert!(
            serde_json::to_vec(&loaded_recv)? == serde_json::to_vec(&recv_snapshot)?,
            "recv ratchet snapshot must survive a real DB reopen"
        );
        assert!(reopened.recv_session_checkpoint_at("conv-reopen", "env-recv-1")?);
        assert_eq!(reopened.gateway_receive_cursor("delivery-reopen")?, 41);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn orphan_session_event_replay_commits_checkpoint_after_reopen() -> Result<(), SdkError> {
        let root = temp_root("orphan-session-event");
        let client = open_client(&root, true)?;
        let session =
            ramflux_crypto::DmSession::recipient([0x31; 32], [0x32; 32], [0x33; 32], [0x34; 32])?;
        let snapshot = session.snapshot();
        let event_id = dm_session_event_id("conv-orphan", "recv", "env-orphan-1");
        client.append_event(&event_id, "dm.ratchet_session", &serde_json::to_vec(&snapshot)?)?;
        assert_eq!(
            client.projection_checkpoint(&dm_session_checkpoint_name("conv-orphan", "recv"))?,
            None
        );
        drop(client);

        let reopened = open_client(&root, false)?;
        reopened.persist_dm_session_snapshot("conv-orphan", "env-orphan-1", "recv", &snapshot)?;
        assert!(reopened.recv_session_checkpoint_at("conv-orphan", "env-orphan-1")?);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn unpersisted_send_advance_is_lost_on_reopen() -> Result<(), SdkError> {
        let root = temp_root("send-window");
        let client = open_client(&root, true)?;
        let baseline =
            ramflux_crypto::DmSession::initiator([0x41; 32], [0x42; 32], [0x43; 32], [0x44; 32])?;
        client.persist_dm_session("conv-send-window", "env-baseline", "send", &baseline)?;
        let baseline_snapshot = baseline.snapshot();
        let mut accepted_but_unpersisted = baseline;
        let _ciphertext =
            accepted_but_unpersisted.encrypt(b"remote-accepted", b"conv-send-window")?;
        drop(client);

        let reopened = open_client(&root, false)?;
        let loaded = reopened.load_dm_session("conv-send-window", "send")?.snapshot();
        assert!(
            serde_json::to_vec(&loaded)? == serde_json::to_vec(&baseline_snapshot)?,
            "a remote-accepted send advance is lost when the process dies before persistence"
        );
        assert!(
            serde_json::to_vec(&loaded)?
                != serde_json::to_vec(&accepted_but_unpersisted.snapshot())?,
            "the reopened sender reuses the pre-send ratchet state"
        );
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}

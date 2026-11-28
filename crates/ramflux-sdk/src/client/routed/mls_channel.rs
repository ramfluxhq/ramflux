// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The DM facade's MLS channel (spec §3.3): find the conversation's group, seal ONE
//! `PrivateMessage` per message for every target device, open one on receive.
//!
//! The group is created and kept current by the lifecycle (D5); a send or receive without a
//! group is a typed error here, never a fallback.
use super::report;
use super::send_cache::{Binding, SealedShared};
use super::{
    GatewayDirectMessage, GatewaySessionAccess, RamfluxClient, SdkDmEncryptedEnvelope, SdkError,
    invalid,
};
use crate::client::identity_authority::HeadUse;
use crate::mls::MlsRuntime;
use crate::mls::channel::{outer_header, seal_once};
use crate::mls::lifecycle::note_sealed;
use crate::mls::order::{ConvStore, Scope};
use ramflux_mls::{MlsError, ReceivedMessage};
use zeroize::Zeroizing;

/// Exporter label of the collapse key (S-2): the key moves from the pair session to the group.
const COLLAPSE_EXPORT_LABEL: &str = "rf-collapse-v1";

/// The group of one conversation, with the runtime that holds its state.
pub(super) struct Channel {
    runtime: MlsRuntime,
    scope: Scope,
    group_id: Vec<u8>,
}

impl Channel {
    /// The collapse key of the group's current epoch (HKDF-free: the MLS exporter).
    pub(super) fn collapse_key(&self) -> Result<Zeroizing<[u8; 32]>, SdkError> {
        let secret = self.runtime.mls().export(&self.group_id, COLLAPSE_EXPORT_LABEL, &[], 32)?;
        let key = <[u8; 32]>::try_from(secret.as_slice()).map_err(|_| SdkError::Mls {
            code: "internal",
            detail: "the collapse exporter returned an unexpected length".to_owned(),
        })?;
        Ok(Zeroizing::new(key))
    }
}

/// What an opened `PrivateMessage` yields.
pub(super) struct OpenedMessage {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub group_id: Vec<u8>,
}

fn no_group() -> SdkError {
    SdkError::Mls { code: "no_group", detail: "the conversation has no MLS group yet".to_owned() }
}

impl RamfluxClient {
    fn dm_scope(&self, peer_anchor: &str) -> Result<Scope, SdkError> {
        let own = self.own_account_anchor()?;
        if own == peer_anchor { Ok(Scope::own(&own)) } else { Scope::dm(&own, peer_anchor) }
    }

    /// The sender's gate before sealing (the part of the old pair selection that is not about the
    /// pair): the local device is active, and a content send authorizes against a freshly fetched
    /// recipient authority.
    pub(super) async fn send_authority_gate(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        fresh_authority: bool,
    ) -> Result<(), SdkError> {
        let local = self.local_device_identity(&engine.config().device_id)?;
        self.require_pair_device_active(&local)?;
        let recipient = Self::qualified_recipient(message)?;
        #[cfg(any(test, feature = "test-support"))]
        let fresh_authority = fresh_authority && !self.scaffold_seal_without_fetch.get();
        let cached = self.device_identity(&recipient).and_then(|identity| {
            self.require_cached_root_authority(HeadUse::NewAuthorization, &identity)
        });
        if fresh_authority || cached.is_err() {
            self.resolve_target_principal_commitment(
                engine.config(),
                message.recipient_principal_commitment.as_deref(),
                message
                    .recipient_device_id
                    .as_deref()
                    .ok_or_else(|| invalid("recipient absent"))?,
            )
            .await?;
        }
        Ok(())
    }

    /// The group a message to `remote` is sealed in.
    pub(super) fn send_channel(
        &self,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Channel, SdkError> {
        let scope = self.dm_scope(remote.root_commitment())?;
        let runtime = MlsRuntime::open_for(self, &[remote.root_commitment()])?;
        let state =
            ConvStore::new(runtime.mls().kv()).get(&scope.conversation_id)?.ok_or_else(no_group)?;
        if state.removed {
            return Err(SdkError::Mls {
                code: "removed",
                detail: "this device was removed from the conversation group".to_owned(),
            });
        }
        Ok(Channel { runtime, scope, group_id: state.group_id })
    }

    /// Seal `inner` once: a retry (same group, epoch and plaintext) returns the record kept by the
    /// first seal; a miss opens the report once, seals once and keeps the record. Every target
    /// of the message reuses the returned bytes and opening (S-1, S-2, S-6).
    pub(super) fn seal_shared(
        &self,
        channel: &Channel,
        body: &[u8],
        inner: &[u8],
        with_report: bool,
    ) -> Result<SealedShared, SdkError> {
        let mls = channel.runtime.mls();
        let epoch = mls.status(&channel.group_id)?.epoch;
        let binding = Binding::new(body, &channel.group_id, epoch)?;
        if let Some(binding) = &binding
            && let Some(shared) = binding.load(self)?
        {
            return Ok(shared);
        }
        let opening = if with_report { Some(report::fresh_report_opening()?) } else { None };
        let plaintext = match &opening {
            Some(opening) => Zeroizing::new(
                ramflux_crypto::frame_report_plaintext(inner, opening)?.as_bytes().to_vec(),
            ),
            None => Zeroizing::new(inner.to_vec()),
        };
        let sealed =
            seal_once(mls, &mut self.seal_cache.borrow_mut(), &channel.group_id, &plaintext)?;
        if !sealed.cached {
            note_sealed(&ConvStore::new(mls.kv()), &channel.scope, sealed.epoch)?;
        }
        let shared = SealedShared { message: sealed.message, epoch: sealed.epoch, opening };
        if let Some(binding) = &binding {
            binding.persist(self, &shared)?;
        }
        Ok(shared)
    }

    /// Open one `PrivateMessage` from `remote`. The group must be the conversation's current
    /// group, or its old group inside the read-only window; the sender leaf must be the device
    /// that signed the outer envelope and must pass the local directory check (rule V, V6).
    pub(super) fn open_shared(
        &self,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        message: &[u8],
    ) -> Result<OpenedMessage, SdkError> {
        let header = outer_header(message)?;
        let scope = self.dm_scope(remote.root_commitment())?;
        let runtime = MlsRuntime::open_for(self, &[remote.root_commitment()])?;
        let mls = runtime.mls();
        let state = ConvStore::new(mls.kv()).get(&scope.conversation_id)?.ok_or_else(no_group)?;
        let now = u64::try_from(crate::time::now_unix_timestamp()).unwrap_or(0);
        if !state.readable(&header.group_id, now) {
            return Err(SdkError::Mls {
                code: "not_found",
                detail: "the message is not in this conversation's group".to_owned(),
            });
        }
        let received = mls.receive(message)?.commit_plain().map_err(MlsError::from)?;
        let ReceivedMessage::Application { plaintext, sender_leaf, .. } = received else {
            return Err(invalid("only application messages open on the routed path"));
        };
        let sender = mls.check_leaf_directory(&header.group_id, sender_leaf)?;
        if sender.device_key() != Some((remote.root_commitment(), remote.device_id())) {
            return Err(invalid("the MLS sender differs from the signing device"));
        }
        Ok(OpenedMessage { plaintext, group_id: header.group_id })
    }
}

/// The nested packet that carries the one `PrivateMessage` in the compact crypto box (the sealed
/// bytes ride as the raw ciphertext; every other field is empty).
pub(super) fn packet(
    client: &RamfluxClient,
    message: &[u8],
    collapse_tag: Option<String>,
    report_commitment: Option<String>,
) -> Result<SdkDmEncryptedEnvelope, SdkError> {
    Ok(SdkDmEncryptedEnvelope {
        source_principal_commitment: Some(client.own_account_anchor()?),
        schema: "ramflux.sdk.dm_x3dh_envelope.v2".to_owned(),
        version: 2,
        x3dh: None,
        ciphertext: ramflux_crypto::DmCiphertext {
            session_id: String::new(),
            counter: 0,
            nonce: [0; 12],
            ciphertext: message.to_vec(),
            ratchet_public_key: None,
            previous_chain_length: 0,
            sender_device_id_hash: [0; 32],
            recipient_device_id_hash: [0; 32],
            device_epoch: 0,
            message_event_id: String::new(),
            canonical_header_bytes: Vec::new(),
            header_hash: String::new(),
            key_commitment: String::new(),
            franking_commitment: String::new(),
            commitment: String::new(),
            ciphertext_hash: String::new(),
        },
        collapse_tag,
        report_commitment,
    })
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local reset preparation and sealing; directory, prekey and submit waits belong to the caller.

use super::{
    GatewayDirectMessage, GatewayInboxEntry, GatewaySessionConfig, RamfluxClient, Route,
    SdkDmEncryptedEnvelope, SdkError, SendMaterial, SendMaterialRequest,
};
use crate::client::identity_authority::HeadUse;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::Envelope;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairControlKind {
    Reset,
    Ack,
}
impl PairControlKind {
    pub(super) fn wire(self) -> &'static str {
        match self {
            Self::Reset => "pair.session.reset.v1",
            Self::Ack => "pair.session.reset.ack.v1",
        }
    }
}
impl PairControlDraft {
    pub(crate) fn remote(&self) -> &RootQualifiedDeviceRef {
        &self.remote
    }
    pub(crate) fn kind(&self) -> PairControlKind {
        self.kind
    }
}
pub(crate) struct PairControlDraft {
    pub(super) message: GatewayDirectMessage,
    pub(super) body: Vec<u8>,
    local: RootQualifiedDeviceRef,
    remote: RootQualifiedDeviceRef,
    kind: PairControlKind,
    fingerprint: Option<serde_json::Value>,
}
impl RamfluxClient {
    pub(crate) fn prepare_received_pair_reply(
        &self,
        config: &GatewaySessionConfig,
        opened: &super::Opened,
        body: &[u8],
    ) -> Result<Option<Envelope>, SdkError> {
        if opened.routing.kind != super::Kind::Control
            || !serde_json::from_slice::<serde_json::Value>(body)
                .is_ok_and(|value| value["type"] == "pair.session.reset.v1")
            || !self.pair_recovery_allowed(&opened.local_device, &opened.remote_device)?
        {
            return Ok(None);
        }
        let draft =
            self.prepare_pair_control_draft(config, &opened.remote_device, PairControlKind::Ack)?;
        let request = self.pair_control_material_request(config, &draft)?;
        // The just-committed authenticated receive installed this pair. A changed authority
        // must be redriven by a later reset, never fetched while the writer is applying it.
        if request.root.is_some() || request.prekey.is_some() {
            return Err(SdkError::InboundPending("reset reply pair material changed".into()));
        }
        self.seal_pair_control_prepared(
            config,
            draft,
            SendMaterial { manifest: None, bundle: None },
        )
    }

    pub(crate) fn prepare_pair_recovery_draft(
        &self,
        config: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<PairControlDraft>, SdkError> {
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, entry)?;
        let local = self.local_device_identity(&config.device_id)?;
        let remote = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if !self.pair_recovery_allowed(&local, &remote)?
            || !self.begin_pair_recovery(&local, &remote, super::now_unix_timestamp())?
        {
            return Ok(None);
        }
        self.prepare_pair_control_draft(config, &remote, PairControlKind::Reset).map(Some)
    }
    pub(crate) fn prepare_due_pair_reset(
        &self,
        config: &GatewaySessionConfig,
        at: i64,
    ) -> Result<Option<PairControlDraft>, SdkError> {
        let local = self.local_device_identity(&config.device_id)?;
        for mut item in self
            .legacy_upgrade_reset_work(&local)?
            .into_iter()
            .filter(|work| work.local == local.storage_key())
        {
            let remote = self.device_identity(&item.remote)?;
            if !self.pair_recovery_allowed(&local, &remote)? {
                self.remove_device_pair(&remote, "retry_relationship_ended")?;
                continue;
            }
            if at
                >= self
                    .normalize_reset_work(&mut item)?
                    .saturating_add(super::reset_policy::MAX_RESET_LIFETIME)
            {
                self.mark_pair_manual(&local, &remote, at)?;
                continue;
            }
            if item.next_at <= at {
                return if self.begin_pair_recovery(&local, &remote, at)? {
                    self.prepare_pair_control_draft(config, &remote, PairControlKind::Reset)
                        .map(Some)
                } else {
                    Ok(None)
                };
            }
        }
        Ok(None)
    }
    pub(super) fn prepare_pair_control_draft(
        &self,
        config: &GatewaySessionConfig,
        remote: &RootQualifiedDeviceRef,
        kind: PairControlKind,
    ) -> Result<PairControlDraft, SdkError> {
        let local = self.local_device_identity(&config.device_id)?;
        let id = format!(
            "pair-control-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        );
        let message = GatewayDirectMessage {
            conversation_id: id.clone(),
            message_id: id.clone(),
            envelope_id: id,
            source_principal_id: config.principal_id.clone(),
            sender_id: config.principal_id.clone(),
            recipient_device_id: Some(remote.device_id().to_owned()),
            recipient_principal_commitment: Some(remote.root_commitment().to_owned()),
            target_delivery_id: self.pair_delivery_id(remote)?,
            encrypted_body: Vec::new(),
            created_at: super::now_unix_timestamp(),
            ttl: crate::offline_retention::RESET_TTL_SECS,
        };
        let body = serde_json::to_vec(&serde_json::json!({
            "type":kind.wire(), "rejected_bootstrap_floor": if kind == PairControlKind::Reset {
                self.bootstrap_high_water(&local, remote)?
            } else { 0 },
        }))?;
        let fingerprint = if kind == PairControlKind::Reset {
            self.account_db()?.load_actor_state(&Self::reset_work_key(&local, remote)?)?
        } else {
            None
        };
        Ok(PairControlDraft { message, body, local, remote: remote.clone(), kind, fingerprint })
    }
    pub(crate) fn pair_control_material_request(
        &self,
        config: &GatewaySessionConfig,
        draft: &PairControlDraft,
    ) -> Result<SendMaterialRequest, SdkError> {
        self.routed_send_material_request(config, &draft.message)
    }
    pub(crate) fn seal_pair_control_prepared(
        &self,
        config: &GatewaySessionConfig,
        draft: PairControlDraft,
        material: SendMaterial,
    ) -> Result<Option<Envelope>, SdkError> {
        if !self.pair_control_draft_current(&draft)? {
            return Ok(None);
        }
        let sealed = self.seal_routed_prepared(
            config,
            &draft.message,
            &draft.body,
            Route::control(),
            material,
        )?;
        self.finish_pair_control_draft(config, draft, &sealed).map(Some)
    }
    pub(super) fn pair_control_draft_current(
        &self,
        draft: &PairControlDraft,
    ) -> Result<bool, SdkError> {
        if !self.pair_recovery_allowed(&draft.local, &draft.remote)? {
            return Ok(false);
        }
        Ok(draft.kind != PairControlKind::Reset
            || (draft.fingerprint.is_some()
                && self.account_db()?.load_actor_state::<serde_json::Value>(
                    &Self::reset_work_key(&draft.local, &draft.remote)?,
                )? == draft.fingerprint))
    }
    pub(super) fn finish_pair_control_draft(
        &self,
        config: &GatewaySessionConfig,
        mut draft: PairControlDraft,
        sealed: &SdkDmEncryptedEnvelope,
    ) -> Result<Envelope, SdkError> {
        if draft.kind == PairControlKind::Reset {
            self.account_db()?.persist_actor_state(
                &format!("dm-pair/reset/{}", sealed.ciphertext.session_id),
                &true,
            )?;
        }
        draft.message.encrypted_body = serde_json::to_vec(sealed)?;
        super::gateway_direct_message_envelope(config, &draft.message, None)
    }
}

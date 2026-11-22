// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local reset preparation and sealing; directory, prekey and submit waits belong to the caller.

use super::{
    GatewayDirectMessage, GatewayInboxEntry, GatewaySessionConfig, RamfluxClient, Route, SdkError,
    SendMaterial, SendMaterialRequest,
};
use crate::client::identity_authority::HeadUse;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::Envelope;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairControlKind {
    Reset,
    Ack,
}
impl PairControlKind {}
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
        config: &crate::SealingConfig,
        opened: &super::Opened,
        body: &[u8],
    ) -> Result<Option<Envelope>, SdkError> {
        if opened.routing.kind != super::Kind::Control
            || !Self::decode_generated_inner(body).is_ok_and(|(_, content)| matches!(content.value,
                Some(ramflux_protocol::message::content::Value::Control(control)) if control.operation == 1))
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
    /// True when a new authorization is waiting on the process-local head clock.
    /// Any other authority error still fails the caller.
    fn reset_blocked_on_fresh_head(
        &self,
        local: &RootQualifiedDeviceRef,
        remote: &RootQualifiedDeviceRef,
    ) -> Result<bool, SdkError> {
        if Self::authorization_awaits_head(
            self.require_cached_root_authority(HeadUse::NewAuthorization, remote),
        )? {
            return Ok(true);
        }
        if self.born_v3_account.is_some() {
            return Self::authorization_awaits_head(
                self.require_current_device_authorization(local),
            );
        }
        Ok(false)
    }
    fn authorization_awaits_head(result: Result<(), SdkError>) -> Result<bool, SdkError> {
        match result {
            Ok(()) => Ok(false),
            Err(SdkError::FreshHeadRequired { .. }) => Ok(true),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn prepare_due_pair_reset(
        &self,
        config: &GatewaySessionConfig,
        at: i64,
    ) -> Result<Option<PairControlDraft>, SdkError> {
        let local = self.local_device_identity(&config.device_id)?;
        for item in self
            .retained_reset_work(&local)?
            .into_iter()
            .filter(|work| work.local == local.storage_key())
        {
            let remote = self.device_identity(&item.remote)?;
            if !self.pair_recovery_allowed(&local, &remote)? {
                self.remove_device_pair(&remote, "retry_relationship_ended")?;
                continue;
            }
            if at
                >= Self::reset_first_at(&item)?
                    .saturating_add(super::reset_policy::MAX_RESET_LIFETIME)
            {
                self.mark_pair_manual(&local, &remote, at)?;
                continue;
            }
            if item.next_at <= at {
                // Begin only once the heads can authorize the send. A cold clock
                // must not consume the attempt budget while the directory fetch
                // is still in flight.
                if self.reset_blocked_on_fresh_head(&local, &remote)? {
                    return Ok(None);
                }
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
        use ramflux_protocol::message as g;
        let local = self.local_device_identity(&config.device_id)?;
        let id = pair_control_message_id()?;
        let mut message = GatewayDirectMessage {
            conversation_id: ramflux_protocol::message::dm_scope::derive(
                local.root_commitment(),
                remote.root_commitment(),
            )
            .map_err(|_| super::invalid("reset direct scope invalid"))?,
            message_id: id.clone(),
            envelope_id: id,
            source_principal_id: config.principal_id.clone(),
            sender_id: config.device_id.clone(),
            recipient_device_id: Some(remote.device_id().to_owned()),
            recipient_principal_commitment: Some(remote.root_commitment().to_owned()),
            target_delivery_id: self.pair_delivery_id(remote)?,
            encrypted_body: Vec::new(),
            created_at: super::now_unix_timestamp(),
            ttl: crate::offline_retention::RESET_TTL_SECS,
        };

        let floor = self.bootstrap_high_water(&local, remote)?;
        let payload = match kind {
            PairControlKind::Reset => {
                g::control::Payload::Reset(g::PairReset { rejected_bootstrap_floor: floor })
            }
            PairControlKind::Ack => {
                g::control::Payload::ResetAck(g::PairResetAck { rejected_bootstrap_floor: 0 })
            }
        };
        let control = crate::client::generated_control::control_from_payload(payload)?;
        let prepared = self.prepare_authored_content(
            &mut message,
            None,
            &g::Content { value: Some(g::content::Value::Control(control)) },
        )?;
        let body = prepared.wire.clone();
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
        config: &crate::SealingConfig,
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
        self.finish_pair_control_draft(config, draft, sealed).map(Some)
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
        config: &crate::SealingConfig,
        mut draft: PairControlDraft,
        sealed: super::SealedRouted,
    ) -> Result<Envelope, SdkError> {
        if draft.kind == PairControlKind::Reset {
            self.account_db()?.persist_actor_state(
                &format!("dm-pair/reset/{}", sealed.packet.ciphertext.session_id),
                &true,
            )?;
        }
        crate::dm::gateway_generated_envelope_from_sealed(config, &mut draft.message, sealed)
    }
}

fn pair_control_message_id() -> Result<String, SdkError> {
    #[cfg(test)]
    if let Some(id) = FIXED_PAIR_CONTROL_ID.with(|cell| cell.borrow().clone()) {
        return Ok(id);
    }
    Ok(format!("pair-control-{}", ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)))
}

#[cfg(test)]
thread_local! {
    static FIXED_PAIR_CONTROL_ID: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Pins the pair-control envelope id until the guard drops (byte-equality tests).
#[cfg(test)]
pub(crate) fn with_fixed_pair_control_id<T>(id: &str, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FIXED_PAIR_CONTROL_ID.with(|cell| cell.replace(None));
        }
    }
    FIXED_PAIR_CONTROL_ID.with(|cell| cell.replace(Some(id.to_owned())));
    let _reset = Reset;
    f()
}

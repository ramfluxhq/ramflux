// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable reset retry and encrypted acknowledgement, independent of inbox retry retention.
use super::reset_policy::{MAX_RESET_LIFETIME, ResetWork};
use super::{GatewaySessionAccess, Kind, Opened, PairControlKind, RamfluxClient, Route, SdkError};
use crate::client::identity_authority::HeadUse;
use crate::gateway::session_push::SubmitRefusal;
use crate::time::now_unix_timestamp;
impl RamfluxClient {
    pub(super) async fn send_pair_reset(
        &self,
        engine: &mut impl GatewaySessionAccess,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        self.send_pair_control(engine, remote, PairControlKind::Reset).await
    }
    pub(super) fn pair_delivery_id(
        &self,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<String, SdkError> {
        let record = self.trusted_device(HeadUse::NewAuthorization, remote)?;
        if let Some(target) = record.get("target_delivery_id").and_then(serde_json::Value::as_str) {
            return Ok(target.to_owned());
        }
        Err(super::invalid("verified pair recipient delivery target missing"))
    }

    /// The identity of the reset a submit belongs to: the stored `ResetWork` row (attempt count,
    /// schedule and first attempt) at submit time. A confirmed receive clears it, and a later
    /// reset writes a different one, so a refusal can tell whether it is still current.
    pub(crate) fn pair_reset_fingerprint(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Option<serde_json::Value>, SdkError> {
        let key = Self::reset_work_key(local, remote)?;
        Ok(self.account_db()?.load_actor_state::<serde_json::Value>(&key)?)
    }
    /// The policy for a certain gateway refusal of a pair control submit. A Conflict on a reset
    /// takes the existing lifetime-expiry terminal (manual recovery) and journals the refusal in
    /// the `pair-reset-refused` form; a capacity refusal pushes the next attempt to the gateway's
    /// floor; `RetrySafe` keeps the existing schedule. Acknowledgements have no durable work.
    ///
    /// `submitted` is the reset's fingerprint taken when the submit was prepared. The refusal is
    /// applied only inside a transaction that re-reads the work row and finds the same
    /// fingerprint; a reset confirmed or replaced meanwhile makes the refusal stale, and it is
    /// dropped without any state change.
    pub(crate) fn pair_control_refused(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        kind: PairControlKind,
        refusal: SubmitRefusal,
        submitted: Option<&serde_json::Value>,
    ) -> Result<SdkError, SdkError> {
        let at = now_unix_timestamp();
        if kind == PairControlKind::Reset {
            let db = self.account_db()?;
            match refusal {
                SubmitRefusal::Conflict => {
                    let pair = RamfluxClient::pair_key(local, remote)?;
                    let applied = db.write_transaction(|| -> Result<bool, SdkError> {
                        if self.pair_reset_fingerprint(local, remote)?.as_ref() != submitted {
                            return Ok(false);
                        }
                        db.append_journal(
                            &format!("pair-reset-refused:{pair}:{at}"),
                            "session.reset",
                            &serde_json::json!({"device_id":remote.storage_key(),"state":"refused","reason":"submit_conflict"}),
                            at,
                            None,
                        )?;
                        self.mark_pair_manual(local, remote, at)?;
                        Ok(true)
                    })?;
                    // The outer transaction deferred the retirement checkpoints: run them now.
                    if applied {
                        self.finish_pair_retirement()?;
                    }
                }
                SubmitRefusal::CapacityRetryAfter { retry_after_ms } => {
                    let floor = i64::try_from(retry_after_ms.div_ceil(1000)).unwrap_or(i64::MAX);
                    let key = Self::reset_work_key(local, remote)?;
                    // Fingerprint recheck, row load and update are one transaction: a receive that
                    // confirms the pair meanwhile can neither be undone nor have its cleared
                    // work recreated. An absent row or a different fingerprint changes nothing.
                    db.write_transaction(|| -> Result<(), SdkError> {
                        let Some(row) = db.load_actor_state::<serde_json::Value>(&key)? else {
                            return Ok(());
                        };
                        if Some(&row) != submitted {
                            return Ok(());
                        }
                        let mut work: ResetWork = serde_json::from_value(row)?;
                        work.next_at = work.next_at.max(at.saturating_add(floor));
                        #[cfg(test)]
                        capacity_pause::run();
                        db.persist_actor_state(&key, &work)?;
                        Ok(())
                    })?;
                }
                SubmitRefusal::RetrySafe => {}
            }
        }
        Ok(SdkError::GatewaySessionRejected(refusal.reason().to_owned()))
    }
    async fn send_pair_control(
        &self,
        engine: &mut impl GatewaySessionAccess,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        kind: PairControlKind,
    ) -> Result<(), SdkError> {
        let draft = self.prepare_pair_control_draft(engine.config(), remote, kind)?;
        let local = self.local_device_identity(&engine.config().device_id)?;
        let submitted = self.pair_reset_fingerprint(&local, remote)?;
        let sealed =
            self.seal_routed_as(engine, &draft.message, &draft.body, Route::control()).await?;
        if self.pair_control_draft_current(&draft)? {
            let envelope = self.finish_pair_control_draft(engine.config(), draft, sealed)?;
            if let Err(refusal) = engine.submit_classified(envelope).await? {
                return Err(self.pair_control_refused(
                    &local,
                    remote,
                    kind,
                    refusal,
                    submitted.as_ref(),
                )?);
            }
        }
        // Submission is transport acceptance, not peer confirmation. Work remains durable.
        Ok(())
    }
    pub(super) fn retained_reset_work(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Vec<ResetWork>, SdkError> {
        let db = self.account_db()?;
        let mut retained = Vec::new();
        for key in db.actor_state_keys("dm-pair/reset-work/")? {
            let Some(item) = db.load_actor_state::<ResetWork>(&key)? else { continue };
            let owner = self.device_identity(&item.local)?;
            let remote = self.device_identity(&item.remote)?;
            if item.local != owner.storage_key()
                || item.remote != remote.storage_key()
                || Self::reset_work_key(&owner, &remote)? != key
                || item.first_at.is_none()
            {
                return Err(super::invalid("reset work requires current root-qualified state"));
            }
            if owner == *local {
                retained.push(item);
            }
        }
        Ok(retained)
    }

    pub(crate) async fn retry_pair_resets(
        &self,
        engine: &mut impl GatewaySessionAccess,
        at: i64,
    ) -> Result<(), SdkError> {
        let local = self.local_device_identity(&engine.config().device_id)?;
        let work = self.retained_reset_work(&local)?;
        let mut attempted = false;
        for item in work.into_iter().filter(|work| work.local == local.storage_key()) {
            let remote = self.device_identity(&item.remote)?;
            if !self.pair_recovery_allowed(&local, &remote)? {
                self.remove_device_pair(&remote, "retry_relationship_ended")?;
                continue;
            }
            let first = Self::reset_first_at(&item)?;
            if at >= first.saturating_add(MAX_RESET_LIFETIME) {
                self.mark_pair_manual(&local, &remote, at)?;
                continue;
            }
            if !attempted && item.next_at <= at {
                attempted = true;
                if self.begin_pair_recovery(&local, &remote, at)?
                    && let Err(error) = self.send_pair_reset(engine, &remote).await
                {
                    tracing::debug!(%error,"device pair reset remains pending");
                }
            }
        }
        Ok(())
    }
    pub(super) async fn reply_pair_reset(
        &self,
        engine: &mut impl GatewaySessionAccess,
        opened: &Opened,
        body: &[u8],
    ) {
        if opened.routing.kind == Kind::Control
            && Self::decode_generated_inner(body).is_ok_and(|(_, content)| matches!(content.value,
                Some(ramflux_protocol::message::content::Value::Control(control)) if control.operation == 1))
            && self
                .pair_recovery_allowed(&opened.local_device, &opened.remote_device)
                .is_ok_and(|allowed| allowed)
            && let Err(error) = self
                .send_pair_control(engine, &opened.remote_device, PairControlKind::Ack)
                .await
        {
            tracing::debug!(%error,"encrypted reset acknowledgement will be retried on the next request");
        }
    }
}

/// Test seam: a pause inside the capacity transaction, between the fingerprint recheck and the
/// update, where a competing writer connection can try to interleave.
#[cfg(test)]
pub(super) mod capacity_pause {
    type Hook = Box<dyn FnOnce()>;
    thread_local! {
        static HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
    }
    pub(in crate::client) fn set(hook: Hook) {
        HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
    }
    pub(super) fn run() {
        let hook = HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }
}

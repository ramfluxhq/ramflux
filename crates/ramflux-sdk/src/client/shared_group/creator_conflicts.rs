// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-device fork repair preserves durable removals before replaying pending intent.
use super::{
    GroupStateChange, RamfluxClient, SdkError, VerifiedGroupState, json, now_unix_timestamp,
};
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_crypto::{GroupStateRelation, advance_native_group_state_with_order};
use ramflux_protocol::group_state::GroupStateSnapshot;
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
struct PendingCreatorChange {
    epoch: u64,
    head: String,
    change: GroupStateChange,
    request: Option<ramflux_protocol::group_state::GroupChangeRequest>,
    expires_at: i64,
}
fn key(group: &str) -> String {
    format!("group-state/creator-pending/{}", ramflux_protocol::encode_base64url(group))
}
/// Prefix of the durable markers for creator-fork repairs that still need the account primary.
const REPAIR_PREFIX: &str = "group-state/creator-repair/";
/// A creator fork whose repair could not be signed on the accept path, which holds no vault key.
/// The incoming state is not adopted until the repair is signed natively on a later redrive.
#[derive(Deserialize, Serialize)]
struct PendingCreatorRepair {
    group_id: String,
    target: String,
    incoming: GroupStateSnapshot,
    recorded_at: i64,
    /// Redrives of this marker that failed; the marker stays pending after each one.
    failures: u32,
    /// Display of the last failure (a typed error text, never key material).
    last_error: Option<String>,
}
/// Longest failure text kept on a marker.
const MAX_REPAIR_ERROR_CHARS: usize = 200;
fn fork_marker_key(group: &str) -> String {
    format!("{REPAIR_PREFIX}{}", ramflux_protocol::encode_base64url(group))
}
/// Outcome of reconciling an incoming creator state with the durable local state.
pub(super) enum Reconciled {
    /// Commit this state: either the incoming one or the natively signed repair of it.
    Adopt(Box<VerifiedGroupState>),
    /// The incoming state is superseded or refused; nothing changes.
    Skip,
    /// The repair needs the account primary; a typed marker holds the incoming state.
    Deferred,
}
impl RamfluxClient {
    pub(super) fn can_repair_group_removals(
        &self,
        incoming: &VerifiedGroupState,
    ) -> Result<bool, SdkError> {
        let Some(previous) = self.account_db()?.shared_group_state(&incoming.view().group_id)?
        else {
            return Ok(false);
        };
        Ok(self.owned_device_identity()?.root_commitment()
            == incoming.creator().identity.root_commitment
            && previous.creator().identity.root_commitment
                == incoming.creator().identity.root_commitment
            && matches!(
                incoming.relation_to(&previous)?,
                GroupStateRelation::Extension
                    | GroupStateRelation::IncomingPreferred
                    | GroupStateRelation::RemovalConflict
            ))
    }
    pub(super) fn record_group_write(
        &self,
        state: &VerifiedGroupState,
        change: GroupStateChange,
    ) -> Result<(), SdkError> {
        let now = now_unix_timestamp();
        let mut pending: Vec<PendingCreatorChange> =
            self.account_db()?.load_actor_state(&key(&state.view().group_id))?.unwrap_or_default();
        pending.retain(|item| {
            item.expires_at > now && change_key(&item.change) != change_key(&change)
        });
        pending.push(PendingCreatorChange {
            epoch: state.view().epoch,
            head: state.snapshot().state_hash.clone(),
            change,
            request: None,
            expires_at: now
                .saturating_add(ramflux_protocol::group_state::GROUP_REQUEST_TTL_SECONDS),
        });
        self.account_db()?.persist_actor_state(&key(&state.view().group_id), &pending)?;
        Ok(())
    }
    pub(crate) fn record_group_request_write(
        &self,
        state: &VerifiedGroupState,
        request: &ramflux_protocol::group_state::GroupChangeRequest,
    ) -> Result<(), SdkError> {
        let mut pending: Vec<PendingCreatorChange> =
            self.account_db()?.load_actor_state(&key(&state.view().group_id))?.unwrap_or_default();
        pending.retain(|item| {
            item.expires_at > now_unix_timestamp()
                && change_key(&item.change) != change_key(&request.change)
        });
        pending.push(PendingCreatorChange {
            epoch: state.view().epoch,
            head: state.snapshot().state_hash.clone(),
            change: request.change.clone(),
            request: Some(request.clone()),
            expires_at: request.expires_at,
        });
        self.account_db()?.persist_actor_state(&key(&state.view().group_id), &pending)?;
        Ok(())
    }
    pub(super) fn reconcile_group_state(
        &self,
        incoming: &VerifiedGroupState,
        target: &str,
        primary: Option<&SelfSigningKey>,
    ) -> Result<Reconciled, SdkError> {
        let Some(previous) = self.account_db()?.shared_group_state(&incoming.view().group_id)?
        else {
            return Ok(Reconciled::Adopt(Box::new(incoming.clone())));
        };
        let repairs = self.account_db()?.shared_group_removal_repairs(incoming)?;
        match incoming.relation_to(&previous)? {
            GroupStateRelation::Same => Ok(Reconciled::Adopt(Box::new(incoming.clone()))),
            GroupStateRelation::Extension if repairs.is_empty() => {
                self.account_db()?.remove_actor_state(&key(&incoming.view().group_id))?;
                Ok(Reconciled::Adopt(Box::new(incoming.clone())))
            }
            GroupStateRelation::Ancestor | GroupStateRelation::ExistingPreferred => {
                Ok(Reconciled::Skip)
            }
            GroupStateRelation::Unrelated => {
                self.group_conflict_event(incoming, "creator_authority_mismatch")?;
                Ok(Reconciled::Skip)
            }
            GroupStateRelation::Extension
            | GroupStateRelation::IncomingPreferred
            | GroupStateRelation::RemovalConflict => {
                let local = self.owned_device_identity()?;
                if incoming.creator().identity.root_commitment != local.root_commitment()
                    || previous.creator().identity.root_commitment != local.root_commitment()
                {
                    if incoming.relation_to(&previous)? == GroupStateRelation::RemovalConflict {
                        self.group_conflict_event(incoming, "removal_requires_repair")?;
                        return Ok(Reconciled::Skip);
                    }
                    return Ok(Reconciled::Adopt(Box::new(incoming.clone())));
                }
                let pending: Vec<PendingCreatorChange> = self
                    .account_db()?
                    .load_actor_state(&key(&incoming.view().group_id))?
                    .unwrap_or_default();
                let replay: Vec<PendingCreatorChange> = pending
                    .into_iter()
                    .filter(|item| {
                        item.epoch <= previous.view().epoch
                            && item.expires_at > now_unix_timestamp()
                    })
                    .collect();
                // Signing is needed only if some repair or replay is not already in the incoming
                // state; the first such step is enough, as later steps only extend it.
                let needs_signing = repairs.iter().any(|removal| {
                    !ramflux_crypto::change_already_applied(incoming.view(), removal)
                }) || replay.iter().any(|item| {
                    item.request.is_some()
                        || !ramflux_crypto::change_already_applied(incoming.view(), &item.change)
                });
                if needs_signing && primary.is_none() {
                    self.record_creator_repair(incoming, target)?;
                    return Ok(Reconciled::Deferred);
                }
                let actor = self.owned_group_actor(target)?;
                let state =
                    self.sign_creator_repairs(incoming, &actor, repairs, replay, primary)?;
                Ok(Reconciled::Adopt(Box::new(state)))
            }
        }
    }
    /// Sign the durable removal repairs, then replay the creator's pending intent on top.
    fn sign_creator_repairs(
        &self,
        incoming: &VerifiedGroupState,
        actor: &ramflux_protocol::GroupStateActor,
        repairs: Vec<GroupStateChange>,
        replay: Vec<PendingCreatorChange>,
        primary: Option<&SelfSigningKey>,
    ) -> Result<VerifiedGroupState, SdkError> {
        let mut state = incoming.clone();
        for removal in repairs {
            if ramflux_crypto::change_already_applied(state.view(), &removal) {
                continue;
            }
            state = self.sign_creator_change(primary, actor, &state, removal.clone())?;
            self.record_group_write(&state, removal)?;
        }
        for change in replay {
            if change.request.is_none()
                && ramflux_crypto::change_already_applied(state.view(), &change.change)
            {
                continue;
            }
            let next = if let Some(request) = &change.request {
                self.apply_authorized_group_request_with_primary(
                    &state,
                    request,
                    actor,
                    now_unix_timestamp(),
                    primary,
                )
            } else {
                self.sign_creator_change(primary, actor, &state, change.change.clone())
            };
            match next {
                Ok(next) => {
                    if let Some(request) = &change.request {
                        self.record_group_request_write(&next, request)?;
                    } else {
                        self.record_group_write(&next, change.change)?;
                    }
                    state = next;
                }
                Err(error) => {
                    self.group_conflict_event(incoming, "creator_pending_change_refused")?;
                    if let Some(request) = change.request {
                        let status = if matches!(
                            error,
                            SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(_))
                                | SdkError::Crypto(ramflux_crypto::CryptoError::Protocol(
                                    ramflux_protocol::ProtocolError::GroupStateLimit(_)
                                ))
                        ) {
                            ramflux_protocol::GroupChangeStatus::Capacity
                        } else {
                            ramflux_protocol::GroupChangeStatus::PermissionDenied
                        };
                        self.reject_reconciled_group_request(
                            &request, &state, actor, status, primary,
                        )?;
                    }
                }
            }
        }
        Ok(state)
    }
    /// Natively sign one creator change; a missing primary is a typed error and never a fallback.
    fn sign_creator_change(
        &self,
        primary: Option<&SelfSigningKey>,
        actor: &ramflux_protocol::GroupStateActor,
        state: &VerifiedGroupState,
        change: GroupStateChange,
    ) -> Result<VerifiedGroupState, SdkError> {
        let primary = primary.ok_or(SdkError::CustodyVaultUnavailable)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let order = self.service_order_for_change(state, &change, actor)?;
        Ok(advance_native_group_state_with_order(primary, branch, actor, state, change, order)?)
    }
    /// Hold an incoming creator fork whose repair has to be signed once the primary is available.
    fn record_creator_repair(
        &self,
        incoming: &VerifiedGroupState,
        target: &str,
    ) -> Result<(), SdkError> {
        let group = incoming.view().group_id.clone();
        let marker_key = fork_marker_key(&group);
        if let Some(held) =
            self.account_db()?.load_actor_state::<PendingCreatorRepair>(&marker_key)?
        {
            let held = ramflux_crypto::verify_group_state_snapshot(held.incoming)?;
            if matches!(
                incoming.relation_to(&held)?,
                GroupStateRelation::Same
                    | GroupStateRelation::Ancestor
                    | GroupStateRelation::ExistingPreferred
            ) {
                return Ok(());
            }
        }
        self.account_db()?.persist_actor_state(
            &marker_key,
            &PendingCreatorRepair {
                group_id: group,
                target: target.to_owned(),
                incoming: incoming.snapshot().clone(),
                recorded_at: now_unix_timestamp(),
                failures: 0,
                last_error: None,
            },
        )?;
        Ok(())
    }
    pub(crate) fn has_pending_creator_repairs(&self) -> Result<bool, SdkError> {
        Ok(!self.account_db()?.list_actor_states::<PendingCreatorRepair>(REPAIR_PREFIX)?.is_empty())
    }
    /// Sign and commit every held creator repair. Run it where the account primary is available,
    /// such as the group courier after unlock. Without a primary the markers stay pending and the
    /// result is `CustodyVaultUnavailable`. Returns how many groups were repaired and committed.
    pub(crate) fn redrive_creator_repairs(
        &self,
        primary: Option<&SelfSigningKey>,
    ) -> Result<usize, SdkError> {
        let markers: Vec<PendingCreatorRepair> =
            self.account_db()?.list_actor_states(REPAIR_PREFIX)?;
        if markers.is_empty() {
            return Ok(0);
        }
        if primary.is_none() {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut repaired = 0;
        for held in markers {
            // One marker that cannot be repaired never blocks the other groups.
            let outcome = self.account_db()?.write_transaction(|| -> Result<bool, SdkError> {
                // Re-read inside the writer: a repair that landed meanwhile has cleared the marker.
                let marker_key = fork_marker_key(&held.group_id);
                let Some(current) =
                    self.account_db()?.load_actor_state::<PendingCreatorRepair>(&marker_key)?
                else {
                    return Ok(false);
                };
                let incoming = ramflux_crypto::verify_group_state_snapshot(current.incoming)?;
                let previous = self.account_db()?.shared_group_state(&current.group_id)?;
                let actor = self.owned_group_actor(&current.target)?;
                let committed =
                    match self.reconcile_group_state(&incoming, &current.target, primary)? {
                        Reconciled::Adopt(state) => self.commit_reconciled_group_state(
                            &state,
                            &incoming,
                            previous.as_ref(),
                            &actor,
                        )?,
                        Reconciled::Skip | Reconciled::Deferred => false,
                    };
                self.account_db()?.remove_actor_state(&marker_key)?;
                Ok(committed)
            });
            match outcome {
                Ok(committed) => repaired += usize::from(committed),
                Err(error) => self.record_repair_failure(&held.group_id, &error)?,
            }
        }
        Ok(repaired)
    }
    /// Keep the marker pending, remember why the last redrive failed and warn without secrets.
    fn record_repair_failure(&self, group: &str, error: &SdkError) -> Result<(), SdkError> {
        let reason: String = error.to_string().chars().take(MAX_REPAIR_ERROR_CHARS).collect();
        let marker_key = fork_marker_key(group);
        let failures = self.account_db()?.write_transaction(|| -> Result<u32, SdkError> {
            let Some(mut marker) =
                self.account_db()?.load_actor_state::<PendingCreatorRepair>(&marker_key)?
            else {
                return Ok(0);
            };
            marker.failures = marker.failures.saturating_add(1);
            marker.last_error = Some(reason.clone());
            self.account_db()?.persist_actor_state(&marker_key, &marker)?;
            Ok(marker.failures)
        })?;
        tracing::warn!(failures, error = %reason, "creator repair redrive failed; marker stays pending");
        Ok(())
    }
    fn group_conflict_event(
        &self,
        state: &VerifiedGroupState,
        reason: &str,
    ) -> Result<(), SdkError> {
        let group = &state.view().group_id;
        let key =
            format!("group-state/conflict-rate/{}", ramflux_protocol::encode_base64url(group));
        let now = now_unix_timestamp();
        let previous: Option<i64> = self.account_db()?.load_actor_state(&key)?;
        if previous.is_some_and(|at| now.saturating_sub(at) < 300) {
            return Ok(());
        }
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.account_db()?.append_group_journal(
                &format!("group-conflict/{}/{now}", ramflux_protocol::encode_base64url(group)),
                "group.state.conflict",
                &json!({"group_id":group,"epoch":state.view().epoch,"reason":reason}),
                now,
                &key,
            )?;
            self.account_db()?.persist_actor_state(&key, &now)?;
            Ok(())
        })
    }
}

fn change_key(change: &GroupStateChange) -> String {
    match change {
        GroupStateChange::Add { member, .. } => {
            format!("device/{}/{}", member.root_commitment, member.device_id)
        }
        GroupStateChange::Remove { root_commitment, device_id }
        | GroupStateChange::SetRole { root_commitment, device_id, .. } => {
            format!("device/{root_commitment}/{device_id}")
        }
        GroupStateChange::SetName { .. } => "name".into(),
        GroupStateChange::TransferOwnership { .. } => "creator".into(),
    }
}

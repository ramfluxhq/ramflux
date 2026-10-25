// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Only same-epoch creator-device conflicts replay this device's pending change.
use super::{
    GroupStateChange, RamfluxClient, SdkError, VerifiedGroupState, advance_group_state, json,
    now_unix_timestamp,
};
use ramflux_crypto::GroupStateRelation;
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
impl RamfluxClient {
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
    ) -> Result<Option<VerifiedGroupState>, SdkError> {
        let Some(previous) = self.account_db()?.shared_group_state(&incoming.view().group_id)?
        else {
            return Ok(Some(incoming.clone()));
        };
        match incoming.relation_to(&previous)? {
            GroupStateRelation::Same => Ok(Some(incoming.clone())),
            GroupStateRelation::Extension => {
                self.account_db()?.remove_actor_state(&key(&incoming.view().group_id))?;
                Ok(Some(incoming.clone()))
            }
            GroupStateRelation::Ancestor | GroupStateRelation::ExistingPreferred => Ok(None),
            GroupStateRelation::Unrelated => {
                self.group_conflict_event(incoming, "creator_authority_mismatch")?;
                Ok(None)
            }
            GroupStateRelation::IncomingPreferred => {
                let local = self.owned_device_identity()?;
                if incoming.creator().identity.root_commitment != local.root_commitment()
                    || previous.creator().identity.root_commitment != local.root_commitment()
                {
                    return Ok(Some(incoming.clone()));
                }
                let pending: Vec<PendingCreatorChange> = self
                    .account_db()?
                    .load_actor_state(&key(&incoming.view().group_id))?
                    .unwrap_or_default();
                let actor = self.owned_group_actor(target)?;
                let mut state = incoming.clone();
                for change in pending.into_iter().filter(|item| {
                    item.epoch <= previous.view().epoch && item.expires_at > now_unix_timestamp()
                }) {
                    if change.request.is_none()
                        && ramflux_crypto::change_already_applied(state.view(), &change.change)
                    {
                        continue;
                    }
                    let next = if let Some(request) = &change.request {
                        self.apply_authorized_group_request(
                            &state,
                            request,
                            &actor,
                            now_unix_timestamp(),
                        )
                    } else {
                        advance_group_state(
                            self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                            &actor,
                            &state,
                            change.change.clone(),
                        )
                        .map_err(SdkError::from)
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
                                    SdkError::Protocol(
                                        ramflux_protocol::ProtocolError::GroupStateLimit(_)
                                    ) | SdkError::Crypto(ramflux_crypto::CryptoError::Protocol(
                                        ramflux_protocol::ProtocolError::GroupStateLimit(_)
                                    ))
                                ) {
                                    ramflux_protocol::GroupChangeStatus::Capacity
                                } else {
                                    ramflux_protocol::GroupChangeStatus::PermissionDenied
                                };
                                self.reject_reconciled_group_request(
                                    &request, &state, &actor, status,
                                )?;
                            }
                        }
                    }
                }
                Ok(Some(state))
            }
        }
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

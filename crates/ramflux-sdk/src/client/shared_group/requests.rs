// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable, expiring group change intent and creator-authenticated terminal results.
use crate::prelude::*;
use ramflux_protocol::group_state::{
    GROUP_REQUEST_TTL_SECONDS, GroupChangeRequest, GroupChangeResult, GroupChangeStatus,
    GroupStateChange, MAX_GROUP_PENDING_REQUESTS, MAX_GROUP_REQUESTS_PER_ROOT,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct RequestRecord {
    pub request: GroupChangeRequest,
    pub incoming: bool,
    pub result: Option<GroupChangeResult>,
    pub local_status: String,
    pub expires_at: i64,
    pub next_at: i64,
    pub delivered: BTreeSet<String>,
    #[serde(default)]
    pub federation: Option<LocalBusFederationRoute>,
}
pub(crate) const REQUEST_PREFIX: &str = "group-change/request/";
pub(crate) fn request_key(
    request: &GroupChangeRequest,
    incoming: bool,
) -> Result<String, SdkError> {
    Ok(format!(
        "{REQUEST_PREFIX}{}",
        ramflux_protocol::hash_base64url(
            "ramflux.group.change.record.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                incoming,
                &request.group_id,
                &request.actor.identity.root_commitment,
                &request.request_id
            ))?
        )
    ))
}
fn capacity() -> SdkError {
    SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
        ramflux_protocol::GroupStateLimit::Requests,
    ))
}
impl RamfluxClient {
    pub(crate) fn group_change_records(&self) -> Result<Vec<RequestRecord>, SdkError> {
        Ok(self.account_db()?.list_actor_states(REQUEST_PREFIX)?)
    }
    pub(crate) fn group_change_record(
        &self,
        request: &GroupChangeRequest,
        incoming: bool,
    ) -> Result<Option<RequestRecord>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&request_key(request, incoming)?)?)
    }
    pub(crate) fn persist_group_request(&self, record: &RequestRecord) -> Result<(), SdkError> {
        self.account_db()?
            .persist_actor_state(&request_key(&record.request, record.incoming)?, record)?;
        Ok(())
    }
    pub(crate) fn stage_group_change_request(
        &self,
        group: &str,
        target: &str,
        change: GroupStateChange,
        supplied_id: Option<&str>,
    ) -> Result<GroupChangeRequest, SdkError> {
        let state = self
            .account_db()?
            .shared_group_state(group)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let actor = self.owned_group_actor(target)?;
        if let Some(id) = supplied_id
            && let Some(previous) = self.group_change_records()?.into_iter().find(|row| {
                !row.incoming
                    && row.request.group_id == group
                    && row.request.request_id == id
                    && row.request.actor.identity.root_commitment == actor.identity.root_commitment
            })
        {
            if previous.request.change != change
                || previous.request.actor.identity.device_id != actor.identity.device_id
            {
                return Err(SdkError::LocalBus(
                    "group request id reused for another intent".into(),
                ));
            }
            return Ok(previous.request);
        }
        let now = now_unix_timestamp();
        let id = supplied_id.map_or_else(crate::new_surface_message_id, |id| Ok(id.to_owned()))?;
        let request = ramflux_crypto::sign_group_change_request(
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &actor,
            &state,
            ramflux_crypto::GroupChangeRequestInput { request_id: id, change, now },
        )?;
        self.insert_group_request(&request, false)?;
        Ok(request)
    }
    pub(crate) fn insert_group_request(
        &self,
        request: &GroupChangeRequest,
        incoming: bool,
    ) -> Result<(), SdkError> {
        ramflux_crypto::verify_group_change_request(request, now_unix_timestamp())?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            let state = self
                .account_db()?
                .shared_group_state(&request.group_id)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            self.admit_group_request(&state, request, incoming)?;
            if let Some(previous) = self.group_change_record(request, incoming)? {
                if previous.request != *request {
                    return Err(SdkError::InboundRejected(
                        "group request id reused with different signed intent".into(),
                    ));
                }
                return Ok(());
            }
            let now = now_unix_timestamp();
            self.account_db()?.retain_expiring_actor_states(REQUEST_PREFIX, now, 4096)?;
            let rows = self.prune_group_request_partitions(self.group_change_records()?)?;
            if rows.len() >= 4096 {
                return Err(capacity());
            }
            // Partition retained results as well as pending work. A group can
            // occupy at most 256 of the 4096 account rows; a source root at most
            // 64 in that group. A full retained pool never adds another row;
            // a full pending queue may still return a bounded signed result.
            let group_rows: Vec<_> =
                rows.iter().filter(|row| row.request.group_id == request.group_id).collect();
            if group_rows.len() >= 256
                || group_rows
                    .iter()
                    .filter(|row| {
                        row.request.actor.identity.root_commitment
                            == request.actor.identity.root_commitment
                    })
                    .count()
                    >= 64
            {
                return Err(capacity());
            }
            let pending: Vec<_> = group_rows
                .iter()
                .filter(|row| {
                    row.incoming == incoming
                        && row.result.is_none()
                        && row.request.expires_at > now
                        && row.local_status == "waiting_for_owner"
                })
                .collect();
            let full = pending.len() >= MAX_GROUP_PENDING_REQUESTS
                || pending
                    .iter()
                    .filter(|row| {
                        row.request.actor.identity.root_commitment
                            == request.actor.identity.root_commitment
                    })
                    .count()
                    >= MAX_GROUP_REQUESTS_PER_ROOT;
            if full && !incoming {
                return Err(capacity());
            }
            let result =
                if full { Some(self.group_capacity_result(request, &state, now)?) } else { None };
            self.persist_group_request(&RequestRecord {
                request: request.clone(),
                incoming,
                result,
                local_status: if full { "result_ready" } else { "waiting_for_owner" }.into(),
                expires_at: request.expires_at.saturating_add(86400),
                next_at: now,
                delivered: BTreeSet::new(),
                federation: None,
            })
        })
    }
    fn admit_group_request(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        request: &GroupChangeRequest,
        incoming: bool,
    ) -> Result<(), SdkError> {
        if state
            .view()
            .effective_role(
                &request.actor.identity.root_commitment,
                &request.actor.identity.device_id,
            )
            .is_none()
            || (incoming
                && self.owned_device_identity()?.root_commitment()
                    != state.creator().identity.root_commitment)
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        Ok(())
    }
    fn group_capacity_result(
        &self,
        request: &GroupChangeRequest,
        state: &ramflux_crypto::VerifiedGroupState,
        now: i64,
    ) -> Result<GroupChangeResult, SdkError> {
        let actor = self.owned_group_actor(&self.shared_group_local_target(&request.group_id)?)?;
        Ok(ramflux_crypto::sign_group_change_result(
            self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &actor,
            request,
            state,
            GroupChangeStatus::Capacity,
            now,
        )?)
    }
    fn prune_group_request_partitions(
        &self,
        mut rows: Vec<RequestRecord>,
    ) -> Result<Vec<RequestRecord>, SdkError> {
        // Repair pre-upgrade stores too: an old outsider flood must not keep
        // the account blocked until all of its former retention periods expire.
        rows.sort_by_key(|row| {
            (row.local_status != "waiting_for_owner", std::cmp::Reverse(row.request.issued_at))
        });
        let mut states = BTreeMap::new();
        let mut groups = BTreeMap::new();
        let mut roots = BTreeMap::new();
        let mut kept = Vec::new();
        for row in rows {
            let group = &row.request.group_id;
            if !states.contains_key(group) {
                states.insert(group.clone(), self.account_db()?.shared_group_state(group)?);
            }
            let actor = &row.request.actor.identity;
            let authorized = !row.incoming
                // Previously admitted pending intent must receive its typed
                // result even if the requester was removed in the meantime.
                || (row.result.is_none() && row.local_status == "waiting_for_owner")
                || states.get(group).and_then(Option::as_ref).is_some_and(|state| {
                    state.view().effective_role(&actor.root_commitment, &actor.device_id).is_some()
                });
            let group_count = groups.entry(group.clone()).or_insert(0);
            let root_count =
                roots.entry((group.clone(), actor.root_commitment.clone())).or_insert(0);
            if !authorized || *group_count >= 256 || *root_count >= 64 {
                self.account_db()?.remove_actor_state(&request_key(&row.request, row.incoming)?)?;
            } else {
                *group_count += 1;
                *root_count += 1;
                kept.push(row);
            }
        }
        Ok(kept)
    }
    pub(crate) fn process_group_request(
        &self,
        request: &GroupChangeRequest,
        target: &str,
    ) -> Result<GroupChangeResult, SdkError> {
        self.check_group_transfer_lease(&request.group_id, None)?;
        self.account_db()?.write_transaction(|| -> Result<GroupChangeResult, SdkError> {
            let mut record = self
                .group_change_record(request, true)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            if let Some(result) = record.result {
                return Ok(result);
            }
            let now = now_unix_timestamp();
            let previous = self
                .account_db()?
                .shared_group_state(&request.group_id)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            let actor = self.owned_group_actor(target)?;
            if actor.identity.root_commitment != previous.creator().identity.root_commitment {
                return Err(StorageError::GroupPermissionDenied.into());
            }
            let next = self.apply_authorized_group_request(&previous, request, &actor, now);
            let (state, status) = match next {
                Ok(state) => {
                    let changed = state.snapshot().state_hash != previous.snapshot().state_hash;
                    if changed {
                        self.account_db()?.commit_shared_group_state(&state, &actor)?;
                        if let (GroupStateChange::Add { member, .. }, Some(federation)) =
                            (&request.change, &record.federation)
                        {
                            self.persist_shared_group_federation_route(
                                &request.group_id,
                                &member.root_commitment,
                                federation,
                            )?;
                        }
                        self.record_group_request_write(&state, request)?;
                        crate::bus::enqueue_shared_group(self, &state, Some(&previous))?;
                    }
                    (
                        state,
                        if changed {
                            GroupChangeStatus::Applied
                        } else {
                            GroupChangeStatus::AlreadyApplied
                        },
                    )
                }
                Err(
                    SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(_))
                    | SdkError::Crypto(CryptoError::Protocol(
                        ramflux_protocol::ProtocolError::GroupStateLimit(_),
                    )),
                ) => (previous, GroupChangeStatus::Capacity),
                Err(_) => (previous, GroupChangeStatus::PermissionDenied),
            };
            let result = ramflux_crypto::sign_group_change_result(
                self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                &actor,
                request,
                &state,
                status,
                now,
            )?;
            record.local_status = "result_ready".into();
            record.result = Some(result.clone());
            record.delivered.clear();
            record.next_at = now;
            self.persist_group_request(&record)?;
            Ok(result)
        })
    }
    pub(super) fn apply_authorized_group_request(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        request: &GroupChangeRequest,
        actor: &ramflux_protocol::GroupStateActor,
        now: i64,
    ) -> Result<ramflux_crypto::VerifiedGroupState, SdkError> {
        self.validate_group_requester(state, request)?;
        Ok(ramflux_crypto::apply_group_change_request(
            self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            actor,
            state,
            request,
            now,
        )?)
    }
    pub(super) fn validate_group_requester(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        request: &GroupChangeRequest,
    ) -> Result<(), SdkError> {
        let identity = self.device_identity_for_root(
            &request.actor.identity.root_commitment,
            &request.actor.identity.device_id,
        )?;
        self.require_cached_root_authority(&identity)?;
        if state.view().effective_role(identity.root_commitment(), identity.device_id()).is_none() {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        self.ensure_shared_group_device(state, &identity)?;
        let trusted = self.trusted_device(&identity)?;
        if trusted["principal_id"] != request.actor.identity.principal_id
            || trusted["signing_public_key"] != request.actor.identity.signing_public_key
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        Ok(())
    }
    pub(super) fn reject_reconciled_group_request(
        &self,
        request: &GroupChangeRequest,
        state: &ramflux_crypto::VerifiedGroupState,
        actor: &ramflux_protocol::GroupStateActor,
        status: GroupChangeStatus,
    ) -> Result<(), SdkError> {
        let Some(mut record) = self.group_change_record(request, true)? else {
            return Ok(());
        };
        record.result = Some(ramflux_crypto::sign_group_change_result(
            self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            actor,
            request,
            state,
            status,
            now_unix_timestamp(),
        )?);
        record.local_status = "result_ready".into();
        record.delivered.clear();
        record.next_at = now_unix_timestamp();
        self.persist_group_request(&record)
    }
    pub(crate) fn apply_group_request_result(
        &self,
        result: &GroupChangeResult,
    ) -> Result<(), SdkError> {
        let source = self.owned_device_identity()?;
        if result.requester.root_commitment != source.root_commitment()
            || result.requester.device_id != source.device_id()
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        let records = self.group_change_records()?;
        let mut record = records
            .into_iter()
            .find(|row| {
                !row.incoming
                    && row.request.request_id == result.request_id
                    && row.request.group_id == result.group_id
                    && row.request.actor.identity.root_commitment == source.root_commitment()
            })
            .ok_or(StorageError::GroupPermissionDenied)?;
        let state = self
            .account_db()?
            .shared_group_state(&result.group_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        ramflux_crypto::verify_group_change_result(
            result,
            &record.request,
            &state,
            now_unix_timestamp(),
        )?;
        if record.result.as_ref().is_some_and(|old| old.epoch > result.epoch) {
            return Ok(());
        }
        record.result = Some(result.clone());
        record.local_status = match result.status {
            GroupChangeStatus::Applied => "applied",
            GroupChangeStatus::AlreadyApplied => "already_applied",
            GroupChangeStatus::PermissionDenied => "permission_denied",
            GroupChangeStatus::Capacity => "capacity",
            GroupChangeStatus::Expired => "expired",
            GroupChangeStatus::Invalid => "invalid",
        }
        .into();
        self.persist_group_request(&record)
    }
    pub(crate) fn group_change_statuses(
        &self,
        group: Option<&str>,
    ) -> Result<serde_json::Value, SdkError> {
        let now = now_unix_timestamp();
        let mut rows = Vec::new();
        for mut record in self
            .group_change_records()?
            .into_iter()
            .filter(|row| !row.incoming && group.is_none_or(|group| group == row.request.group_id))
        {
            if record.request.expires_at <= now && record.result.is_none() {
                record.local_status = "expired".into();
                self.persist_group_request(&record)?;
            }
            rows.push(serde_json::json!({"group_id":record.request.group_id,"request_id":record.request.request_id,"status":record.local_status,"waiting_for_owner":record.result.is_none() && record.request.expires_at>now,"result":record.result,"expires_at":record.request.expires_at}));
        }
        Ok(serde_json::json!({"requests":rows,"request_ttl_seconds":GROUP_REQUEST_TTL_SECONDS}))
    }
}

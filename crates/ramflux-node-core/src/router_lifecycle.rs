// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    AccountLifecycleRecord, AccountLifecycleState, DEFAULT_DELETE_TIMELOCK_SECONDS,
    FederatedLifecycleTombstoneRequest, FederatedLifecycleTombstoneResponse,
    IdentityLifecycleTombstone, LifecycleCancelRequest, LifecycleEventRequest,
    LifecycleFinalizeRequest, LifecycleResponse, NodeCoreError, RouterCore,
    identity_deletion_proof, lifecycle_tombstone_hash, verify_lifecycle_tombstone,
    verify_recovery_quorum_proof,
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl RouterCore {
    /// # Errors
    /// Returns an error when the lifecycle transition is invalid.
    pub fn mvp7_apply_lifecycle_event(
        &self,
        request: &LifecycleEventRequest,
    ) -> Result<LifecycleResponse, NodeCoreError> {
        let record = match request.event_type.as_str() {
            "identity.deactivated" => AccountLifecycleRecord {
                principal_id: request.principal_id.clone(),
                state: AccountLifecycleState::Deactivated,
                lifecycle_epoch: request.lifecycle_epoch,
                causal_event_id: request.event_id.clone(),
                updated_at: request.now,
                timelock_until: None,
                tombstone_hash: Some(self.store_lifecycle_tombstone(request)?),
                deletion_proof: None,
            },
            "identity.reactivated" => {
                if let (Some(quorum), Some(proof)) =
                    (&request.recovery_quorum, &request.recovery_quorum_proof)
                {
                    if proof.context.principal_id != request.principal_id
                        || proof.context.event_type != request.event_type
                        || proof.context.lifecycle_epoch != request.lifecycle_epoch
                    {
                        return Err(NodeCoreError::Unauthorized(
                            "recovery quorum context does not match lifecycle event".to_owned(),
                        ));
                    }
                    verify_recovery_quorum_proof(quorum, proof, request.now)?;
                } else if request.recovery_quorum.is_some()
                    || request.recovery_quorum_proof.is_some()
                {
                    return Err(NodeCoreError::Unauthorized(
                        "recovery quorum config and proof must be provided together".to_owned(),
                    ));
                }
                AccountLifecycleRecord {
                    principal_id: request.principal_id.clone(),
                    state: AccountLifecycleState::Active,
                    lifecycle_epoch: request.lifecycle_epoch,
                    causal_event_id: request.event_id.clone(),
                    updated_at: request.now,
                    timelock_until: None,
                    tombstone_hash: None,
                    deletion_proof: None,
                }
            }
            "identity.deleted" => {
                let timelock_seconds =
                    request.timelock_seconds.unwrap_or(DEFAULT_DELETE_TIMELOCK_SECONDS);
                AccountLifecycleRecord {
                    principal_id: request.principal_id.clone(),
                    state: AccountLifecycleState::DeletePending,
                    lifecycle_epoch: request.lifecycle_epoch,
                    causal_event_id: request.event_id.clone(),
                    updated_at: request.now,
                    timelock_until: Some(request.now.saturating_add(timelock_seconds)),
                    tombstone_hash: Some(self.store_lifecycle_tombstone(request)?),
                    deletion_proof: None,
                }
            }
            _ => {
                return Err(NodeCoreError::ItestHttp(format!(
                    "unsupported lifecycle event: {}",
                    request.event_type
                )));
            }
        };
        crate::lock_unpoisoned(&self.control)
            .lifecycle_by_principal
            .insert(request.principal_id.clone(), record.clone());
        let metadata_present = self.mvp7_metadata_summary(&request.principal_id).metadata_present;
        let tombstone = record
            .tombstone_hash
            .as_deref()
            .and_then(|hash| self.lifecycle_tombstone_by_hash(hash));
        Ok(LifecycleResponse { record, metadata_present, deleted_metadata_count: 0, tombstone })
    }

    /// # Errors
    /// Returns an error when there is no pending delete for the principal.
    pub fn mvp7_cancel_delete(
        &self,
        request: &LifecycleCancelRequest,
    ) -> Result<LifecycleResponse, NodeCoreError> {
        let existing = crate::lock_unpoisoned(&self.control)
            .lifecycle_by_principal
            .get(&request.principal_id)
            .cloned()
            .ok_or_else(|| {
                NodeCoreError::ItestHttp(format!("missing lifecycle: {}", request.principal_id))
            })?;
        if existing.state != AccountLifecycleState::DeletePending {
            return Err(NodeCoreError::ItestHttp(format!(
                "delete is not pending: {}",
                request.principal_id
            )));
        }
        let record = AccountLifecycleRecord {
            principal_id: request.principal_id.clone(),
            state: AccountLifecycleState::Active,
            lifecycle_epoch: existing.lifecycle_epoch.saturating_add(1),
            causal_event_id: format!("{}_cancel_delete", existing.causal_event_id),
            updated_at: request.now,
            timelock_until: None,
            tombstone_hash: None,
            deletion_proof: None,
        };
        crate::lock_unpoisoned(&self.control)
            .lifecycle_by_principal
            .insert(request.principal_id.clone(), record.clone());
        let metadata_present = self.mvp7_metadata_summary(&request.principal_id).metadata_present;
        Ok(LifecycleResponse {
            record,
            metadata_present,
            deleted_metadata_count: 0,
            tombstone: None,
        })
    }

    /// # Errors
    /// Returns an error when the delete timelock has not expired.
    pub fn mvp7_finalize_delete(
        &self,
        request: &LifecycleFinalizeRequest,
    ) -> Result<LifecycleResponse, NodeCoreError> {
        let existing = crate::lock_unpoisoned(&self.control)
            .lifecycle_by_principal
            .get(&request.principal_id)
            .cloned()
            .ok_or_else(|| {
                NodeCoreError::ItestHttp(format!("missing lifecycle: {}", request.principal_id))
            })?;
        if existing.state != AccountLifecycleState::DeletePending {
            return Err(NodeCoreError::ItestHttp(format!(
                "delete is not pending: {}",
                request.principal_id
            )));
        }
        if let Some(timelock_until) = existing.timelock_until
            && request.now < timelock_until
        {
            return Err(NodeCoreError::ItestHttp(format!(
                "delete timelock has not expired: {}",
                request.principal_id
            )));
        }
        let tombstone_hash = existing.tombstone_hash.clone().ok_or_else(|| {
            NodeCoreError::ItestHttp("missing lifecycle tombstone hash".to_owned())
        })?;
        let (target_delivery_id, mut deleted_metadata_count) = {
            let mut control = crate::lock_unpoisoned(&self.control);
            let target_delivery_id = control
                .mvp1_identities
                .target_delivery_id_for_principal(&request.principal_id)
                .map(ToOwned::to_owned);
            let deleted_metadata_count = u64::try_from(
                control.mvp1_identities.remove_principal_metadata(&request.principal_id),
            )
            .unwrap_or(u64::MAX);
            (target_delivery_id, deleted_metadata_count)
        };
        if let Some(target_delivery_id) = &target_delivery_id {
            let mut shard = self.target_shard(target_delivery_id);
            deleted_metadata_count = deleted_metadata_count
                .saturating_add(u64::from(shard.registry.remove_target(target_delivery_id)));
            deleted_metadata_count = deleted_metadata_count.saturating_add(
                u64::try_from(shard.inbox.remove_target(target_delivery_id)).unwrap_or(u64::MAX),
            );
            shard.deleted_delivery_targets.insert(target_delivery_id.clone());
            drop(shard);
            self.remove_target_index(target_delivery_id);
        }
        let proof = identity_deletion_proof(
            &request.principal_id,
            &tombstone_hash,
            request.now,
            deleted_metadata_count,
            0,
        )?;
        let record = AccountLifecycleRecord {
            principal_id: request.principal_id.clone(),
            state: AccountLifecycleState::Deleted,
            lifecycle_epoch: existing.lifecycle_epoch.saturating_add(1),
            causal_event_id: format!("{}_finalized", existing.causal_event_id),
            updated_at: request.now,
            timelock_until: None,
            tombstone_hash: Some(tombstone_hash),
            deletion_proof: Some(proof),
        };
        let tombstone = record
            .tombstone_hash
            .as_deref()
            .and_then(|hash| self.lifecycle_tombstone_by_hash(hash));
        crate::lock_unpoisoned(&self.control)
            .lifecycle_by_principal
            .insert(request.principal_id.clone(), record.clone());
        Ok(LifecycleResponse { record, metadata_present: false, deleted_metadata_count, tombstone })
    }

    #[must_use]
    pub fn mvp7_lifecycle(&self, principal_id: &str) -> Option<AccountLifecycleRecord> {
        crate::lock_unpoisoned(&self.control).lifecycle_by_principal.get(principal_id).cloned()
    }

    #[must_use]
    pub fn mvp7_lifecycle_tombstone_by_hash(
        &self,
        tombstone_hash: &str,
    ) -> Option<IdentityLifecycleTombstone> {
        self.lifecycle_tombstone_by_hash(tombstone_hash)
    }

    /// # Errors
    /// Returns an error when the federated lifecycle tombstone signature or state is invalid.
    pub fn mvp7_apply_federated_tombstone(
        &self,
        request: &FederatedLifecycleTombstoneRequest,
    ) -> Result<FederatedLifecycleTombstoneResponse, NodeCoreError> {
        match request.lifecycle_state {
            AccountLifecycleState::Deactivated | AccountLifecycleState::Deleted => {
                let tombstone = request.tombstone.as_ref().ok_or_else(|| {
                    NodeCoreError::ItestHttp("missing federated lifecycle tombstone".to_owned())
                })?;
                verify_lifecycle_tombstone(tombstone)?;
                if request.lifecycle_state == AccountLifecycleState::Deleted
                    && request.deletion_proof.is_none()
                {
                    return Err(NodeCoreError::ItestHttp(
                        "missing federated deletion proof".to_owned(),
                    ));
                }
                crate::lock_unpoisoned(&self.control)
                    .lifecycle_tombstones
                    .insert(tombstone.tombstone_id.clone(), tombstone.clone());
                let mut shard = self.target_shard(&request.target_delivery_id);
                if request.lifecycle_state == AccountLifecycleState::Deleted {
                    shard.deactivated_delivery_targets.remove(&request.target_delivery_id);
                    shard.deleted_delivery_targets.insert(request.target_delivery_id.clone());
                } else {
                    shard.deactivated_delivery_targets.insert(request.target_delivery_id.clone());
                }
                Ok(FederatedLifecycleTombstoneResponse {
                    accepted: true,
                    lifecycle_state: request.lifecycle_state.clone(),
                    target_delivery_id: request.target_delivery_id.clone(),
                    tombstone_hash: Some(tombstone.tombstone_hash.clone()),
                })
            }
            AccountLifecycleState::Active => {
                let mut shard = self.target_shard(&request.target_delivery_id);
                if shard.deleted_delivery_targets.contains(&request.target_delivery_id) {
                    return Err(NodeCoreError::ItestHttp(format!(
                        "deleted target cannot reactivate: {}",
                        request.target_delivery_id
                    )));
                }
                shard.deactivated_delivery_targets.remove(&request.target_delivery_id);
                Ok(FederatedLifecycleTombstoneResponse {
                    accepted: true,
                    lifecycle_state: AccountLifecycleState::Active,
                    target_delivery_id: request.target_delivery_id.clone(),
                    tombstone_hash: None,
                })
            }
            AccountLifecycleState::DeletePending => Err(NodeCoreError::ItestHttp(
                "federated delete_pending tombstone is not accepted".to_owned(),
            )),
        }
    }

    pub(crate) fn store_lifecycle_tombstone(
        &self,
        request: &LifecycleEventRequest,
    ) -> Result<String, NodeCoreError> {
        let tombstone_id = format!("{}_tombstone", request.event_id);
        let actor_public_key = {
            let control = crate::lock_unpoisoned(&self.control);
            control
                .mvp1_identities
                .devices
                .get(&request.actor_device_id)
                .filter(|device| device.principal_id == request.principal_id)
                .map(|device| device.branch_public_key.clone())
                .ok_or_else(|| {
                    NodeCoreError::ItestHttp(format!(
                        "lifecycle actor device is not registered: {}",
                        request.actor_device_id
                    ))
                })?
        };
        let mut tombstone = IdentityLifecycleTombstone {
            tombstone_id: tombstone_id.clone(),
            target_id: request.principal_id.clone(),
            target_kind: "identity".to_owned(),
            actor_device_id: request.actor_device_id.clone(),
            actor_public_key,
            reason: request.reason_code.clone(),
            created_at: request.now,
            causal_event_id: request.event_id.clone(),
            signature: String::new(),
            tombstone_hash: String::new(),
        };
        tombstone.tombstone_hash = lifecycle_tombstone_hash(&tombstone)?;
        tombstone.signature = ramflux_crypto::sign_protocol_object(&tombstone)
            .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
        let tombstone_hash = tombstone.tombstone_hash.clone();
        crate::lock_unpoisoned(&self.control).lifecycle_tombstones.insert(tombstone_id, tombstone);
        Ok(tombstone_hash)
    }

    pub(crate) fn lifecycle_tombstone_by_hash(
        &self,
        tombstone_hash: &str,
    ) -> Option<IdentityLifecycleTombstone> {
        crate::lock_unpoisoned(&self.control)
            .lifecycle_tombstones
            .values()
            .find(|tombstone| tombstone.tombstone_hash == tombstone_hash)
            .cloned()
    }
}

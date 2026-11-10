// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Committed-head forwarding bypasses legacy route time and mailbox admission.
use super::{
    Arc, ForwardingReservationState, HomeNodeMigratedNackDelivery, HomeNodeMigrationForwardPlan,
    HomeNodeMigrationRecord, HomeNodeRouteRecord, NodeCoreError, Ordering, RouterCore,
    RouterForwardPreparation, RouterForwardReservation, RouterSubmitOutcome,
    complete_forward_preparation, envelope_home_node_forward_count,
    envelope_target_index_shard_index, forwarding_reservation_is_active, lock_unpoisoned,
};
impl RouterCore {
    /// Reserve a forward only after A durably checks its own committed window.
    /// # Errors
    /// Returns storage errors without reserving or forwarding any traffic.
    pub fn prepare_committed_home_forward(
        &self,
        store: &crate::RouterRedbStore,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: ramflux_protocol::Envelope,
        now: u64,
        lease_seconds: u64,
    ) -> Result<RouterForwardPreparation, NodeCoreError> {
        crate::check_entry_bound(&envelope)?;
        ramflux_protocol::ephemeral::require_durable(&envelope)?;
        let Some(head) = store.migration_forward_window(&envelope.target_delivery_id, now)? else {
            return closed_preparation(self, store, &envelope, now);
        };
        if envelope_home_node_forward_count(&envelope) > 0 {
            return Ok(complete_forward_preparation(RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id: envelope.target_delivery_id,
                reason: "migration_second_hop".into(),
            }));
        }
        let ramflux_protocol::home_migration::HomeRecord::Committed {
            commit_proof,
            authorization,
            ..
        } = &head.record
        else {
            return Err(NodeCoreError::Redb("committed head required".into()));
        };
        let proof_hash = ramflux_protocol::home_migration::record_hash(&head.record)
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        let now = i64::try_from(now).map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        let migration = HomeNodeMigrationRecord {
            format_version: 2,
            identity_commitment: head.record.account_anchor().into(),
            old_home_node: authorization.body.old_node.clone(),
            new_home_node: authorization.body.destination_node.clone(),
            new_home_node_key_hash: authorization.body.destination_key.clone(),
            route_record_hash: proof_hash.clone(),
            effective_at: i64::try_from(commit_proof.body.committed_at).unwrap_or(i64::MAX),
            issued_at: now,
            migration_proof_hash: proof_hash.clone(),
            migrated_at: now,
        };
        let route = committed_route(store, &head, &migration, now)?;
        let mut forwarded = envelope.clone();
        forwarded
            .ext
            .ext
            .insert(crate::HOME_NODE_FORWARD_COUNT_EXT_KEY.into(), serde_json::json!(1));
        let plan = HomeNodeMigrationForwardPlan {
            migration_evidence: Some(crate::ForwardedMigrationEvidence {
                commit_proof: Some((**commit_proof).clone()),
                retain_until: crate::inbox_retain_until(&envelope, now),
                floors: vec![],
            }),
            target_delivery_id: envelope.target_delivery_id.clone(),
            proof_hash,
            new_home_node: migration.new_home_node.clone(),
            route,
            envelope: forwarded,
            forward_count: 1,
        };
        let shard_index = envelope_target_index_shard_index(&envelope.envelope_id);
        let key = crate::envelope_replay_tuple_key(source, &envelope);
        let mut reservations = lock_unpoisoned(&self.forwarding_reservations.shards[shard_index]);
        if forwarding_reservation_is_active(&mut reservations, &key, now) {
            return Ok(complete_forward_preparation(RouterSubmitOutcome::ForwardInProgress {
                target_delivery_id: envelope.target_delivery_id,
            }));
        }
        let attempt_id =
            self.forwarding_reservations.next_attempt_id.fetch_add(1, Ordering::Relaxed);
        reservations.insert(
            key.clone(),
            ForwardingReservationState {
                attempt_id,
                lease_until: now
                    .saturating_add(i64::try_from(lease_seconds.max(1)).unwrap_or(i64::MAX)),
            },
        );
        drop(reservations);
        Ok(RouterForwardPreparation::Forward(Box::new(RouterForwardReservation {
            reservations: Arc::clone(&self.forwarding_reservations),
            shard_index,
            key,
            attempt_id,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope: Some(envelope),
            migration,
            plan: Some(plan),
            replayed: false,
            now_unix_seconds: now,
        })))
    }
}

fn closed_preparation(
    core: &RouterCore,
    store: &crate::RouterRedbStore,
    envelope: &ramflux_protocol::Envelope,
    now: u64,
) -> Result<RouterForwardPreparation, NodeCoreError> {
    let response = core.migration_submission_refusal(
        store,
        envelope,
        ramflux_protocol::home_migration::Refusal::HomeMigrated,
        now,
    )?;
    let nack = response
        .nack
        .ok_or_else(|| NodeCoreError::Redb("missing signed migration refusal".into()))?;
    Ok(complete_forward_preparation(RouterSubmitOutcome::RejectedHomeNodeMigrated(
        HomeNodeMigratedNackDelivery {
            target_delivery_id: envelope.target_delivery_id.clone(),
            proof_hash: nack.proof_hash.clone().unwrap_or_default(),
            new_home_node_hint: nack.new_home_node_hint.clone().unwrap_or_default(),
            nack,
        },
    )))
}

fn committed_route(
    store: &crate::RouterRedbStore,
    head: &ramflux_protocol::home_migration::RecordEvidence,
    migration: &HomeNodeMigrationRecord,
    now: i64,
) -> Result<HomeNodeRouteRecord, NodeCoreError> {
    let ramflux_protocol::home_migration::HomeRecord::Committed {
        commit_proof, authorization, ..
    } = &head.record
    else {
        return Err(NodeCoreError::Redb("committed route required".into()));
    };
    let proof_hash = &migration.migration_proof_hash;
    Ok(HomeNodeRouteRecord {
        identity_commitment: migration.identity_commitment.clone(),
        home_node: migration.new_home_node.clone(),
        home_node_key_hash: migration.new_home_node_key_hash.clone(),
        node_public_key: authorization.body.destination_key.clone(),
        node_endpoint: store
            .migration_operation(
                head.record.account_anchor(),
                &authorization.body.migration_id,
                crate::MigrationRole::Source,
            )?
            .ok_or(NodeCoreError::HomeMigration(
                ramflux_protocol::home_migration::Refusal::BaseMismatch,
            ))?
            .offer
            .body
            .federation_endpoint,
        route_record_hash: proof_hash.clone(),
        migration_proof_hash: proof_hash.clone(),
        route_update_proof_hash: String::new(),
        updated_at: now,
        expires_at: i64::try_from(commit_proof.body.forward_until).unwrap_or(i64::MAX),
    })
}

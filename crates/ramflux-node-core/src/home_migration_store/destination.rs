// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Destination reservations, seal CAS, proof-only activation and relayed terminal fences.
use super::{
    Action, Authorization, BUSINESS, BusinessOutcome, COURIER, DeliveryMapEntry, FORWARD_SECONDS,
    GUARDS, HEADS, HomeAttestation, HomeRecord, InboxRoute, MAX_COMMIT_DELAY, MAX_SEAL_DELAY,
    MigrationNode, MigrationOperation, MigrationRole, NodeCoreError, NoncommitFence, OPS, Offer,
    Phase, Prepare, Receipt, RecordEvidence, Refusal, RouterCore, RouterRedbStore, SKEW_SECONDS,
    Signed, TARGETS, VerifiedHome, auth_error, business_key, clock, commit_transition, crypto,
    delivery_map_hash, maintenance, map_for, message_hash, op_key, read, record_hash, refusal,
    save_head, storage, write,
};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::custody::object_hash;

#[derive(Clone, Copy)]
pub struct PrepareMigration<'a> {
    pub prepare: &'a Signed<Prepare>,
    pub attestation: &'a Signed<HomeAttestation>,
    pub base: &'a VerifiedHome,
    pub delivery_map: &'a [DeliveryMapEntry],
}
impl RouterCore {
    /// Reserve against A's independently authenticated home and current local authority.
    /// # Errors
    /// Rejects unregistered/stale bases, forged attestation, bad maps and exhausted live budgets.
    pub fn prepare_home_migration(
        &self,
        store: &RouterRedbStore,
        node: &MigrationNode,
        input: PrepareMigration<'_>,
        now: u64,
    ) -> Result<Signed<Offer>, NodeCoreError> {
        let p = &input.prepare.body;
        self.with_migration_authority(&p.account_anchor, now, |authority, _publication| {
            let (expected_map, map_hash) = verify_preparation(node, input, authority, now)?;
            let tx = store.migration_db().begin_write().map_err(storage)?;
            let now = clock(&tx, now)?;
            let key = op_key(&p.account_anchor, &p.migration_id, MigrationRole::Destination)?;
            if let Some(existing) = read::<MigrationOperation>(&tx, OPS, &key)? {
                if message_hash(&existing.prepare).map_err(storage)?
                    != message_hash(input.prepare).map_err(storage)?
                {
                    return Err(refusal(Refusal::IdempotencyConflict));
                }
                return Ok(existing.offer);
            }
            if let Some(floor) = read::<RecordEvidence>(&tx, HEADS, &p.account_anchor)?
                && !input
                    .base
                    .extends(floor.record.epoch(), &record_hash(&floor.record).map_err(storage)?)
            {
                return Err(refusal(Refusal::EvidenceRequired));
            }
            maintenance::reserve_budget(&tx, &p.account_anchor, true)?;
            let offer = crypto::sign_node(
                Offer {
                    version: 1,
                    migration_id: p.migration_id.clone(),
                    account_anchor: p.account_anchor.clone(),
                    prepare_hash: message_hash(input.prepare).map_err(storage)?,
                    authority_record_hash: p.authority_record_hash.clone(),
                    previous_home_hash: p.previous_home_hash.clone(),
                    next_home_epoch: p
                        .previous_home_epoch
                        .checked_add(1)
                        .filter(|v| *v <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
                        .ok_or_else(|| refusal(Refusal::HomeCheckpointRequired))?,
                    old_node: p.old_node.clone(),
                    destination_node: p.destination_node.clone(),
                    destination_key: p.destination_key.clone(),
                    discovery_hash: node.discovery_hash.clone(),
                    server_record_hash: node.server_record_hash.clone(),
                    gateway_tcp_addr: node.gateway_tcp_addr.clone(),
                    federation_endpoint: node.federation_endpoint.clone(),
                    delivery_map_hash: map_hash,
                    admission_id: ramflux_protocol::encode_base64url(
                        ramflux_crypto::random_32().map_err(auth_error)?,
                    ),
                    nonce: p.nonce.clone(),
                    issued_at: now,
                    accept_until: now
                        .checked_add(MAX_SEAL_DELAY)
                        .ok_or_else(|| refusal(Refusal::CommitExpired))?,
                    max_commit_delay: MAX_COMMIT_DELAY,
                    forward_seconds: FORWARD_SECONDS,
                },
                node.node_id(),
                &node.key,
            )
            .map_err(auth_error)?;
            let op = MigrationOperation {
                role: MigrationRole::Destination,
                phase: Phase::Prepared,
                prepare: input.prepare.clone(),
                offer: offer.clone(),
                authorization: None,
                seal: None,
                proof: None,
                fence: None,
                base: input.base.evidence().clone(),
                attestation: input.attestation.clone(),
                delivery_map: expected_map,
                state_version: 1,
                next_due: now,
                expires_at: offer.body.accept_until + SKEW_SECONDS,
                recovery_guard: false,
                live_budget: true,
            };
            write(&tx, OPS, &key, &op)?;
            maintenance::index_expiry(&tx, &key, op.expires_at)?;
            write(
                &tx,
                BUSINESS,
                &business_key(&p.account_anchor, &p.migration_id, Action::Prepare)?,
                &BusinessOutcome {
                    payload_hash: message_hash(input.prepare).map_err(storage)?,
                    operation_key: key,
                    expires_at: op.expires_at,
                },
            )?;
            commit_transition(store, tx)?;
            Ok(offer)
        })
    }
    /// Seal one immutable authorization and its dormant inboxes with a durable courier item.
    /// # Errors
    /// Rejects expired/conflicting admission, changed current roster or management authority.
    pub fn seal_home_migration(
        &self,
        store: &RouterRedbStore,
        node: &MigrationNode,
        authorization: &Signed<Authorization>,
        now: u64,
    ) -> Result<Signed<Receipt>, NodeCoreError> {
        let a = &authorization.body;
        self.with_migration_authority(&a.account_anchor,now,|authority, _publication|{
            let tx=store.migration_db().begin_write().map_err(storage)?;let now=clock(&tx,now)?;
            let key=op_key(&a.account_anchor,&a.migration_id,MigrationRole::Destination)?;
            let mut op:MigrationOperation=read(&tx,OPS,&key)?.ok_or_else(||refusal(Refusal::EvidenceRequired))?;
            let auth_hash=message_hash(authorization).map_err(storage)?;
            if let Some(existing)=&op.authorization {
                if message_hash(existing).map_err(storage)?!=auth_hash {return Err(refusal(Refusal::IdempotencyConflict));}
                if let Some(seal)=op.seal{return Ok(seal);}
            }
            if op.phase!=Phase::Prepared {return Err(refusal(Refusal::AdmissionExpired));}
            crypto::verify_authorization(authorization,authority,now).map_err(auth_error)?;
            let offer=&op.offer.body;
            if now>offer.accept_until || now>a.seal_until || a.seal_until>offer.accept_until
                || a.offer_hash!=message_hash(&op.offer).map_err(storage)? || a.previous_home_hash!=offer.previous_home_hash
                || a.next_home_epoch!=offer.next_home_epoch || a.old_node!=offer.old_node
                || a.destination_node!=node.node_id() || a.destination_key!=node.public_key()
                || a.gateway_tcp_addr!=node.gateway_tcp_addr || a.delivery_map_hash!=offer.delivery_map_hash
                || op.delivery_map!=map_for(authority)? || a.authority_record_hash!=offer.authority_record_hash
                || a.actor!=op.prepare.body.actor {return Err(refusal(Refusal::AuthorityUpdateRequired));}
            maintenance::require_no_live_window(&tx,&a.account_anchor,Some(&key))?;
            let deadline=now.checked_add(a.max_commit_delay).ok_or_else(||refusal(Refusal::CommitExpired))?;
            let seal=crypto::sign_node(Receipt{version:1,action:Action::Seal,migration_id:a.migration_id.clone(),account_anchor:a.account_anchor.clone(),node_id:node.node_id().into(),
                request_hash:auth_hash.clone(),request_nonce:a.nonce.clone(),authorization_hash:Some(auth_hash.clone()),seal_hash:None,home_record_hash:None,
                phase:Phase::Sealed,state_version:2,sealed_at:Some(now),commit_deadline:Some(deadline),commit_proof_hash:None,
                response_payload_hash:ramflux_protocol::custody::framed_hash(ramflux_protocol::domain::HOME_RECEIPT,&serde_json::json!({"offer":null,"commit_proof":null,"noncommit_fence":null,"resolve_result":null,"backlog_progress":null,"attestation":null})).map_err(storage)?,
                issued_at:now,expires_at:now+300,reason_code:None},node.node_id(),&node.key).map_err(auth_error)?;
            op.authorization=Some(authorization.clone());op.seal=Some(seal.clone());op.phase=Phase::Sealed;op.state_version=2;op.next_due=now;
            op.expires_at=crypto::hard_deadline(a).map_err(auth_error)?;op.recovery_guard=true;
            maintenance::unsealed_budget(&tx,&a.account_anchor,false)?;
            for entry in &op.delivery_map {
                if let Some(old)=read::<InboxRoute>(&tx,TARGETS,&entry.target_delivery_id)?
                    && (old.anchor!=a.account_anchor || old.epoch>=a.next_home_epoch) {return Err(refusal(Refusal::BaseMismatch));}
                write(&tx,TARGETS,&entry.target_delivery_id,&InboxRoute{anchor:a.account_anchor.clone(),migration_id:a.migration_id.clone(),epoch:a.next_home_epoch,active:false})?;
            }
            tx.open_table(GUARDS).map_err(storage)?.insert(a.account_anchor.as_str(),key.as_str()).map_err(storage)?;
            write(&tx,OPS,&key,&op)?;
            write(&tx,COURIER,&maintenance::due_key(now,&a.account_anchor,&a.migration_id),&key)?;
            write(&tx,BUSINESS,&business_key(&a.account_anchor,&a.migration_id,Action::Seal)?,&BusinessOutcome{payload_hash:auth_hash,operation_key:key,expires_at:op.expires_at})?;
            commit_transition(store,tx)?;Ok(seal)
        })
    }
}
impl RouterRedbStore {
    /// Activate only a verified A-signed successor matching B's own durable seal.
    /// # Errors
    /// Rejects another destination, mismatched sealed state, fork or durable failure.
    pub fn activate_home_migration(
        &self,
        node: &MigrationNode,
        result: &ramflux_protocol::home_migration::ResolveResult,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let HomeRecord::Committed { authorization, commit_proof } = &result.home.record else {
            return Err(refusal(Refusal::EvidenceRequired));
        };
        let a = &authorization.body;
        let tx = self.migration_db().begin_write().map_err(storage)?;
        let now = clock(&tx, now)?;
        let key = op_key(&a.account_anchor, &a.migration_id, MigrationRole::Destination)?;
        if let Some(head) = read::<RecordEvidence>(&tx, HEADS, &a.account_anchor)?
            && head.record.home() == (node.node_id(), node.public_key())
            && record_hash(&head.record).map_err(storage)?
                == record_hash(&result.home.record).map_err(storage)?
        {
            return Ok(());
        }
        let mut op: MigrationOperation =
            read(&tx, OPS, &key)?.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let home = verify_activation_base(result, &op, now)?;
        if op.fence.is_some() {
            return Err(refusal(Refusal::HomeFork));
        }
        let seal = op.seal.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let stored_auth =
            op.authorization.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let floor: Option<RecordEvidence> = read(&tx, HEADS, &a.account_anchor)?;
        let floor_hash =
            floor.as_ref().map(|e| record_hash(&e.record)).transpose().map_err(storage)?;
        crypto::activation_allowed(
            &home,
            &crypto::SealedBinding {
                destination_node: node.node_id(),
                destination_key: node.public_key(),
                authorization_hash: &message_hash(stored_auth).map_err(storage)?,
                offer_hash: &message_hash(&op.offer).map_err(storage)?,
                seal_hash: &message_hash(seal).map_err(storage)?,
                previous_home_hash: &record_hash(&op.base.record).map_err(storage)?,
                next_home_epoch: op.offer.body.next_home_epoch,
                home_floor: floor
                    .as_ref()
                    .zip(floor_hash.as_ref())
                    .map(|(e, h)| (e.record.epoch(), h.as_str())),
            },
        )
        .map_err(auth_error)?;
        if op.phase == Phase::Active {
            return Ok(());
        }
        if !matches!(op.phase, Phase::Sealed | Phase::CommitPending | Phase::CommitOutcomeUnknown) {
            return Err(refusal(Refusal::BaseMismatch));
        }
        save_head(&tx, home.evidence())?;
        for entry in &op.delivery_map {
            write(
                &tx,
                TARGETS,
                &entry.target_delivery_id,
                &InboxRoute {
                    anchor: a.account_anchor.clone(),
                    migration_id: a.migration_id.clone(),
                    epoch: a.next_home_epoch,
                    active: true,
                },
            )?;
        }
        maintenance::release_budget(&tx, &a.account_anchor, false)?;
        op.live_budget = false;
        maintenance::remove_courier(&tx, &op)?;
        maintenance::index_expiry(&tx, &key, op.expires_at)?;
        op.phase = Phase::Active;
        op.proof = Some((**commit_proof).clone());
        op.state_version += 1;
        op.recovery_guard = false;
        tx.open_table(GUARDS)
            .map_err(storage)?
            .remove(a.account_anchor.as_str())
            .map_err(storage)?;
        write(&tx, OPS, &key, &op)?;
        commit_transition(self, tx)?;
        Ok(())
    }
    /// A client or B's courier may relay a standalone terminal fence; no nonce freshness is needed.
    /// # Errors
    /// Rejects a conflicting commit, another source or a fence for another sealed operation.
    pub fn accept_home_noncommit_fence(
        &self,
        fence: &Signed<NoncommitFence>,
        anchor: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let tx = self.migration_db().begin_write().map_err(storage)?;
        clock(&tx, now)?;
        let key = op_key(anchor, &fence.body.migration_id, MigrationRole::Destination)?;
        let mut op: MigrationOperation =
            read(&tx, OPS, &key)?.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let (old, old_key) = op.base.record.home();
        crypto::verify_node(fence, old, old_key).map_err(auth_error)?;
        if op.proof.is_some() || op.phase == Phase::Active {
            return Err(refusal(Refusal::HomeFork));
        }
        if fence.body.authorization_hash
            != message_hash(
                op.authorization.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?,
            )
            .map_err(storage)?
            || fence.body.seal_hash.as_ref().is_some_and(|hash| {
                op.seal.as_ref().and_then(|seal| message_hash(seal).ok()).as_ref() != Some(hash)
            })
        {
            return Err(refusal(Refusal::BaseMismatch));
        }
        if op.fence.is_some() {
            return Ok(());
        }
        maintenance::remove_courier(&tx, &op)?;
        op.live_budget = false;
        op.fence = Some(fence.clone());
        op.phase = Phase::Expired;
        op.state_version += 1;
        op.recovery_guard = false;
        for entry in &op.delivery_map {
            write(
                &tx,
                TARGETS,
                &entry.target_delivery_id,
                &InboxRoute {
                    anchor: anchor.into(),
                    migration_id: fence.body.migration_id.clone(),
                    epoch: op.offer.body.next_home_epoch,
                    active: false,
                },
            )?;
        }
        tx.open_table(GUARDS).map_err(storage)?.remove(anchor).map_err(storage)?;
        write(&tx, OPS, &key, &op)?;
        maintenance::index_expiry(&tx, &key, op.expires_at)?;
        maintenance::release_budget(&tx, anchor, false)?;
        commit_transition(self, tx)?;
        Ok(())
    }
}

fn verify_preparation(
    node: &MigrationNode,
    input: PrepareMigration<'_>,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(Vec<DeliveryMapEntry>, String), NodeCoreError> {
    let p = &input.prepare.body;
    crypto::verify_actor(input.prepare, authority, now).map_err(auth_error)?;
    let (old, old_key) = input.base.home();
    crypto::verify_node(input.attestation, old, old_key).map_err(auth_error)?;
    let attest = &input.attestation.body;
    let expected_map = map_for(authority)?;
    let map_hash = delivery_map_hash(&expected_map).map_err(storage)?;
    if p.destination_node != node.node_id()
        || p.destination_key != node.public_key()
        || p.old_node != old
        || input.base.hash() != p.previous_home_hash
        || input.base.epoch() != p.previous_home_epoch
        || input.base.evidence().record.account_anchor() != p.account_anchor
        || attest.account_anchor != p.account_anchor
        || attest.audience_node != node.node_id()
        || attest.previous_home_hash != p.previous_home_hash
        || attest.authority_record_hash != object_hash(authority.envelope()).map_err(storage)?
        || attest.device_set_epoch != authority.envelope().body.device_set_epoch
        || attest.delivery_map_hash != map_hash
        || p.delivery_map_hash != map_hash
        || input.delivery_map != expected_map
        || attest.issued_at > now.saturating_add(SKEW_SECONDS)
        || attest.expires_at <= attest.issued_at
        || attest.expires_at - attest.issued_at > 60
        || now > attest.expires_at
        || attest.nonce != p.nonce
    {
        return Err(refusal(Refusal::AuthorityUpdateRequired));
    }
    Ok((expected_map, map_hash))
}

fn verify_activation_base(
    result: &ramflux_protocol::home_migration::ResolveResult,
    op: &MigrationOperation,
    now: u64,
) -> Result<VerifiedHome, NodeCoreError> {
    let base_hash = record_hash(&op.base.record).map_err(storage)?;
    let (source, source_key) = op.base.record.home();
    let home = crypto::verify_home_chain(
        result,
        &crypto::HomeTrust {
            account_anchor: op.base.record.account_anchor(),
            node_id: source,
            node_key: source_key,
            home_epoch: op.base.record.epoch(),
            home_hash: Some(&base_hash),
            cached_manager_range: op.base.authority.record.body.master_certificate.body.range_index,
            cached_manager_certificate_hash: Some(
                &object_hash(&op.base.authority.record.body.master_certificate).map_err(storage)?,
            ),
        },
        now,
    )
    .map_err(auth_error)?;
    Ok(home)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-node genesis, account-authorized base CAS and terminal cancellation finality.
use super::{
    Action, BACKLOG, BUSINESS, BusinessOutcome, CommitProof, DeliveryMapEntry, FORWARD_SECONDS,
    GUARDS, Genesis, HEADS, HomeAttestation, HomeRecord, MAX_CHAIN_RECORDS, MigrationNode,
    MigrationOperation, MigrationRole, NodeCoreError, NoncommitFence, OPS, PROOFS, Phase, RECORDS,
    RecordEvidence, Refusal, RouterCore, RouterRedbStore, Signed, VerifiedRecord, auth_error,
    business_key, clock, commit_transition, crypto, delivery_map_hash, maintenance, map_for,
    message_hash, op_key, read, record_hash, refusal, save_head, storage, write,
};
use ramflux_protocol::custody::object_hash;
/// Independently admitted peer pin, supplied by server mesh configuration, never JSON.
#[derive(Clone, Copy)]
pub struct MigrationPeer<'a> {
    pub node_id: &'a str,
    pub node_key: &'a str,
}
#[derive(Clone, Copy)]
pub struct AttestMigration<'a> {
    pub account_anchor: &'a str,
    pub destination: &'a str,
    pub nonce: &'a str,
}
pub struct AttestedHome {
    pub home: RecordEvidence,
    pub attestation: Signed<HomeAttestation>,
    pub delivery_map: Vec<DeliveryMapEntry>,
}
#[derive(Clone, Copy)]
pub struct CommitMigration<'a> {
    pub sealed: &'a MigrationOperation,
    pub peer: MigrationPeer<'a>,
}
pub enum FenceOutcome {
    Fenced(Signed<NoncommitFence>),
    Committed(Box<RecordEvidence>),
}
impl RouterCore {
    /// Attest an existing registration, creating node-signed genesis on the first request.
    /// # Errors
    /// Rejects absent registration, a different current home and invalid node authority.
    pub fn attest_home_migration(
        &self,
        store: &RouterRedbStore,
        node: &MigrationNode,
        input: AttestMigration<'_>,
        now: u64,
    ) -> Result<AttestedHome, NodeCoreError> {
        let AttestMigration { account_anchor: anchor, destination, nonce } = input;
        self.with_migration_authority(anchor, now, |authority| {
            let map = map_for(authority)?;
            let mut registered = false;
            for entry in &map {
                registered |= store.custody_prekey(&entry.target_delivery_id)?.is_some();
            }
            if !registered || destination == node.node_id() {
                return Err(refusal(Refusal::HomeGenesisRequired));
            }
            let tx = store.migration_db().begin_write().map_err(storage)?;
            clock(&tx, now)?;
            let head = if let Some(head) = read::<RecordEvidence>(&tx, HEADS, anchor)? {
                head
            } else {
                let genesis = crypto::sign_node(
                    Genesis {
                        version: 1,
                        account_anchor: anchor.into(),
                        home_epoch: 0,
                        home_node: node.node_id().into(),
                        home_node_key: node.public_key().into(),
                        custody_record_hash: object_hash(authority.envelope()).map_err(storage)?,
                        registered_at: now,
                    },
                    node.node_id(),
                    &node.key,
                )
                .map_err(auth_error)?;
                let head = RecordEvidence {
                    record: HomeRecord::Genesis { genesis: Box::new(genesis) },
                    management_certificate_chain: vec![],
                    actor_certificate: None,
                    node_record: node.record.clone(),
                };
                save_head(&tx, &head)?;
                head
            };
            if head.record.home() != (node.node_id(), node.public_key()) {
                return Err(refusal(Refusal::BaseMismatch));
            }
            let attestation = crypto::sign_node(
                HomeAttestation {
                    version: 1,
                    account_anchor: anchor.into(),
                    audience_node: destination.into(),
                    previous_home_hash: record_hash(&head.record).map_err(storage)?,
                    authority_record_hash: object_hash(authority.envelope()).map_err(storage)?,
                    device_set_epoch: authority.envelope().body.device_set_epoch,
                    delivery_map_hash: delivery_map_hash(&map).map_err(storage)?,
                    nonce: nonce.into(),
                    issued_at: now,
                    expires_at: now + 60,
                },
                node.node_id(),
                &node.key,
            )
            .map_err(auth_error)?;
            commit_transition(store, tx)?;
            Ok(AttestedHome { home: head, attestation, delivery_map: map })
        })
    }
    /// Serialize one E+1, proof, recovery gate and backlog schedule in the router database.
    /// # Errors
    /// Rejects stale bases/authority/maps, unadmitted destination keys, expired seals and cancellation.
    pub fn commit_home_migration(
        &self,
        store: &RouterRedbStore,
        node: &MigrationNode,
        input: CommitMigration<'_>,
        now: u64,
    ) -> Result<RecordEvidence, NodeCoreError> {
        let CommitMigration { sealed, peer } = input;
        let auth =
            sealed.authorization.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let seal = sealed.seal.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let a = &auth.body;
        self.with_migration_authority(&a.account_anchor, now, |authority| {
            let tx = store.migration_db().begin_write().map_err(storage)?;
            clock(&tx, now)?;
            let key = op_key(&a.account_anchor, &a.migration_id, MigrationRole::Source)?;
            if let Some(hash) = read::<String>(&tx, PROOFS, &key)? {
                let record: RecordEvidence = read(&tx, RECORDS, &hash)?
                    .ok_or_else(|| storage("migration permanent proof lost its record"))?;
                let HomeRecord::Committed { authorization, .. } = &record.record else {
                    return Err(storage("migration proof index points to genesis"));
                };
                if message_hash(authorization).map_err(storage)?
                    != message_hash(auth).map_err(storage)?
                {
                    return Err(refusal(Refusal::IdempotencyConflict));
                }
                return Ok(record);
            }
            if let Some(old) = read::<MigrationOperation>(&tx, OPS, &key)? {
                if old.authorization.as_ref().map(message_hash).transpose().map_err(storage)?
                    != Some(message_hash(auth).map_err(storage)?)
                {
                    return Err(refusal(Refusal::IdempotencyConflict));
                }
                if old.fence.is_some() {
                    return Err(refusal(Refusal::CommitExpired));
                }
                if let Some(proof) = old.proof {
                    let record = HomeRecord::Committed {
                        authorization: Box::new(auth.clone()),
                        commit_proof: Box::new(proof),
                    };
                    return read(&tx, RECORDS, &record_hash(&record).map_err(storage)?)?
                        .ok_or_else(|| storage("migration committed proof lost its record"));
                }
            }
            crypto::verify_authorization(auth, authority, now).map_err(auth_error)?;
            verify_sealed(node, sealed, peer, authority, true)?;
            let deadline = crypto::commit_bounds(a, &sealed.offer.body, &seal.body, now)
                .map_err(|_| refusal(Refusal::CommitExpired))?;
            let current: RecordEvidence = read(&tx, HEADS, &a.account_anchor)?
                .ok_or_else(|| refusal(Refusal::HomeGenesisRequired))?;
            if record_hash(&current.record).map_err(storage)? != a.previous_home_hash
                || current.record.epoch().checked_add(1) != Some(a.next_home_epoch)
                || current.record.home() != (node.node_id(), node.public_key())
                || a.next_home_epoch >= MAX_CHAIN_RECORDS as u64
            {
                return Err(refusal(Refusal::BaseMismatch));
            }
            maintenance::require_no_live_window(&tx, &a.account_anchor, None)?;
            maintenance::reserve_budget(&tx, &a.account_anchor, false)?;
            let backlog_hash = schedule_backlog(&tx, a, &sealed.delivery_map, now)?;
            let evidence = committed_evidence(
                node,
                sealed,
                authority,
                CommitMoment { now, deadline, backlog_hash },
            )?;
            let HomeRecord::Committed { commit_proof, .. } = &evidence.record else {
                return Err(storage("migration commit produced genesis"));
            };
            save_head(&tx, &evidence)?;
            write(&tx, PROOFS, &key, &record_hash(&evidence.record).map_err(storage)?)?;
            let mut source = sealed.clone();
            source.base = current;
            source.role = MigrationRole::Source;
            source.phase = Phase::Committed;
            source.proof = Some((**commit_proof).clone());
            source.state_version += 1;
            source.recovery_guard = true;
            write(&tx, OPS, &key, &source)?;
            tx.open_table(GUARDS)
                .map_err(storage)?
                .insert(a.account_anchor.as_str(), key.as_str())
                .map_err(storage)?;
            write(
                &tx,
                BUSINESS,
                &business_key(&a.account_anchor, &a.migration_id, Action::Commit)?,
                &BusinessOutcome {
                    payload_hash: message_hash(auth).map_err(storage)?,
                    operation_key: key,
                    expires_at: source.expires_at,
                },
            )?;
            commit_transition(store, tx)?;
            Ok(evidence)
        })
    }
    /// Cancellation/expiry and first commit use the same durable source operation CAS.
    /// # Errors
    /// Rejects wrong seals/authority and returns the existing proof instead of rolling it back.
    pub fn fence_home_migration(
        &self,
        store: &RouterRedbStore,
        node: &MigrationNode,
        input: CommitMigration<'_>,
        now: u64,
        cancel: bool,
    ) -> Result<FenceOutcome, NodeCoreError> {
        let CommitMigration { sealed, peer } = input;
        let a = sealed.authorization.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let s = sealed.seal.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        self.with_migration_authority(&a.body.account_anchor, now, |authority| {
            let tx = store.migration_db().begin_write().map_err(storage)?;
            clock(&tx, now)?;
            let key = op_key(&a.body.account_anchor, &a.body.migration_id, MigrationRole::Source)?;
            if let Some(hash) = read::<String>(&tx, PROOFS, &key)? {
                let record: RecordEvidence = read(&tx, RECORDS, &hash)?
                    .ok_or_else(|| storage("migration permanent proof lost its record"))?;
                let HomeRecord::Committed { authorization, .. } = &record.record else {
                    return Err(storage("migration proof index points to genesis"));
                };
                if message_hash(authorization).map_err(storage)?
                    != message_hash(a).map_err(storage)?
                {
                    return Err(refusal(Refusal::IdempotencyConflict));
                }
                return Ok(FenceOutcome::Committed(Box::new(record)));
            }
            if let Some(old) = read::<MigrationOperation>(&tx, OPS, &key)? {
                if old.authorization.as_ref().map(message_hash).transpose().map_err(storage)?
                    != Some(message_hash(a).map_err(storage)?)
                {
                    return Err(refusal(Refusal::IdempotencyConflict));
                }
                if let Some(proof) = old.proof {
                    let record = HomeRecord::Committed {
                        authorization: Box::new(a.clone()),
                        commit_proof: Box::new(proof),
                    };
                    return Ok(FenceOutcome::Committed(Box::new(
                        read(&tx, RECORDS, &record_hash(&record).map_err(storage)?)?
                            .ok_or_else(|| storage("migration commit record unavailable"))?,
                    )));
                }
                if let Some(fence) = old.fence {
                    return Ok(FenceOutcome::Fenced(fence));
                }
            }
            verify_sealed(node, sealed, peer, authority, false)?;
            if !cancel
                && now
                    <= s.body.commit_deadline.ok_or_else(|| refusal(Refusal::EvidenceRequired))?
                && now <= crypto::hard_deadline(&a.body).map_err(auth_error)?
            {
                return Err(refusal(Refusal::CommitOutcomeUnknown));
            }
            // The caller's fresh custody action authenticates cancellation; a courier may only expire.
            let fence = crypto::sign_node(
                NoncommitFence {
                    version: 1,
                    migration_id: a.body.migration_id.clone(),
                    authorization_hash: message_hash(a).map_err(storage)?,
                    seal_hash: message_hash(s).map_err(storage)?,
                    fenced_at: now,
                },
                node.node_id(),
                &node.key,
            )
            .map_err(auth_error)?;
            if now <= crypto::hard_deadline(&a.body).map_err(auth_error)? {
                let mut old = sealed.clone();
                old.role = MigrationRole::Source;
                old.phase = Phase::Expired;
                old.fence = Some(fence.clone());
                old.recovery_guard = false;
                write(&tx, OPS, &key, &old)?;
                maintenance::index_expiry(&tx, &key, old.expires_at)?;
            }
            commit_transition(store, tx)?;
            Ok(FenceOutcome::Fenced(fence))
        })
    }
}
fn verify_sealed(
    node: &MigrationNode,
    sealed: &MigrationOperation,
    peer: MigrationPeer<'_>,
    authority: &VerifiedRecord,
    check_current: bool,
) -> Result<(), NodeCoreError> {
    let auth = sealed.authorization.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
    let a = &auth.body;
    let seal = sealed.seal.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
    crypto::verify_signatures(auth).map_err(auth_error)?;
    crypto::verify_signatures(&sealed.prepare).map_err(auth_error)?;
    crypto::verify_node(&sealed.offer, peer.node_id, peer.node_key).map_err(auth_error)?;
    crypto::verify_node(seal, peer.node_id, peer.node_key).map_err(auth_error)?;
    crypto::verify_node(&sealed.attestation, node.node_id(), node.public_key())
        .map_err(auth_error)?;
    let p = &sealed.prepare.body;
    let o = &sealed.offer.body;
    let s = &seal.body;
    let current_hash = object_hash(authority.envelope()).map_err(storage)?;
    if a.old_node != node.node_id()
        || a.destination_node != peer.node_id
        || a.destination_key != peer.node_key
        || p.account_anchor != a.account_anchor
        || p.migration_id != a.migration_id
        || p.authority_record_hash != a.authority_record_hash
        || p.previous_home_epoch.checked_add(1) != Some(a.next_home_epoch)
        || p.actor != a.actor
        || p.old_node != a.old_node
        || p.destination_node != a.destination_node
        || p.destination_key != a.destination_key
        || p.previous_home_hash != a.previous_home_hash
        || o.account_anchor != a.account_anchor
        || o.migration_id != a.migration_id
        || o.authority_record_hash != a.authority_record_hash
        || o.prepare_hash != message_hash(&sealed.prepare).map_err(storage)?
        || o.old_node != a.old_node
        || o.destination_node != a.destination_node
        || o.destination_key != a.destination_key
        || o.forward_seconds != a.forward_seconds
        || a.gateway_tcp_addr != o.gateway_tcp_addr
        || o.nonce != p.nonce
        || sealed.attestation.body.nonce != p.nonce
        || o.next_home_epoch != a.next_home_epoch
        || o.previous_home_hash != a.previous_home_hash
        || o.delivery_map_hash != a.delivery_map_hash
        || a.offer_hash != message_hash(&sealed.offer).map_err(storage)?
        || s.action != Action::Seal
        || s.phase != Phase::Sealed
        || s.migration_id != a.migration_id
        || s.account_anchor != a.account_anchor
        || s.authorization_hash.as_deref() != Some(message_hash(auth).map_err(storage)?.as_str())
        || sealed.attestation.body.account_anchor != a.account_anchor
        || sealed.attestation.body.previous_home_hash != a.previous_home_hash
        || sealed.attestation.body.audience_node != peer.node_id
        || sealed.attestation.body.authority_record_hash != a.authority_record_hash
        || sealed.attestation.body.delivery_map_hash != a.delivery_map_hash
        || (check_current && a.authority_record_hash != current_hash)
        || (check_current && sealed.delivery_map != map_for(authority)?)
        || a.delivery_map_hash != delivery_map_hash(&sealed.delivery_map).map_err(storage)?
    {
        return Err(refusal(Refusal::AuthorityUpdateRequired));
    }
    Ok(())
}

struct CommitMoment {
    now: u64,
    deadline: u64,
    backlog_hash: String,
}
fn committed_evidence(
    node: &MigrationNode,
    sealed: &MigrationOperation,
    authority: &VerifiedRecord,
    moment: CommitMoment,
) -> Result<RecordEvidence, NodeCoreError> {
    let auth = sealed.authorization.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
    let a = &auth.body;
    let seal = sealed.seal.as_ref().ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
    let CommitMoment { now, deadline, backlog_hash } = moment;
    let proof = crypto::sign_node(
        CommitProof {
            version: 1,
            migration_id: a.migration_id.clone(),
            account_anchor: a.account_anchor.clone(),
            old_node: a.old_node.clone(),
            destination_node: a.destination_node.clone(),
            destination_key: a.destination_key.clone(),
            previous_home_hash: a.previous_home_hash.clone(),
            next_home_epoch: a.next_home_epoch,
            authority_record_hash: a.authority_record_hash.clone(),
            authorization_hash: message_hash(auth).map_err(storage)?,
            offer_hash: message_hash(&sealed.offer).map_err(storage)?,
            seal_hash: message_hash(seal).map_err(storage)?,
            commit_deadline: deadline,
            committed_at: now,
            forward_until: now
                .checked_add(FORWARD_SECONDS)
                .ok_or_else(|| refusal(Refusal::CommitExpired))?,
            backlog_manifest_hash: backlog_hash,
        },
        node.node_id(),
        &node.key,
    )
    .map_err(auth_error)?;
    let actor = authority
        .envelope()
        .body
        .devices
        .iter()
        .find(|d| d.device_id == a.actor.device_id)
        .and_then(|d| d.branch_certificate.clone())
        .ok_or_else(|| refusal(Refusal::ActorRevoked))?;
    let evidence = RecordEvidence {
        record: HomeRecord::Committed {
            authorization: Box::new(auth.clone()),
            commit_proof: Box::new(proof.clone()),
        },
        management_certificate_chain: vec![authority.envelope().body.master_certificate.clone()],
        actor_certificate: Some(actor),
        node_record: node.record.clone(),
    };
    Ok(evidence)
}

fn schedule_backlog(
    tx: &redb::WriteTransaction,
    a: &ramflux_protocol::home_migration::Authorization,
    map: &[DeliveryMapEntry],
    now: u64,
) -> Result<String, NodeCoreError> {
    let cursors = RouterRedbStore::migration_backlog_barrier(
        tx,
        &a.account_anchor,
        &a.migration_id,
        map,
        now,
    )?;
    for cursor in &cursors {
        write(
            tx,
            BACKLOG,
            &serde_json::to_string(&(
                &cursor.account_anchor,
                &cursor.migration_id,
                &cursor.target_delivery_id,
            ))
            .map_err(storage)?,
            cursor,
        )?;
    }
    let backlog_hash = ramflux_protocol::custody::framed_hash(
        ramflux_protocol::domain::HOME_DELIVERY_MAP,
        &cursors,
    )
    .map_err(storage)?;
    Ok(backlog_hash)
}

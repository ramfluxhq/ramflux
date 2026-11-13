// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home-writer CAS and exact-operation/outbox idempotency in one durable transaction.
use super::{AccountReach, Result, refuse, storage};
use crate::{RouterRedbStore, custody_authority::CustodyAccountState};
use ramflux_protocol::{
    contact_reach::{
        Admission, Applied, Decision, MAX_FRAME_BYTES, MAX_STATE_BYTES, NOTICE_DOMAIN, Notice,
        OPERATION_HASH_DOMAIN, Operation, OperationResult, PeerReply, Query, Reason, Subject,
        Submission, SubmitOutcome,
    },
    custody::{self, DeviceRef, Envelope as Signed},
};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

pub(super) const ACCOUNTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_accounts_v1");
const OPERATIONS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_operations_v1");
pub(super) const OUTBOX: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_outbox_v1");
const CLOCK: TableDefinition<&str, u64> = TableDefinition::new("contact_reach_clock_v1");
const CUSTODY: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_accounts_v3");
const HEADS: TableDefinition<&str, &[u8]> = TableDefinition::new("home_head_v1");
const TRUST: TableDefinition<&str, &[u8]> = TableDefinition::new("contact_reach_peer_trust_v1");
const QUERIES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_candidate_queries_v1");
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptedPeer {
    home: ramflux_protocol::home_migration::RecordEvidence,
    authority_pins: ramflux_crypto::custody::AuthorityPins,
    custodian_pins: ramflux_crypto::custody::AuthorityPins,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateQuery {
    query: Query,
    expires: u64,
    consumed: bool,
    authenticated_node_key: Option<String>,
    snapshot_hash: Option<String>,
}

/// Session-derived owner context. Services derive both fields from authenticated state.
#[derive(Clone, Copy)]
pub struct ReachOwner<'a> {
    pub recipient_root: &'a str,
    pub actor: &'a DeviceRef,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRow {
    hash: String,
    expires_at: u64,
    result: OperationResult,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachOutbox {
    pub recipient_root: String,
    pub operation_id: String,
    pub operation_hash: String,
    pub target_node_id: String,
    pub submission: Submission,
    pub retain_until: u64,
}

pub(super) fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(ramflux_protocol::canonical_json_bytes(value)?)
}
pub(super) fn row<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(storage)
}

pub(super) fn clock(tx: &redb::WriteTransaction, now: u64) -> Result<u64> {
    if now > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
        return Err(refuse(Reason::ForeignUnavailable));
    }
    let mut table = tx.open_table(CLOCK).map_err(storage)?;
    let previous = table.get("floor").map_err(storage)?.map_or(0, |v| v.value());
    let fenced = now.max(previous);
    table.insert("floor", fenced).map_err(storage)?;
    Ok(fenced)
}
pub(super) fn load(tx: &redb::WriteTransaction, root: &str) -> Result<AccountReach> {
    tx.open_table(ACCOUNTS)
        .map_err(storage)?
        .get(root)
        .map_err(storage)?
        .map(|v| row(v.value()))
        .transpose()
        .map(Option::unwrap_or_default)
}
pub(super) fn save(tx: &redb::WriteTransaction, root: &str, state: &AccountReach) -> Result<()> {
    let bytes = encoded(state)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(refuse(Reason::ForeignCapacity));
    }
    tx.open_table(ACCOUNTS).map_err(storage)?.insert(root, bytes.as_slice()).map_err(storage)?;
    Ok(())
}

fn account(tx: &redb::WriteTransaction, root: &str) -> Result<CustodyAccountState> {
    tx.open_table(CUSTODY)
        .map_err(storage)?
        .get(root)
        .map_err(storage)?
        .map(|v| row(v.value()))
        .transpose()?
        .ok_or_else(|| refuse(Reason::CustodyRefused))
}
pub(super) fn authority(
    tx: &redb::WriteTransaction,
    root: &str,
    now: u64,
) -> Result<ramflux_crypto::custody::VerifiedRecord> {
    let state = account(tx, root)?;
    let cert = &state.publication.record.body.master_certificate.body;
    let human = if cert.custody_kind == custody::CustodyKind::ExternalHuman {
        let human = account(tx, &cert.primary_device_ref.account_anchor)?;
        let verified = ramflux_crypto::custody::verify_record(
            &human.publication.record,
            now,
            human.publication.compacted_ids.as_deref(),
            None,
        )?;
        human.pins.require_current(&verified)?;
        Some(verified)
    } else {
        None
    };
    let verified = ramflux_crypto::custody::verify_record(
        &state.publication.record,
        now,
        state.publication.compacted_ids.as_deref(),
        human.as_ref(),
    )?;
    state.pins.require_current(&verified)?;
    Ok(verified)
}
pub(super) fn authorize_read(
    authority: &ramflux_crypto::custody::VerifiedRecord,
    actor: &DeviceRef,
    now: u64,
) -> Result<()> {
    if actor.account_anchor == authority.envelope().body.account_anchor {
        authority.authorize(actor, "sync", now)?;
    } else {
        authority.authorize_primary_management(actor, "contact_consent", now)?;
    }
    Ok(())
}

pub(super) fn home(
    tx: &redb::WriteTransaction,
    root: &str,
) -> Result<ramflux_protocol::home_migration::RecordEvidence> {
    tx.open_table(HEADS)
        .map_err(storage)?
        .get(root)
        .map_err(storage)?
        .map(|v| row(v.value()))
        .transpose()?
        .ok_or_else(|| refuse(Reason::HomeEvidenceRequired))
}

fn key(root: &str, id: &str) -> Result<String> {
    serde_json::to_string(&(root, id)).map_err(storage)
}

impl RouterRedbStore {
    /// Retain bounded query correlation separately from permanent authority pins.
    /// Calling this does not grant contact, delivery, directory or own-copy permission.
    /// # Errors
    /// Refuses an unauthenticated account/device, changed query reuse and candidate saturation.
    pub fn reach_remember_query(
        &self,
        owner: ReachOwner<'_>,
        query: &Query,
        now: u64,
    ) -> Result<()> {
        query.validate()?;
        if encoded(query)?.len() > 4096 {
            return Err(refuse(Reason::ForeignPayloadTooLarge));
        }
        let tx = self.begin_write()?;
        let now = clock(&tx, now)?;
        let authority = authority(&tx, owner.recipient_root, now)?;
        authority.authorize(owner.actor, "message", now)?;
        let home = home(&tx, owner.recipient_root)?;
        if query.source_node != home.record.home().0 {
            return Err(refuse(Reason::AnchorMismatch));
        }
        let mut table = tx.open_table(QUERIES).map_err(storage)?;
        let expired = table
            .iter()
            .map_err(storage)?
            .take(256)
            .map(|v| {
                let (key, value) = v.map_err(storage)?;
                Ok((key.value().to_owned(), row::<CandidateQuery>(value.value())?))
            })
            .collect::<Result<Vec<_>>>()?;
        for (key, value) in expired {
            if value.expires <= now {
                table.remove(key.as_str()).map_err(storage)?;
            }
        }
        let key = key(owner.recipient_root, &query.nonce)?;
        let prior = table
            .get(key.as_str())
            .map_err(storage)?
            .map(|v| row::<CandidateQuery>(v.value()))
            .transpose()?;
        if let Some(prior) = prior {
            if prior.query != *query || prior.consumed {
                return Err(refuse(Reason::IdempotencyConflict));
            }
            return Ok(());
        }
        if table.len().map_err(storage)? >= 256 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        table
            .insert(
                key.as_str(),
                encoded(&CandidateQuery {
                    query: query.clone(),
                    expires: now
                        .checked_add(60)
                        .ok_or_else(|| refuse(Reason::ForeignUnavailable))?,
                    consumed: false,
                    authenticated_node_key: None,
                    snapshot_hash: None,
                })?
                .as_slice(),
            )
            .map_err(storage)?;
        drop(table);
        tx.commit()?;
        Ok(())
    }
    /// Read the authoritative state without synthesizing a default policy.
    /// # Errors
    /// Returns storage failures; absent state is not an open account.
    pub fn reach_account(&self, root: &str) -> Result<Option<AccountReach>> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(ACCOUNTS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(storage(e)),
        };
        table.get(root).map_err(storage)?.map(|v| row(v.value())).transpose()
    }

    /// Read an authenticated owner's retained checkpoint without installing a peer key.
    /// # Errors
    /// Refuses unavailable owner authority or malformed retained storage.
    pub fn reach_peer_checkpoint(
        &self,
        owner: ReachOwner<'_>,
        peer_root: &str,
        now: u64,
    ) -> Result<Option<ramflux_protocol::home_migration::RecordEvidence>> {
        let tx = self.begin_write()?;
        let now = clock(&tx, now)?;
        authority(&tx, owner.recipient_root, now)?.authorize(owner.actor, "message", now)?;
        let trust_key = key(owner.recipient_root, peer_root)?;
        let previous = tx
            .open_table(TRUST)
            .map_err(storage)?
            .get(trust_key.as_str())
            .map_err(storage)?
            .map(|v| row::<AdoptedPeer>(v.value()))
            .transpose()?;
        tx.commit()?;
        Ok(previous.map(|state| state.home))
    }

    /// Cache the exact result of an independently authenticated resolver read.
    /// Only the resolver calls this after TLS/discovery continuity and peer snapshot verification;
    /// owner-provided Reply objects never select or install this node key.
    /// # Errors
    /// Refuses absent/stale query correlation, mismatched peer and changed results.
    pub fn reach_remember_verified_reply(
        &self,
        owner: ReachOwner<'_>,
        query: &Query,
        peer: &ramflux_crypto::contact_reach::VerifiedPeer,
        now: u64,
    ) -> Result<()> {
        let tx = self.begin_write()?;
        let now = clock(&tx, now)?;
        authority(&tx, owner.recipient_root, now)?.authorize(owner.actor, "message", now)?;
        let key = key(owner.recipient_root, &query.nonce)?;
        let mut table = tx.open_table(QUERIES).map_err(storage)?;
        let mut candidate: CandidateQuery = table
            .get(key.as_str())
            .map_err(storage)?
            .map(|v| row(v.value()))
            .transpose()?
            .ok_or_else(|| refuse(Reason::ForeignSnapshotInvalid))?;
        if candidate.query != *query
            || candidate.consumed
            || candidate.expires <= now
            || peer.expires_at() <= now
            || peer.root() != query.account_anchor
            || peer.node() != query.target_node
            || candidate.authenticated_node_key.as_deref().is_some_and(|key| key != peer.node_key())
            || candidate.snapshot_hash.as_deref().is_some_and(|hash| hash != peer.snapshot_hash())
        {
            return Err(refuse(Reason::ForeignSnapshotInvalid));
        }
        candidate.authenticated_node_key = Some(peer.node_key().into());
        candidate.snapshot_hash = Some(peer.snapshot_hash().into());
        table.insert(key.as_str(), encoded(&candidate)?.as_slice()).map_err(storage)?;
        drop(table);
        tx.commit()?;
        Ok(())
    }

    /// Commit a primary-approved policy/admission/start/reply operation at the home writer.
    /// Local success for composite operations means the exact sealed submission is spooled.
    /// # Errors
    /// Refuses current-authority/CAS conflicts, changed retries and bounded-storage exhaustion.
    pub fn reach_owner_commit(
        &self,
        owner: ReachOwner<'_>,
        operation: &Operation,
        now: u64,
    ) -> Result<OperationResult> {
        let _home_gate = self.acquire_home_operation(owner.recipient_root)?;
        let (id, expires) = match operation {
            Operation::Policy { update } => (&update.body.operation_id, update.body.expires_at),
            Operation::Admission { update, .. }
            | Operation::Start { update, .. }
            | Operation::Reply { update, .. } => {
                (&update.body.operation_id, update.body.expires_at)
            }
            _ => return Err(refuse(Reason::ForeignInvalidFrame)),
        };
        let hash = match operation {
            Operation::Policy { update } => custody::framed_hash(OPERATION_HASH_DOMAIN, update)?,
            Operation::Admission { update, .. } => {
                custody::framed_hash(OPERATION_HASH_DOMAIN, update)?
            }
            _ => custody::framed_hash(OPERATION_HASH_DOMAIN, operation)?,
        };
        let operation_key = key(owner.recipient_root, id)?;
        let tx = self.begin_write()?;
        let now = clock(&tx, now)?;
        let current = authority(&tx, owner.recipient_root, now)?;
        let local_home = home(&tx, owner.recipient_root)?;
        let home_hash = ramflux_protocol::home_migration::record_hash(&local_home.record)?;
        // Even a duplicate must come from the current management session, not a browser courier.
        current.authorize_primary_management(owner.actor, "contact_consent", now)?;
        if let Some(previous) = tx
            .open_table(OPERATIONS)
            .map_err(storage)?
            .get(operation_key.as_str())
            .map_err(storage)?
            .map(|v| row::<OperationRow>(v.value()))
            .transpose()?
        {
            if previous.hash != hash {
                return Err(refuse(Reason::IdempotencyConflict));
            }
            return Ok(previous.result);
        }
        // Outbox links retain exact retry identity after short-lived command rows are collected.
        if let Some(previous) = tx
            .open_table(OUTBOX)
            .map_err(storage)?
            .get(operation_key.as_str())
            .map_err(storage)?
            .map(|v| row::<ReachOutbox>(v.value()))
            .transpose()?
        {
            if previous.operation_hash != hash {
                return Err(refuse(Reason::IdempotencyConflict));
            }
            return Err(refuse(Reason::ForeignUnavailable));
        }
        let mut state = load(&tx, owner.recipient_root)?;
        let result = apply_owner_command(
            &tx,
            &mut state,
            operation,
            OwnerCommand { owner, current: &current, home_hash: &home_hash, now },
        )?;
        retain_operation(&tx, &operation_key, expires, &hash, &result, now)?;
        save(&tx, owner.recipient_root, &state)?;
        tx.commit()?;
        Ok(result)
    }
}

fn retain_operation(
    tx: &redb::WriteTransaction,
    operation_key: &str,
    expires: u64,
    hash: &str,
    result: &OperationResult,
    now: u64,
) -> Result<()> {
    let mut operations = tx.open_table(OPERATIONS).map_err(storage)?;
    // Bounded retention; no live operation row is evicted to make room.
    let collected = operations
        .iter()
        .map_err(storage)?
        .take(65_536)
        .map(|e| {
            let (k, v) = e.map_err(storage)?;
            Ok((k.value().to_owned(), row::<OperationRow>(v.value())?.expires_at))
        })
        .collect::<Result<Vec<_>>>()?;
    for (key, until) in collected {
        if until <= now
            && tx.open_table(OUTBOX).map_err(storage)?.get(key.as_str()).map_err(storage)?.is_none()
        {
            operations.remove(key.as_str()).map_err(storage)?;
        }
    }
    if operations.len().map_err(storage)? >= 65_536 {
        return Err(refuse(Reason::ForeignCapacity));
    }
    let retained = expires.checked_add(60).ok_or_else(|| refuse(Reason::ForeignCapacity))?;
    operations
        .insert(
            operation_key,
            encoded(&OperationRow {
                hash: hash.into(),
                expires_at: retained,
                result: result.clone(),
            })?
            .as_slice(),
        )
        .map_err(storage)?;
    drop(operations);
    Ok(())
}

#[derive(Clone, Copy)]
struct OwnerCommand<'a> {
    owner: ReachOwner<'a>,
    current: &'a ramflux_crypto::custody::VerifiedRecord,
    home_hash: &'a str,
    now: u64,
}
fn apply_owner_command(
    tx: &redb::WriteTransaction,
    state: &mut AccountReach,
    operation: &Operation,
    context: OwnerCommand<'_>,
) -> Result<OperationResult> {
    let OwnerCommand { owner, current, home_hash, now } = context;
    let result = match operation {
        Operation::Policy { update } => {
            ramflux_crypto::contact_reach::verify_policy(
                update,
                current,
                home_hash,
                owner.actor,
                now,
            )?;
            state.policy(update.clone())?;
            OperationResult::Policy { revision: state.policy_revision(), outcome: Applied::Applied }
        }
        Operation::Admission { update, peer_evidence, notice } => {
            ramflux_crypto::contact_reach::verify_admission(
                update,
                current,
                home_hash,
                owner.actor,
                now,
            )?;
            check_peer(
                tx,
                owner.recipient_root,
                update,
                peer_evidence.as_deref(),
                notice.as_deref(),
                now,
            )?;
            check_allow(state, update, peer_evidence.as_deref(), now)?;
            let conversation = match &update.body.subject {
                Subject::Conversation { conversation_id, .. } => Some(conversation_id.clone()),
                Subject::Friendship { root } => Some(
                    ramflux_protocol::message::dm_scope::derive(owner.recipient_root, root)
                        .map_err(|_| refuse(Reason::ReachRouteInvalid))?,
                ),
                _ => None,
            };
            denials::retire_node_grants(tx, state, owner.recipient_root, update)?;
            state.admission(update.clone(), conversation.as_deref(), now)?;
            super::ingress::erase_denied(tx, owner.recipient_root, update)?;
            OperationResult::Admission {
                revision: state.admission_revision,
                outcome: Applied::Applied,
            }
        }
        Operation::Start { .. } | Operation::Reply { .. } => {
            apply_conversation(tx, state, operation, context)?
        }
        _ => return Err(refuse(Reason::ForeignInvalidFrame)),
    };
    Ok(result)
}

fn apply_conversation(
    tx: &redb::WriteTransaction,
    state: &mut AccountReach,
    operation: &Operation,
    context: OwnerCommand<'_>,
) -> Result<OperationResult> {
    let OwnerCommand { owner, current, home_hash, now } = context;
    let (Operation::Start { update, peer_evidence, notice, target_node_id, submission }
    | Operation::Reply { update, peer_evidence, notice, target_node_id, submission }) = operation
    else {
        return Err(refuse(Reason::ForeignInvalidFrame));
    };
    let result = {
        ramflux_crypto::contact_reach::verify_admission(
            update,
            current,
            home_hash,
            owner.actor,
            now,
        )?;
        check_peer(tx, owner.recipient_root, update, Some(peer_evidence), Some(notice), now)?;
        let Subject::Conversation { root, conversation_id } = &update.body.subject else {
            return Err(refuse(Reason::ForeignInvalidFrame));
        };
        if update.body.decision != Decision::Allow
            || &submission.route.body.recipient_root != root
            || submission.route.body.source.account_anchor != owner.recipient_root
            || &submission.route.body.conversation_id != conversation_id
            || target_node_id != &peer_evidence.snapshot.body.source_node
        {
            return Err(refuse(Reason::ReachRouteInvalid));
        }
        ramflux_crypto::contact_reach::verify_submission(submission, current, now)?;
        check_allow(state, update, Some(peer_evidence), now)?;
        let id = &update.body.operation_id;
        let hash = custody::framed_hash(OPERATION_HASH_DOMAIN, operation)?;
        let operation_key = key(owner.recipient_root, id)?;
        let outbox = ReachOutbox {
            recipient_root: owner.recipient_root.into(),
            operation_id: id.clone(),
            operation_hash: hash.clone(),
            target_node_id: target_node_id.clone(),
            submission: *submission.clone(),
            retain_until: submission.route.body.expires_at,
        };
        let bytes = encoded(&outbox)?;
        let mut outboxes = tx.open_table(OUTBOX).map_err(storage)?;
        if outboxes.len().map_err(storage)? >= 65_536 || bytes.len() > MAX_FRAME_BYTES {
            return Err(refuse(Reason::ForeignCapacity));
        }
        outboxes.insert(operation_key.as_str(), bytes.as_slice()).map_err(storage)?;
        drop(outboxes);
        state.admission(update.clone(), Some(conversation_id), now)?;
        let submission_result = Box::new(OperationResult::Submit {
            envelope_id: submission.envelope.envelope_id.clone(),
            outcome: SubmitOutcome::Spooled,
            reason: None,
        });
        if matches!(operation, Operation::Start { .. }) {
            OperationResult::Start {
                revision: state.admission_revision,
                outcome: Applied::Applied,
                submission: submission_result,
            }
        } else {
            OperationResult::Reply {
                revision: state.admission_revision,
                outcome: Applied::Applied,
                submission: submission_result,
            }
        }
    };
    Ok(result)
}

/// Compare the independently verified checkpoint with the latest home writer state.
fn check_home_base(
    peer: &ramflux_crypto::contact_reach::VerifiedPeer,
    previous: &AdoptedPeer,
) -> Result<()> {
    let old = &previous.home.record;
    let new = &peer.home().evidence().record;
    let hash = ramflux_protocol::home_migration::record_hash(old)?;
    if new.epoch() < old.epoch() {
        return Err(refuse(Reason::HomeRollback));
    }
    if new.epoch() == old.epoch() {
        if peer.home().hash() != hash {
            return Err(refuse(Reason::HomeFork));
        }
    } else if peer.verified_base_hash() != Some(hash.as_str()) {
        return Err(refuse(Reason::HomeRollback));
    }
    Ok(())
}
pub(super) fn adopt_ingress_peer(
    tx: &redb::WriteTransaction,
    recipient: &str,
    peer: &ramflux_crypto::contact_reach::VerifiedPeer,
) -> Result<()> {
    let trust_key = key(recipient, peer.root())?;
    let previous = tx
        .open_table(TRUST)
        .map_err(storage)?
        .get(trust_key.as_str())
        .map_err(storage)?
        .map(|v| row::<AdoptedPeer>(v.value()))
        .transpose()?;
    adopt_peer(tx, recipient, &trust_key, peer, previous)
}

fn adopt_peer(
    tx: &redb::WriteTransaction,
    recipient: &str,
    key: &str,
    peer: &ramflux_crypto::contact_reach::VerifiedPeer,
    previous: Option<AdoptedPeer>,
) -> Result<()> {
    if let Some(previous) = &previous {
        check_home_base(peer, previous)?;
    }
    let mut state = previous.unwrap_or_else(|| AdoptedPeer {
        home: peer.home().evidence().clone(),
        authority_pins: ramflux_crypto::custody::AuthorityPins::default(),
        custodian_pins: ramflux_crypto::custody::AuthorityPins::default(),
    });
    state.authority_pins.observe(peer.authority())?;
    state.authority_pins.require_current(peer.authority())?;
    let certificate = &peer.authority().envelope().body.master_certificate.body;
    if certificate.custody_kind == custody::CustodyKind::ExternalHuman {
        let human = peer.authority().management_actor_authority(&certificate.primary_device_ref)?;
        state.custodian_pins.observe(human)?;
        state.custodian_pins.require_current(human)?;
    }
    state.home = peer.home().evidence().clone();
    let bytes = encoded(&state)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(refuse(Reason::ForeignCapacity));
    }
    let prefix = format!("[{},", serde_json::to_string(recipient).map_err(storage)?);
    let mut table = tx.open_table(TRUST).map_err(storage)?;
    let mut count = 1_usize;
    let mut total = bytes.len();
    for entry in table.range(prefix.as_str()..).map_err(storage)?.take(1025) {
        let (old, value) = entry.map_err(storage)?;
        if !old.value().starts_with(&prefix) {
            break;
        }
        if old.value() == key {
            continue;
        }
        count += 1;
        total = total
            .checked_add(value.value().len())
            .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
    }
    if count > 1024 || total > 64 * 1024 * 1024 {
        return Err(refuse(Reason::ForeignCapacity));
    }
    table.insert(key, bytes.as_slice()).map_err(storage)?;
    Ok(())
}

fn check_allow(
    state: &AccountReach,
    update: &Signed<Admission>,
    reply: Option<&PeerReply>,
    now: u64,
) -> Result<()> {
    if update.body.decision != Decision::Allow {
        return Ok(());
    }
    let root = update.body.subject.root().ok_or_else(|| refuse(Reason::ForeignInvalidFrame))?;
    let reply = reply.ok_or_else(|| refuse(Reason::ForeignSnapshotInvalid))?;
    state.check_denials(root, &reply.snapshot.body.source_node, now)?;
    if state.blocks.contains_key(&update.body.subject.key()?) {
        return Err(refuse(Reason::ForeignReadRefused));
    }
    Ok(())
}

fn check_peer(
    tx: &redb::WriteTransaction,
    recipient: &str,
    update: &Signed<Admission>,
    reply: Option<&PeerReply>,
    notice: Option<&Notice>,
    now: u64,
) -> Result<()> {
    if update.body.decision != Decision::Allow {
        if reply.is_some() || notice.is_some() {
            return Err(refuse(Reason::ForeignInvalidFrame));
        }
        return Ok(());
    }
    let reply = reply.ok_or_else(|| refuse(Reason::ContactConfirmationRequired))?;
    let notice = notice.ok_or_else(|| refuse(Reason::ContactConfirmationRequired))?;
    let root = update.body.subject.root().ok_or_else(|| refuse(Reason::ForeignInvalidFrame))?;
    let trust_key = key(recipient, root)?;
    let saved = tx
        .open_table(TRUST)
        .map_err(storage)?
        .get(trust_key.as_str())
        .map_err(storage)?
        .map(|v| row::<AdoptedPeer>(v.value()))
        .transpose()?;
    let b = &reply.snapshot.body;
    let query_key = key(recipient, &b.request_nonce)?;
    let mut candidate: CandidateQuery = tx
        .open_table(QUERIES)
        .map_err(storage)?
        .get(query_key.as_str())
        .map_err(storage)?
        .map(|v| row(v.value()))
        .transpose()?
        .ok_or_else(|| refuse(Reason::ForeignSnapshotInvalid))?;
    if candidate.expires <= now || candidate.consumed || candidate.query.account_anchor != root {
        return Err(refuse(Reason::ForeignSnapshotExpired));
    }
    let node_key = candidate
        .authenticated_node_key
        .as_deref()
        .ok_or_else(|| refuse(Reason::ForeignSnapshotInvalid))?;
    if candidate.snapshot_hash.as_deref() != Some(custody::object_hash(&reply.snapshot)?.as_str()) {
        return Err(refuse(Reason::ForeignSnapshotInvalid));
    }
    let peer = ramflux_crypto::contact_reach::verify_peer_reply(
        reply,
        &candidate.query,
        node_key,
        saved.as_ref().map(|state| &state.home),
        now,
    )?;
    ramflux_crypto::contact_reach::verify_notice(notice, recipient, &peer)?;
    if peer.root() != root
        || update.body.notice_hash.as_deref()
            != Some(custody::framed_hash(NOTICE_DOMAIN, notice)?.as_str())
        || update.body.evidence_hash.as_deref() != Some(peer.snapshot_hash())
    {
        return Err(refuse(Reason::ContactConfirmationRequired));
    }
    adopt_peer(tx, recipient, &trust_key, &peer, saved)?;
    candidate.consumed = true;
    tx.open_table(QUERIES)
        .map_err(storage)?
        .insert(query_key.as_str(), encoded(&candidate)?.as_slice())
        .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests;

mod denials;

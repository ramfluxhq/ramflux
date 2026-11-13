// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home-writer CAS and exact-operation/outbox idempotency in one durable transaction.
use super::{AccountReach, Result, refuse, storage};
use crate::{RouterRedbStore, custody_authority::CustodyAccountState};
use ramflux_protocol::{
    contact_reach::*,
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
const TRUST: TableDefinition<&str, &[u8]> = TableDefinition::new("contact_reach_peer_home_v1");

/// Session-derived owner context. Services derive both fields from authenticated state.
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
        .map(|v| v.unwrap_or_default())
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
        let result = match operation {
            Operation::Policy { update } => {
                ramflux_crypto::contact_reach::verify_policy(
                    update,
                    &current,
                    &home_hash,
                    owner.actor,
                    now,
                )?;
                state.policy(update.clone())?;
                OperationResult::Policy {
                    revision: state.policy_revision(),
                    outcome: Applied::Applied,
                }
            }
            Operation::Admission { update, peer_evidence, notice } => {
                ramflux_crypto::contact_reach::verify_admission(
                    update,
                    &current,
                    &home_hash,
                    owner.actor,
                    now,
                )?;
                check_peer(
                    &tx,
                    owner.recipient_root,
                    update,
                    peer_evidence.as_deref(),
                    notice.as_deref(),
                    now,
                )?;
                let conversation = match &update.body.subject {
                    Subject::Conversation { conversation_id, .. } => Some(conversation_id.clone()),
                    _ => None,
                };
                state.admission(update.clone(), conversation.as_deref(), now)?;
                super::ingress::erase_denied(&tx, owner.recipient_root, update)?;
                OperationResult::Admission {
                    revision: state.admission_revision,
                    outcome: Applied::Applied,
                }
            }
            Operation::Start { update, peer_evidence, notice, target_node_id, submission }
            | Operation::Reply { update, peer_evidence, notice, target_node_id, submission } => {
                ramflux_crypto::contact_reach::verify_admission(
                    update,
                    &current,
                    &home_hash,
                    owner.actor,
                    now,
                )?;
                check_peer(
                    &tx,
                    owner.recipient_root,
                    update,
                    Some(peer_evidence),
                    Some(notice),
                    now,
                )?;
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
                ramflux_crypto::contact_reach::verify_submission(submission, &current, now)?;
                state.check_denials(root, target_node_id, now)?;
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
            }
            _ => return Err(refuse(Reason::ForeignInvalidFrame)),
        };
        let mut operations = tx.open_table(OPERATIONS).map_err(storage)?;
        // Bounded retention; no live operation row is evicted to make room.
        let expired = operations
            .iter()
            .map_err(storage)?
            .take(65_536)
            .map(|e| {
                let (k, v) = e.map_err(storage)?;
                Ok((k.value().to_owned(), row::<OperationRow>(v.value())?.expires_at))
            })
            .collect::<Result<Vec<_>>>()?;
        for (key, until) in expired {
            if until <= now
                && tx
                    .open_table(OUTBOX)
                    .map_err(storage)?
                    .get(key.as_str())
                    .map_err(storage)?
                    .is_none()
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
                operation_key.as_str(),
                encoded(&OperationRow { hash, expires_at: retained, result: result.clone() })?
                    .as_slice(),
            )
            .map_err(storage)?;
        drop(operations);
        save(&tx, owner.recipient_root, &state)?;
        tx.commit()?;
        Ok(result)
    }
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
        .map(|v| row::<ramflux_protocol::home_migration::RecordEvidence>(v.value()))
        .transpose()?;
    let b = &reply.snapshot.body;
    let query = Query {
        version: 1,
        source_node: b.target_node.clone(),
        target_node: b.source_node.clone(),
        account_anchor: root.into(),
        card_hash: None,
        nonce: b.request_nonce.clone(),
        base: None,
        device_ref: None,
    };
    // The original query hash may include a card/base; use that exact request at service ingress.
    // Owner evidence with another query is rejected rather than rewriting its signed hash.
    let node_key = reply.payload.home.home.record.home().1;
    let peer = ramflux_crypto::contact_reach::verify_peer_reply(
        reply,
        &query,
        node_key,
        saved.as_ref(),
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
    tx.open_table(TRUST)
        .map_err(storage)?
        .insert(trust_key.as_str(), encoded(peer.home().evidence())?.as_slice())
        .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests;

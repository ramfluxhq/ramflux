// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic quota/dedup admission precedes all durable payload and foreign-trust publication.
mod maintenance;
use super::{
    ReachClass, Result, refuse, storage,
    store::{self, encoded, row},
};
use crate::{MigrationNode, RouterRedbStore};
use ramflux_protocol::{
    contact_reach::{
        Admission, ChallengeRequest, CostPurpose, Decision, DeliveryReach, ENVELOPE_HASH_DOMAIN,
        OperationResult, Reason, StrangerEntry, Subject, Submission,
    },
    custody::{self, DeviceRef},
};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const PENDING: TableDefinition<u64, &[u8]> = TableDefinition::new("contact_reach_pending_v1");
const DEDUP: TableDefinition<&str, &[u8]> = TableDefinition::new("contact_reach_dedup_v1");
const COUNTERS: TableDefinition<&str, &[u8]> = TableDefinition::new("contact_reach_counters_v1");
const SEQUENCE: TableDefinition<&str, u64> = TableDefinition::new("contact_reach_sequence_v1");
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachPending {
    pub entry: StrangerEntry,
    pub recipient_root: String,
    pub class: ReachClass,
    pub bytes: u64,
    pub target: DeviceRef,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReachIngress {
    pub seq: u64,
    pub class: ReachClass,
    pub duplicate: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dedup {
    hash: String,
    seq: u64,
    class: ReachClass,
    until: u64,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Counter {
    entries: u64,
    bytes: u64,
    until: u64,
}

fn charge(
    tx: &redb::WriteTransaction,
    key: &str,
    usage: (u64, u64),
    capacity: (u64, u64),
    until: u64,
) -> Result<()> {
    let (entries, bytes) = usage;
    let (cap, byte_cap) = capacity;
    let mut table = tx.open_table(COUNTERS).map_err(storage)?;
    let mut value: Counter =
        table.get(key).map_err(storage)?.map(|v| row(v.value())).transpose()?.unwrap_or_default();
    value.entries = value
        .entries
        .checked_add(entries)
        .filter(|n| *n <= cap)
        .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
    value.bytes = value
        .bytes
        .checked_add(bytes)
        .filter(|n| *n <= byte_cap)
        .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
    value.until = value.until.max(until);
    table.insert(key, encoded(&value)?.as_slice()).map_err(storage)?;
    drop(table);
    if until > 0 {
        maintenance::remember_counter(tx, key, until)?;
    }
    Ok(())
}
fn keys(p: &ReachPending) -> Result<Vec<(String, u64, u64)>> {
    let e = &p.entry;
    let r = &p.recipient_root;
    let json = |v: serde_json::Value| serde_json::to_string(&v).map_err(storage);
    if p.class == ReachClass::Unsolicited {
        Ok(vec![
            ("unsolicited-global".into(), 4096, 128 * 1024 * 1024),
            (json(serde_json::json!(["unsolicited-recipient", r]))?, 100, 4 * 1024 * 1024),
            (json(serde_json::json!(["unsolicited-node", r, e.peer_node]))?, 32, 2 * 1024 * 1024),
            (json(serde_json::json!(["unsolicited-root", r, e.source_root]))?, 4, 1024 * 1024),
        ])
    } else {
        let mut keys = vec![
            ("accepted-global".into(), 65_536, 1024 * 1024 * 1024),
            (
                json(serde_json::json!(["accepted-conversation", r, e.conversation_id]))?,
                256,
                16 * 1024 * 1024,
            ),
        ];
        if p.class == ReachClass::Replied {
            keys.push(("replied-global".into(), 32_768, 512 * 1024 * 1024));
        }
        Ok(keys)
    }
}
fn rates(tx: &redb::WriteTransaction, p: &ReachPending, now: u64) -> Result<()> {
    let e = &p.entry;
    let r = &p.recipient_root;
    let window = if p.class == ReachClass::Unsolicited { 3600 } else { 60 };
    let index = now / window;
    let retain = index
        .checked_add(2)
        .and_then(|n| n.checked_mul(window))
        .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
    let caps = if p.class == ReachClass::Unsolicited { [20, 10, 4] } else { [1200, 600, 120] };
    for (key, cap) in [
        (serde_json::json!(["rate-recipient", window, index, r]), caps[0]),
        (serde_json::json!(["rate-node", window, index, r, e.peer_node]), caps[1]),
        (serde_json::json!(["rate-root", window, index, r, e.source_root]), caps[2]),
    ] {
        let key = serde_json::to_string(&key).map_err(storage)?;
        charge(tx, &key, (1, 0), (cap, 0), retain)?;
    }
    Ok(())
}
fn dedup_key(root: &str, source: &str, id: &str, target: &str) -> Result<String> {
    serde_json::to_string(&(root, source, id, target)).map_err(storage)
}
fn remove_payload(tx: &redb::WriteTransaction, seq: u64) -> Result<()> {
    let mut table = tx.open_table(PENDING).map_err(storage)?;
    let value =
        table.get(seq).map_err(storage)?.map(|v| row::<ReachPending>(v.value())).transpose()?;
    let Some(p) = value else { return Ok(()) };
    table.remove(seq).map_err(storage)?;
    drop(table);
    let mut counters = tx.open_table(COUNTERS).map_err(storage)?;
    for (key, _, _) in keys(&p)? {
        let mut count: Counter = counters
            .get(key.as_str())
            .map_err(storage)?
            .map(|v| row(v.value()))
            .transpose()?
            .ok_or_else(|| storage("missing pending charge"))?;
        count.entries =
            count.entries.checked_sub(1).ok_or_else(|| storage("pending entry underflow"))?;
        count.bytes =
            count.bytes.checked_sub(p.bytes).ok_or_else(|| storage("pending byte underflow"))?;
        counters.insert(key.as_str(), encoded(&count)?.as_slice()).map_err(storage)?;
    }
    Ok(())
}

fn stage(tx: &redb::WriteTransaction, pending: &ReachPending, key: &str, hash: &str) -> Result<()> {
    let ReachPending { class, bytes, .. } = *pending;
    let seq = pending.entry.seq;
    let retain_until = pending.entry.retain_until;
    let now = pending.entry.received_at;
    for (key, cap, byte_cap) in keys(pending)? {
        charge(tx, &key, (1, bytes), (cap, byte_cap), 0)?;
    }
    rates(tx, pending, now)?;
    let (metadata, metadata_cap) = maintenance::metadata(class);
    charge(
        tx,
        metadata,
        (
            1,
            u64::try_from(
                key.len()
                    + encoded(&Dedup { hash: hash.into(), seq, class, until: retain_until })?.len(),
            )
            .map_err(storage)?,
        ),
        (metadata_cap, 32 * 1024 * 1024),
        0,
    )?;
    tx.open_table(PENDING)
        .map_err(storage)?
        .insert(seq, encoded(pending)?.as_slice())
        .map_err(storage)?;
    tx.open_table(DEDUP)
        .map_err(storage)?
        .insert(
            key,
            encoded(&Dedup { hash: hash.into(), seq, class, until: retain_until })?.as_slice(),
        )
        .map_err(storage)?;
    maintenance::remember_dedup(tx, key, retain_until)?;
    Ok(())
}

fn verify_source(
    peer: &ramflux_crypto::contact_reach::VerifiedPeer,
    submission: &Submission,
    now: u64,
) -> Result<()> {
    let envelope = &submission.envelope;
    let route = &submission.route.body;
    ramflux_protocol::ephemeral::require_durable(envelope).map_err(crate::NodeCoreError::from)?;
    let (evidence, source) = crate::DeviceAuthKeyResponse::forwarded_envelope_source(envelope)?;
    let evidence = evidence.custody_authority.ok_or_else(|| refuse(Reason::CustodyRefused))?;
    let verified = ramflux_crypto::custody::verify_publication(&evidence, now)?;
    if peer.root() != route.source.account_anchor
        || peer.expires_at() <= now
        || verified.envelope().body.master_certificate
            != peer.authority().envelope().body.master_certificate
    {
        return Err(refuse(Reason::CustodyRefused));
    }
    let current_branch = peer.authority().authorize(&route.source, "message", now)?;
    let historical_branch = verified.authorize(&route.source, "message", route.issued_at)?;
    if current_branch.branch_signing_public_key != historical_branch.branch_signing_public_key
        || current_branch.agreement_identity_public_key
            != historical_branch.agreement_identity_public_key
    {
        return Err(refuse(Reason::CustodyRefused));
    }
    ramflux_crypto::contact_reach::verify_submission(submission, &verified, now)?;
    if source.root_commitment() != route.source.account_anchor {
        return Err(refuse(Reason::ReachRouteInvalid));
    }
    Ok(())
}

impl RouterRedbStore {
    /// Authenticate a complete sealed submission and reserve its receiving-home compartment.
    /// The sealed source proof comes from verified home evidence, never a sender body assertion.
    /// # Errors
    /// Refuses stale authority, wrong target, denial state, invalid work and quota exhaustion.
    pub fn reach_admit(
        &self,
        node: &MigrationNode,
        peer: &ramflux_crypto::contact_reach::VerifiedPeer,
        submission: &Submission,
        now: u64,
    ) -> Result<ReachIngress> {
        let route = &submission.route.body;
        let source_home = peer.node();
        let envelope = &submission.envelope;
        let _home_gate = self.acquire_submission(&envelope.target_delivery_id)?;
        verify_source(peer, submission, now)?;
        let (root, device) =
            ramflux_protocol::parse_qualified_device_id(&envelope.target_delivery_id)?
                .ok_or_else(|| refuse(Reason::ReachRouteInvalid))?;
        if root != route.recipient_root {
            return Err(refuse(Reason::ReachRouteInvalid));
        }
        let tx = self.begin_write()?;
        let now = store::clock(&tx, now)?;
        maintenance::clean(&tx, now)?;
        if peer.expires_at() <= now {
            return Err(refuse(Reason::ForeignSnapshotExpired));
        }
        let recipient = store::authority(&tx, &root, now)?;
        let target = recipient
            .envelope()
            .body
            .devices
            .iter()
            .find(|d| d.device_id == device)
            .ok_or_else(|| refuse(Reason::ReachRouteInvalid))?;
        let target = DeviceRef {
            account_anchor: root.clone(),
            device_id: device,
            device_epoch: target.device_epoch,
        };
        recipient.authorize(&target, "message", now)?;
        if recipient.envelope().body.devices.len() > 32 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        let local_home = store::home(&tx, &root)?;
        if local_home.record.home() != (node.node_id(), node.public_key()) {
            return Err(refuse(Reason::HomeRollback));
        }
        let state = store::load(&tx, &root)?;
        let (class, placement) = state.classify(route, source_home, now)?;
        let key = dedup_key(
            &root,
            &route.source.account_anchor,
            &envelope.envelope_id,
            &envelope.target_delivery_id,
        )?;
        let hash = custody::framed_hash(ENVELOPE_HASH_DOMAIN, envelope)?;
        let dedup = tx.open_table(DEDUP).map_err(storage)?;
        if let Some(old) = dedup
            .get(key.as_str())
            .map_err(storage)?
            .map(|v| row::<Dedup>(v.value()))
            .transpose()?
        {
            if old.hash != hash {
                return Err(refuse(Reason::IdempotencyConflict));
            }
            return Ok(ReachIngress { seq: old.seq, class: old.class, duplicate: true });
        }
        let retain_until = if class == ReachClass::Unsolicited {
            route
                .expires_at
                .min(now.checked_add(604_800).ok_or_else(|| refuse(Reason::ForeignCapacity))?)
        } else {
            route.expires_at
        };
        if retain_until <= now {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        let bytes = u64::try_from(encoded(envelope)?.len()).map_err(storage)?;
        if class == ReachClass::Unsolicited && bytes > 256 * 1024 {
            return Err(refuse(Reason::ForeignPayloadTooLarge));
        }
        drop(dedup);
        if class == ReachClass::Unsolicited {
            let cost = submission.cost.as_ref().ok_or_else(|| refuse(Reason::CostRequired))?;
            let expected = ChallengeRequest {
                purpose: CostPurpose::Stranger,
                source_root: route.source.account_anchor.clone(),
                recipient_root: Some(root.clone()),
                operation_hash: hash.clone(),
            };
            ramflux_crypto::contact_reach::verify_cost(
                cost,
                &expected,
                node.node_id(),
                node.public_key(),
                now,
            )?;
            super::cost::consume(&tx, cost, &hash, now)?;
        }
        let mut sequence = tx.open_table(SEQUENCE).map_err(storage)?;
        let old = sequence.get("next").map_err(storage)?.map_or(0, |v| v.value());
        let seq = old
            .checked_add(1)
            .filter(|n| *n <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        sequence.insert("next", seq).map_err(storage)?;
        drop(sequence);
        let pending = ReachPending {
            recipient_root: root,
            class,
            bytes,
            target,
            entry: StrangerEntry {
                seq,
                peer_node: source_home.into(),
                source_root: route.source.account_anchor.clone(),
                received_at: now,
                retain_until,
                envelope: envelope.clone(),
                reach: DeliveryReach {
                    route: submission.route.clone(),
                    cost: submission.cost.clone(),
                },
                conversation_id: route.conversation_id.clone(),
                placement,
                policy_revision: state.policy_revision(),
            },
        };
        stage(&tx, &pending, &key, &hash)?;
        tx.commit()?;
        Ok(ReachIngress { seq, class, duplicate: false })
    }

    /// Atomically ACK transferred bounded payloads, then return an owner-scoped page.
    /// An ACK is neither a read receipt nor friendship acceptance.
    /// # Errors
    /// Refuses wrong devices, malformed cursors and excessive page or ACK budgets.
    pub fn reach_pending_page(
        &self,
        owner: super::ReachOwner<'_>,
        after: u64,
        limit: u64,
        acks: &[u64],
        now: u64,
    ) -> Result<OperationResult> {
        if !(1..=16).contains(&limit)
            || acks.len() > 16
            || acks.contains(&0)
            || acks.iter().collect::<std::collections::BTreeSet<_>>().len() != acks.len()
        {
            return Err(refuse(Reason::ForeignInvalidFrame));
        }
        let tx = self.begin_write()?;
        let now = store::clock(&tx, now)?;
        maintenance::clean(&tx, now)?;
        let authority = store::authority(&tx, owner.recipient_root, now)?;
        authority.authorize(owner.actor, "message", now)?;
        for &seq in acks {
            let p = tx
                .open_table(PENDING)
                .map_err(storage)?
                .get(seq)
                .map_err(storage)?
                .map(|v| row::<ReachPending>(v.value()))
                .transpose()?;
            if let Some(p) = p {
                if p.recipient_root != owner.recipient_root || &p.target != owner.actor {
                    return Err(refuse(Reason::ForeignReadRefused));
                }
                remove_payload(&tx, seq)?;
            }
        }
        let table = tx.open_table(PENDING).map_err(storage)?;
        let mut entries = Vec::new();
        let mut bytes = 0_usize;
        let mut expired = Vec::new();
        let state = store::load(&tx, owner.recipient_root)?;
        for item in table.range(after..).map_err(storage)?.take(65_536) {
            let (seq, raw) = item.map_err(storage)?;
            if seq.value() <= after {
                continue;
            }
            let p: ReachPending = row(raw.value())?;
            if p.recipient_root != owner.recipient_root || &p.target != owner.actor {
                continue;
            }
            if p.entry.retain_until <= now
                || state.check_denials(&p.entry.source_root, &p.entry.peer_node, now).is_err()
            {
                expired.push(seq.value());
                continue;
            }
            let length = encoded(&p.entry)?.len();
            if entries.len() >= usize::try_from(limit).map_err(storage)?
                || bytes + length > 2 * 1024 * 1024
            {
                break;
            }
            bytes += length;
            entries.push(p.entry);
        }
        drop(table);
        for seq in expired {
            remove_payload(&tx, seq)?;
        }
        let next_seq = entries.last().map_or(after, |e| e.seq);
        tx.commit()?;
        Ok(OperationResult::Strangers { entries, next_seq })
    }
}

pub(super) fn erase_denied(
    tx: &redb::WriteTransaction,
    recipient: &str,
    update: &custody::Envelope<Admission>,
) -> Result<()> {
    if !matches!(update.body.decision, Decision::Block | Decision::Decline) {
        return Ok(());
    }
    let table = tx.open_table(PENDING).map_err(storage)?;
    let mut removed = Vec::new();
    for value in table.iter().map_err(storage)?.take(65_536) {
        let (seq, bytes) = value.map_err(storage)?;
        let pending: ReachPending = row(bytes.value())?;
        if pending.recipient_root != recipient {
            continue;
        }
        let denied = match &update.body.subject {
            Subject::Friendship { root } => root == &pending.entry.source_root,
            Subject::Node { node_id } => node_id == &pending.entry.peer_node,
            _ => false,
        };
        if denied {
            removed.push(seq.value());
        }
    }
    drop(table);
    for seq in removed {
        remove_payload(tx, seq)?;
    }
    Ok(())
}

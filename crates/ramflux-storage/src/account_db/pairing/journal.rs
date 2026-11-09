// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed pairing row codecs. Nested protocol values reuse [`PairingWire`]; no secret serde.
use super::schema::{
    ADOPTION_ROW_MAX, FLOOR_ROW_MAX, HEAD_ROW_MAX, ID_MAX, LIVE_CAP, LIVE_ROW_MAX, TERMINAL_CAP,
    TERMINAL_ROW_MAX,
};
use crate::{AccountDb, StorageError};
use ramflux_protocol::custody::pairing::native::{Failure, Invitation};
use ramflux_protocol::custody::pairing::{PairingWire, RoleContext, WireError};
use ramflux_protocol::custody::{DeviceRef, Envelope, Publication};
use ramflux_protocol::{
    MAX_SAFE_JSON_INTEGER, canonical_json_bytes, decode_base64url, encode_base64url, parse_i_json,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

const PHASES: [&str; 14] = [
    "invited",
    "commitments",
    "revealed",
    "sas_pending",
    "mutually_confirmed",
    "proposal_pending",
    "prepared",
    "submitted",
    "acknowledged",
    "locally_installed",
    "completed",
    "cancelled",
    "expired",
    "rejected",
];

fn field(name: &'static str) -> StorageError {
    StorageError::PairingField(name)
}

fn require(ok: bool, name: &'static str) -> Result<(), StorageError> {
    if ok { Ok(()) } else { Err(field(name)) }
}

fn map_wire(error: &WireError) -> StorageError {
    match error {
        WireError::Field(name) => field(name),
        WireError::Json => field("json"),
        WireError::Shape => field("shape"),
        WireError::Size => field("size"),
        WireError::NonCanonical => field("noncanonical"),
    }
}

fn b32(value: &str, name: &'static str) -> Result<(), StorageError> {
    require(
        value.len() == 43
            && decode_base64url(value)
                .is_ok_and(|v| v.len() == 32 && encode_base64url(&v) == value),
        name,
    )
}

fn integer(value: u64, name: &'static str) -> Result<(), StorageError> {
    require(value <= MAX_SAFE_JSON_INTEGER, name)
}

fn ident(value: &str, name: &'static str) -> Result<(), StorageError> {
    require(
        !value.is_empty()
            && value.len() <= ID_MAX
            && !value.chars().any(char::is_control)
            && !value.contains(['/', '\\'])
            && value != "."
            && value != "..",
        name,
    )
}

fn optional_ident(value: Option<&str>, name: &'static str) -> Result<(), StorageError> {
    match value {
        None => Ok(()),
        Some(v) => ident(v, name),
    }
}

fn optional_b32(value: Option<&str>, name: &'static str) -> Result<(), StorageError> {
    match value {
        None => Ok(()),
        Some(v) => b32(v, name),
    }
}

fn bounded(bytes: &[u8], max: usize, name: &'static str) -> Result<(), StorageError> {
    require(bytes.len() <= max, name)
}

fn require_ref(value: &DeviceRef) -> Result<(), StorageError> {
    b32(&value.account_anchor, "ref.account_anchor")?;
    require(
        !value.device_id.is_empty()
            && value.device_id.len() <= ID_MAX
            && !value.device_id.chars().any(char::is_control),
        "ref.device_id",
    )?;
    integer(value.device_epoch, "ref.device_epoch")?;
    require(value.device_epoch >= 1, "ref.device_epoch")
}

fn decode_ref(bytes: &[u8], name: &'static str) -> Result<DeviceRef, StorageError> {
    bounded(bytes, 4096, name)?;
    let value: DeviceRef = parse_i_json(bytes).map_err(|_| field(name))?;
    require_ref(&value)?;
    if canonical_json_bytes(&value).map_err(|_| field("json"))? != bytes {
        return Err(field("noncanonical"));
    }
    Ok(value)
}

/// Live ceremony row. Public refs and hashes only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRow {
    pub account_id: String,
    pub operation_id: String,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub local_seq: u64,
    pub generation: u64,
    pub role: String,
    pub descriptor: Vec<u8>,
    pub phase: String,
    pub context: Option<Vec<u8>>,
    pub transcript_hash: Option<String>,
    pub proposal_hash: Option<String>,
    pub transfer_ciphertext_hash: Option<String>,
    pub candidate_id: Option<String>,
    pub branch_reservation: Option<String>,
    pub branch_vault_ref: Option<String>,
    pub primary_vault_ref: Option<String>,
    pub base_record_hash: String,
    pub base_epoch: u64,
    pub expires_at: u64,
    pub result: Option<Vec<u8>>,
}

/// One-row issuer floor retained across backup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloorRow {
    pub account_id: String,
    pub account_anchor: String,
    pub issued_seq: u64,
    pub next_generation: u64,
}

/// In-flight publication head. One per account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRow {
    pub account_id: String,
    pub operation_id: String,
    pub invitation_id: Option<String>,
    pub generation: u64,
    pub kind: String,
    pub base_record_hash: String,
    pub base_epoch: u64,
    pub publisher_ref: Vec<u8>,
    pub candidate: Vec<u8>,
    pub candidate_hash: String,
    pub state: String,
    pub ack: Option<Vec<u8>>,
    pub recipient_ref: Option<Vec<u8>>,
    pub revoked_ref: Option<Vec<u8>>,
    pub created_at: u64,
}

/// Terminal result cache row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalRow {
    pub account_id: String,
    pub operation_id: String,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub local_seq: u64,
    pub generation: u64,
    pub outcome: String,
    pub record_hash: Option<String>,
    pub finished_at: u64,
    pub cleanup: String,
}

/// Durable installed adoption marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdoptionRow {
    pub account_id: String,
    pub operation_id: String,
    pub record_hash: String,
    pub local_ref: Vec<u8>,
    pub local_role: String,
    pub branch_vault_ref: String,
    pub data_vault_ref: String,
    pub primary_vault_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveContext {
    initiator: RoleContext,
    responder: RoleContext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadAck {
    record_hash: String,
    device_set_epoch: u64,
}

impl LiveRow {
    /// Closed live-row rules, including the candidate-state constraint on submitted.
    ///
    /// # Errors
    /// Returns the exact invalid field.
    pub fn validate(&self) -> Result<(), StorageError> {
        self.validate_keys()?;
        self.validate_phase_refs()?;
        decode_descriptor(&self.descriptor)?;
        if let Some(bytes) = &self.context {
            decode_context(bytes)?;
        }
        if let Some(bytes) = &self.result {
            decode_failure(bytes)?;
        }
        require(self.encoded_size() <= LIVE_ROW_MAX, "size")
    }

    fn validate_keys(&self) -> Result<(), StorageError> {
        ident(&self.account_id, "account_id")?;
        b32(&self.operation_id, "operation_id")?;
        b32(&self.invitation_id, "invitation_id")?;
        integer(self.issuer_seq, "issuer_seq")?;
        require(self.issuer_seq >= 1, "issuer_seq")?;
        integer(self.local_seq, "local_seq")?;
        require(self.local_seq >= 1, "local_seq")?;
        integer(self.generation, "generation")?;
        require(self.generation >= 1, "generation")?;
        require(matches!(self.role.as_str(), "initiator" | "responder"), "role")?;
        require(PHASES.contains(&self.phase.as_str()), "phase")?;
        b32(&self.base_record_hash, "base_record_hash")?;
        integer(self.base_epoch, "base_epoch")?;
        integer(self.expires_at, "expires_at")?;
        optional_ident(self.branch_reservation.as_deref(), "branch_reservation")?;
        optional_ident(self.branch_vault_ref.as_deref(), "branch_vault_ref")?;
        optional_ident(self.primary_vault_ref.as_deref(), "primary_vault_ref")?;
        optional_b32(self.transcript_hash.as_deref(), "transcript_hash")?;
        optional_b32(self.proposal_hash.as_deref(), "proposal_hash")?;
        optional_b32(self.transfer_ciphertext_hash.as_deref(), "transfer_ciphertext_hash")?;
        optional_b32(self.candidate_id.as_deref(), "candidate_id")
    }

    fn validate_phase_refs(&self) -> Result<(), StorageError> {
        let early = matches!(self.phase.as_str(), "invited" | "commitments");
        require(early == self.context.is_none(), "context")?;
        require(self.context.is_none() == self.transcript_hash.is_none(), "transcript_hash")?;
        let needs_proposal = matches!(
            self.phase.as_str(),
            "proposal_pending"
                | "prepared"
                | "submitted"
                | "acknowledged"
                | "locally_installed"
                | "completed"
        );
        require(needs_proposal == self.proposal_hash.is_some(), "proposal_hash")?;
        self.validate_candidate_state()
    }

    fn validate_candidate_state(&self) -> Result<(), StorageError> {
        let needs_candidate = matches!(
            self.phase.as_str(),
            "prepared" | "submitted" | "acknowledged" | "locally_installed" | "completed"
        );
        require(needs_candidate == self.candidate_id.is_some(), "candidate_id")?;
        if needs_candidate {
            require(
                self.candidate_id.as_deref() == Some(self.operation_id.as_str()),
                "candidate_id",
            )?;
        }
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut n = self.account_id.len()
            + self.operation_id.len()
            + self.invitation_id.len()
            + self.role.len()
            + self.descriptor.len()
            + self.phase.len()
            + self.base_record_hash.len();
        n += self.context.as_ref().map_or(0, Vec::len);
        n += self.transcript_hash.as_ref().map_or(0, String::len);
        n += self.proposal_hash.as_ref().map_or(0, String::len);
        n += self.transfer_ciphertext_hash.as_ref().map_or(0, String::len);
        n += self.candidate_id.as_ref().map_or(0, String::len);
        n += self.branch_reservation.as_ref().map_or(0, String::len);
        n += self.branch_vault_ref.as_ref().map_or(0, String::len);
        n += self.primary_vault_ref.as_ref().map_or(0, String::len);
        n += self.result.as_ref().map_or(0, Vec::len);
        n
    }
}

impl FloorRow {
    /// # Errors
    /// Returns the exact invalid field.
    pub fn validate(&self) -> Result<(), StorageError> {
        ident(&self.account_id, "account_id")?;
        b32(&self.account_anchor, "account_anchor")?;
        integer(self.issued_seq, "issued_seq")?;
        integer(self.next_generation, "next_generation")?;
        let n = self.account_id.len() + self.account_anchor.len() + 16;
        require(n <= FLOOR_ROW_MAX, "size")
    }
}

impl HeadRow {
    /// # Errors
    /// Returns the exact invalid field.
    pub fn validate(&self) -> Result<(), StorageError> {
        ident(&self.account_id, "account_id")?;
        b32(&self.operation_id, "operation_id")?;
        optional_b32(self.invitation_id.as_deref(), "invitation_id")?;
        integer(self.generation, "generation")?;
        require(self.generation >= 1, "generation")?;
        require(matches!(self.kind.as_str(), "enroll" | "transfer" | "revoke"), "kind")?;
        b32(&self.base_record_hash, "base_record_hash")?;
        integer(self.base_epoch, "base_epoch")?;
        decode_ref(&self.publisher_ref, "publisher_ref")?;
        decode_publication(&self.candidate)?;
        b32(&self.candidate_hash, "candidate_hash")?;
        require(matches!(self.state.as_str(), "prepared" | "submitted" | "acknowledged"), "state")?;
        integer(self.created_at, "created_at")?;
        self.validate_kind_arms()?;
        self.validate_ack()?;
        require(self.row_len() <= HEAD_ROW_MAX, "size")
    }

    fn validate_kind_arms(&self) -> Result<(), StorageError> {
        match self.kind.as_str() {
            "enroll" | "transfer" => {
                require(self.invitation_id.is_some(), "invitation_id")?;
                require(self.recipient_ref.is_some(), "recipient_ref")?;
                require(self.revoked_ref.is_none(), "revoked_ref")?;
                decode_ref(
                    self.recipient_ref.as_ref().ok_or(field("recipient_ref"))?,
                    "recipient_ref",
                )?;
            }
            "revoke" => {
                require(self.invitation_id.is_none(), "invitation_id")?;
                require(self.recipient_ref.is_none(), "recipient_ref")?;
                require(self.revoked_ref.is_some(), "revoked_ref")?;
                decode_ref(self.revoked_ref.as_ref().ok_or(field("revoked_ref"))?, "revoked_ref")?;
            }
            _ => return Err(field("kind")),
        }
        Ok(())
    }

    fn validate_ack(&self) -> Result<(), StorageError> {
        match (self.state.as_str(), &self.ack) {
            ("acknowledged", Some(bytes)) => decode_ack(bytes),
            ("acknowledged", None) | (_, Some(_)) => Err(field("ack")),
            (_, None) => Ok(()),
        }
    }

    fn row_len(&self) -> usize {
        self.account_id.len()
            + self.operation_id.len()
            + self.invitation_id.as_ref().map_or(0, String::len)
            + self.kind.len()
            + self.base_record_hash.len()
            + self.publisher_ref.len()
            + self.candidate.len()
            + self.candidate_hash.len()
            + self.state.len()
            + self.ack.as_ref().map_or(0, Vec::len)
            + self.recipient_ref.as_ref().map_or(0, Vec::len)
            + self.revoked_ref.as_ref().map_or(0, Vec::len)
    }
}

impl TerminalRow {
    /// # Errors
    /// Returns the exact invalid field.
    pub fn validate(&self) -> Result<(), StorageError> {
        ident(&self.account_id, "account_id")?;
        b32(&self.operation_id, "operation_id")?;
        b32(&self.invitation_id, "invitation_id")?;
        integer(self.issuer_seq, "issuer_seq")?;
        require(self.issuer_seq >= 1, "issuer_seq")?;
        integer(self.local_seq, "local_seq")?;
        require(self.local_seq >= 1, "local_seq")?;
        integer(self.generation, "generation")?;
        require(self.generation >= 1, "generation")?;
        require(
            matches!(self.outcome.as_str(), "completed" | "cancelled" | "expired" | "rejected"),
            "outcome",
        )?;
        optional_b32(self.record_hash.as_deref(), "record_hash")?;
        integer(self.finished_at, "finished_at")?;
        require(matches!(self.cleanup.as_str(), "none" | "pending" | "done"), "cleanup")?;
        let n = self.account_id.len()
            + self.operation_id.len()
            + self.invitation_id.len()
            + self.outcome.len()
            + self.record_hash.as_ref().map_or(0, String::len)
            + self.cleanup.len()
            + 32;
        require(n <= TERMINAL_ROW_MAX, "size")
    }
}

impl AdoptionRow {
    /// # Errors
    /// Returns the exact invalid field.
    pub fn validate(&self) -> Result<(), StorageError> {
        ident(&self.account_id, "account_id")?;
        b32(&self.operation_id, "operation_id")?;
        b32(&self.record_hash, "record_hash")?;
        decode_ref(&self.local_ref, "local_ref")?;
        require(matches!(self.local_role.as_str(), "primary" | "secondary"), "local_role")?;
        ident(&self.branch_vault_ref, "branch_vault_ref")?;
        ident(&self.data_vault_ref, "data_vault_ref")?;
        optional_ident(self.primary_vault_ref.as_deref(), "primary_vault_ref")?;
        match self.local_role.as_str() {
            "primary" => require(self.primary_vault_ref.is_some(), "primary_vault_ref")?,
            "secondary" => require(self.primary_vault_ref.is_none(), "primary_vault_ref")?,
            _ => {}
        }
        let n = self.account_id.len()
            + self.operation_id.len()
            + self.record_hash.len()
            + self.local_ref.len()
            + self.local_role.len()
            + self.branch_vault_ref.len()
            + self.data_vault_ref.len()
            + self.primary_vault_ref.as_ref().map_or(0, String::len);
        require(n <= ADOPTION_ROW_MAX, "size")
    }
}

/// # Errors
/// Returns the exact invalid field.
pub fn decode_live(row: &LiveRow) -> Result<(), StorageError> {
    row.validate()
}

/// # Errors
/// Returns the exact invalid field.
pub fn decode_floor(row: &FloorRow) -> Result<(), StorageError> {
    row.validate()
}

/// # Errors
/// Returns the exact invalid field.
pub fn decode_head(row: &HeadRow) -> Result<(), StorageError> {
    row.validate()
}

/// # Errors
/// Returns the exact invalid field.
pub fn decode_terminal(row: &TerminalRow) -> Result<(), StorageError> {
    row.validate()
}

/// # Errors
/// Returns the exact invalid field.
pub fn decode_adoption(row: &AdoptionRow) -> Result<(), StorageError> {
    row.validate()
}

fn decode_descriptor(bytes: &[u8]) -> Result<Envelope<Invitation>, StorageError> {
    bounded(bytes, LIVE_ROW_MAX, "descriptor")?;
    let envelope: Envelope<Invitation> = parse_i_json(bytes).map_err(|_| field("descriptor"))?;
    envelope.body.validate().map_err(|error| map_wire(&error))?;
    let raw = decode_base64url(&envelope.signature).map_err(|_| field("signature"))?;
    require(raw.len() == 64 && encode_base64url(&raw) == envelope.signature, "signature")?;
    if canonical_json_bytes(&envelope).map_err(|_| field("json"))? != bytes {
        return Err(field("noncanonical"));
    }
    Ok(envelope)
}

fn decode_context(bytes: &[u8]) -> Result<LiveContext, StorageError> {
    bounded(bytes, 57_344, "context")?;
    let context: LiveContext = parse_i_json(bytes).map_err(|_| field("context"))?;
    context.initiator.validate().map_err(|error| map_wire(&error))?;
    context.responder.validate().map_err(|error| map_wire(&error))?;
    require(context.initiator.role == "initiator", "context")?;
    require(context.responder.role == "responder", "context")?;
    if canonical_json_bytes(&context).map_err(|_| field("json"))? != bytes {
        return Err(field("noncanonical"));
    }
    Ok(context)
}

fn decode_failure(bytes: &[u8]) -> Result<Failure, StorageError> {
    bounded(bytes, 1_024, "result")?;
    Failure::from_wire_bytes(bytes).map_err(|error| map_wire(&error))
}

fn decode_publication(bytes: &[u8]) -> Result<Publication, StorageError> {
    bounded(bytes, HEAD_ROW_MAX, "candidate")?;
    let value: Publication = parse_i_json(bytes).map_err(|_| field("candidate"))?;
    if canonical_json_bytes(&value).map_err(|_| field("json"))? != bytes {
        return Err(field("noncanonical"));
    }
    Ok(value)
}

fn decode_ack(bytes: &[u8]) -> Result<(), StorageError> {
    bounded(bytes, 1_024, "ack")?;
    let ack: HeadAck = parse_i_json(bytes).map_err(|_| field("ack"))?;
    b32(&ack.record_hash, "ack")?;
    integer(ack.device_set_epoch, "ack")?;
    if canonical_json_bytes(&ack).map_err(|_| field("json"))? != bytes {
        return Err(field("noncanonical"));
    }
    Ok(())
}

impl AccountDb {
    /// Persist a validated floor row.
    ///
    /// # Errors
    /// Returns the exact invalid field or SQLite errors.
    pub fn put_pairing_floor(&self, row: &FloorRow) -> Result<(), StorageError> {
        decode_floor(row)?;
        self.connection.execute(
            "INSERT INTO pairing_floor(account_id,account_anchor,issued_seq,next_generation)
             VALUES(?1,?2,?3,?4)
             ON CONFLICT(account_id) DO UPDATE SET
              account_anchor=excluded.account_anchor,
              issued_seq=excluded.issued_seq,
              next_generation=excluded.next_generation",
            params![
                row.account_id,
                row.account_anchor,
                row.issued_seq.cast_signed(),
                row.next_generation.cast_signed()
            ],
        )?;
        Ok(())
    }

    /// Persist a validated live row.
    ///
    /// # Errors
    /// Returns the exact invalid field, live cap, or SQLite errors.
    pub fn put_pairing_live(&self, row: &LiveRow) -> Result<(), StorageError> {
        decode_live(row)?;
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM pairing_live WHERE account_id=?1 AND operation_id<>?2",
            params![row.account_id, row.operation_id],
            |r| r.get(0),
        )?;
        require(count < LIVE_CAP, "live_cap")?;
        self.connection.execute(
            "INSERT INTO pairing_live(
              account_id,operation_id,invitation_id,issuer_seq,local_seq,generation,role,descriptor,
              phase,context,transcript_hash,proposal_hash,transfer_ciphertext_hash,candidate_id,
              branch_reservation,branch_vault_ref,primary_vault_ref,base_record_hash,base_epoch,
              expires_at,result)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
             ON CONFLICT(account_id,operation_id) DO UPDATE SET
              invitation_id=excluded.invitation_id,issuer_seq=excluded.issuer_seq,
              local_seq=excluded.local_seq,generation=excluded.generation,role=excluded.role,
              descriptor=excluded.descriptor,phase=excluded.phase,context=excluded.context,
              transcript_hash=excluded.transcript_hash,proposal_hash=excluded.proposal_hash,
              transfer_ciphertext_hash=excluded.transfer_ciphertext_hash,candidate_id=excluded.candidate_id,
              branch_reservation=excluded.branch_reservation,branch_vault_ref=excluded.branch_vault_ref,
              primary_vault_ref=excluded.primary_vault_ref,base_record_hash=excluded.base_record_hash,
              base_epoch=excluded.base_epoch,expires_at=excluded.expires_at,result=excluded.result",
            params![
                row.account_id,
                row.operation_id,
                row.invitation_id,
                row.issuer_seq.cast_signed(),
                row.local_seq.cast_signed(),
                row.generation.cast_signed(),
                row.role,
                row.descriptor,
                row.phase,
                row.context,
                row.transcript_hash,
                row.proposal_hash,
                row.transfer_ciphertext_hash,
                row.candidate_id,
                row.branch_reservation,
                row.branch_vault_ref,
                row.primary_vault_ref,
                row.base_record_hash,
                row.base_epoch.cast_signed(),
                row.expires_at.cast_signed(),
                row.result,
            ],
        )?;
        Ok(())
    }

    /// Persist a validated head row.
    ///
    /// # Errors
    /// Returns the exact invalid field or SQLite errors.
    pub fn put_pairing_head(&self, row: &HeadRow) -> Result<(), StorageError> {
        decode_head(row)?;
        self.connection.execute(
            "INSERT INTO pairing_head(
              account_id,operation_id,invitation_id,generation,kind,base_record_hash,base_epoch,
              publisher_ref,candidate,candidate_hash,state,ack,recipient_ref,revoked_ref,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             ON CONFLICT(account_id) DO UPDATE SET
              operation_id=excluded.operation_id,invitation_id=excluded.invitation_id,
              generation=excluded.generation,kind=excluded.kind,base_record_hash=excluded.base_record_hash,
              base_epoch=excluded.base_epoch,publisher_ref=excluded.publisher_ref,candidate=excluded.candidate,
              candidate_hash=excluded.candidate_hash,state=excluded.state,ack=excluded.ack,
              recipient_ref=excluded.recipient_ref,revoked_ref=excluded.revoked_ref,created_at=excluded.created_at",
            params![
                row.account_id,
                row.operation_id,
                row.invitation_id,
                row.generation.cast_signed(),
                row.kind,
                row.base_record_hash,
                row.base_epoch.cast_signed(),
                row.publisher_ref,
                row.candidate,
                row.candidate_hash,
                row.state,
                row.ack,
                row.recipient_ref,
                row.revoked_ref,
                row.created_at.cast_signed(),
            ],
        )?;
        Ok(())
    }

    /// Persist a validated terminal row.
    ///
    /// # Errors
    /// Returns the exact invalid field, terminal cap, or SQLite errors.
    pub fn put_pairing_terminal(&self, row: &TerminalRow) -> Result<(), StorageError> {
        decode_terminal(row)?;
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM pairing_terminal WHERE account_id=?1 AND operation_id<>?2",
            params![row.account_id, row.operation_id],
            |r| r.get(0),
        )?;
        require(count < TERMINAL_CAP, "terminal_cap")?;
        self.connection.execute(
            "INSERT INTO pairing_terminal(
              account_id,operation_id,invitation_id,issuer_seq,local_seq,generation,outcome,
              record_hash,finished_at,cleanup)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(account_id,operation_id) DO UPDATE SET
              invitation_id=excluded.invitation_id,issuer_seq=excluded.issuer_seq,
              local_seq=excluded.local_seq,generation=excluded.generation,outcome=excluded.outcome,
              record_hash=excluded.record_hash,finished_at=excluded.finished_at,cleanup=excluded.cleanup",
            params![
                row.account_id,
                row.operation_id,
                row.invitation_id,
                row.issuer_seq.cast_signed(),
                row.local_seq.cast_signed(),
                row.generation.cast_signed(),
                row.outcome,
                row.record_hash,
                row.finished_at.cast_signed(),
                row.cleanup,
            ],
        )?;
        Ok(())
    }

    /// Persist a validated adoption row.
    ///
    /// # Errors
    /// Returns the exact invalid field or SQLite errors.
    pub fn put_pairing_adoption(&self, row: &AdoptionRow) -> Result<(), StorageError> {
        decode_adoption(row)?;
        self.connection.execute(
            "INSERT INTO pairing_adoption(
              account_id,operation_id,record_hash,local_ref,local_role,branch_vault_ref,
              data_vault_ref,primary_vault_ref)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(account_id) DO UPDATE SET
              operation_id=excluded.operation_id,record_hash=excluded.record_hash,
              local_ref=excluded.local_ref,local_role=excluded.local_role,
              branch_vault_ref=excluded.branch_vault_ref,data_vault_ref=excluded.data_vault_ref,
              primary_vault_ref=excluded.primary_vault_ref",
            params![
                row.account_id,
                row.operation_id,
                row.record_hash,
                row.local_ref,
                row.local_role,
                row.branch_vault_ref,
                row.data_vault_ref,
                row.primary_vault_ref,
            ],
        )?;
        Ok(())
    }

    /// Load the floor for this account, if present.
    ///
    /// # Errors
    /// Returns SQLite errors or a malformed stored row.
    pub fn pairing_floor(&self) -> Result<Option<FloorRow>, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT account_id,account_anchor,issued_seq,next_generation FROM pairing_floor WHERE account_id=?1",
                params![self.local_account_id],
                |r| {
                    Ok(FloorRow {
                        account_id: r.get(0)?,
                        account_anchor: r.get(1)?,
                        issued_seq: r.get::<_, i64>(2)?.cast_unsigned(),
                        next_generation: r.get::<_, i64>(3)?.cast_unsigned(),
                    })
                },
            )
            .optional()?;
        if let Some(row) = &row {
            row.validate()?;
        }
        Ok(row)
    }

    /// Count live rows for this account.
    ///
    /// # Errors
    /// Returns SQLite errors.
    pub fn pairing_live_count(&self) -> Result<i64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT count(*) FROM pairing_live WHERE account_id=?1",
            params![self.local_account_id],
            |r| r.get(0),
        )?)
    }

    /// Count terminal rows for this account.
    ///
    /// # Errors
    /// Returns SQLite errors.
    pub fn pairing_terminal_count(&self) -> Result<i64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT count(*) FROM pairing_terminal WHERE account_id=?1",
            params![self.local_account_id],
            |r| r.get(0),
        )?)
    }

    /// Load the adoption marker, if present.
    ///
    /// # Errors
    /// Returns SQLite errors or a malformed stored row.
    pub fn pairing_adoption(&self) -> Result<Option<AdoptionRow>, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT account_id,operation_id,record_hash,local_ref,local_role,branch_vault_ref,data_vault_ref,primary_vault_ref
                 FROM pairing_adoption WHERE account_id=?1",
                params![self.local_account_id],
                |r| {
                    Ok(AdoptionRow {
                        account_id: r.get(0)?,
                        operation_id: r.get(1)?,
                        record_hash: r.get(2)?,
                        local_ref: r.get(3)?,
                        local_role: r.get(4)?,
                        branch_vault_ref: r.get(5)?,
                        data_vault_ref: r.get(6)?,
                        primary_vault_ref: r.get(7)?,
                    })
                },
            )
            .optional()?;
        if let Some(row) = &row {
            row.validate()?;
        }
        Ok(row)
    }
}

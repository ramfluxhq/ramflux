// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Strict canonical admission. Crypto verification and stateful authorization are later parts.
use super::{
    Action, AvatarRef, BatchResult, BatchRow, Checkpoint, CheckpointDelta, CounterKey, CounterRow,
    DeletePreemptingPending, DeltaKind, DirectoryCode, DirectoryFailure, DirectoryReceiptBody,
    DirectoryResolveBody, DueKey, DueRow, ExpectedHead, HoldKey, HoldRow, HomeRevalidateRequest,
    HomeRevalidateResult, IdentityProfileV2Body, IndexState, Metric, NameRow, OperationKey,
    OperationOwnerRow, OperationRow, ProfileRef, ReceiptDecision, ReceiptState, Replacement,
    RootRow, ServeCandidate, Signed, SkeletonRow, UsernameBindingBody, UsernameOperationBody,
};
use crate::ProtocolError;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("invalid username-directory field: {0}")]
    Field(&'static str),
    #[error("noncanonical username-directory bytes")]
    Noncanonical,
    #[error("username-directory size limit")]
    Size,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
/// Closed wire codecs expose validation but never authorize a request.
pub trait Wire: Serialize + serde::de::DeserializeOwned {
    const LIMIT: usize;
    /// # Errors
    /// Rejects field bounds and locally decidable cross-field violations.
    fn validate(&self) -> Result<(), CodecError>;
}
/// # Errors
/// Rejects noncanonical, oversized, duplicate/unknown/missing fields and invalid values.
pub fn decode<T: Wire>(bytes: &[u8]) -> Result<T, CodecError> {
    need(bytes.len() <= T::LIMIT, "frame_size")?;
    let mut depth = 0_u32;
    let mut quoted = false;
    let mut escaped = false;
    for &b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    need(depth <= 12, "depth")?;
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
    }
    let value: serde_json::Value = crate::parse_i_json(bytes)?;
    strings(&value)?;
    let decoded: T = serde_json::from_value(value)?;
    decoded.validate()?;
    if crate::canonical_json_bytes(&decoded)? != bytes {
        return Err(CodecError::Noncanonical);
    }
    Ok(decoded)
}
/// # Errors
/// Rejects invalid values; local text normalization is exposed by dedicated helpers.
pub fn encode<T: Wire>(value: &T) -> Result<Vec<u8>, CodecError> {
    value.validate()?;
    let bytes = crate::canonical_json_bytes(value)?;
    if bytes.len() > T::LIMIT {
        return Err(CodecError::Size);
    }
    Ok(bytes)
}
pub(crate) fn need(ok: bool, field: &'static str) -> Result<(), CodecError> {
    if ok { Ok(()) } else { Err(CodecError::Field(field)) }
}
fn safe(n: u64, field: &'static str) -> Result<(), CodecError> {
    need(n <= crate::MAX_SAFE_JSON_INTEGER, field)
}
fn positive(n: u64, field: &'static str) -> Result<(), CodecError> {
    safe(n, field)?;
    need(n > 0, field)
}
fn duration(start: u64, end: u64, max: u64) -> Result<(), CodecError> {
    need(end.checked_sub(start).is_some_and(|n| n > 0 && n <= max), "expires_at")
}
fn within<T: Serialize>(v: &T, cap: usize) -> Result<(), CodecError> {
    need(crate::canonical_json_bytes(v)?.len() <= cap, "frame_size")
}
fn fixed(value: &str, n: usize, field: &'static str) -> Result<(), CodecError> {
    let decoded = crate::decode_base64url(value).map_err(|_| CodecError::Field(field))?;
    need(decoded.len() == n && crate::encode_base64url(decoded) == value, field)
}
/// # Errors
/// Rejects remote names; no normalization occurs during admission.
pub fn validate_username(value: &str) -> Result<(), CodecError> {
    need(
        (5..=32).contains(&value.len())
            && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "name",
    )
}
/// # Errors
/// Bounds and normalizes locally supplied username input only.
pub fn normalize_username(value: &str) -> Result<String, CodecError> {
    need(value.len() <= 1024, "name")?;
    let result = value.trim().to_ascii_lowercase();
    validate_username(&result)?;
    Ok(result)
}
fn node(value: &str) -> Result<(), CodecError> {
    need(
        !value.is_empty()
            && value.len() <= 253
            && value.parse::<std::net::IpAddr>().is_err()
            && value.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }),
        "node",
    )
}
fn text(value: &str, field: &'static str) -> Result<(), CodecError> {
    match field {
        "name" | "old_name" => validate_username(value),
        "node" | "home" | "center_id" => node(value),
        "signature" => fixed(value, 64, field),
        "schema" => need(value == crate::domain::IDENTITY_PROFILE_V2, "schema"),
        "principal_id" => need(
            !value.is_empty() && value.len() <= 256 && value.bytes().all(|b| b.is_ascii_graphic()),
            field,
        ),
        "display_name" => need(
            crate::identity_name::normalize_profile_display_name(value)
                .map_err(|_| CodecError::Field(field))?
                == value,
            field,
        ),
        "bio" => need(normalize_bio(value)? == value, field),
        "skeleton" => need(
            (5..=64).contains(&value.len())
                && value.bytes().all(|b| {
                    b == b'O'
                        || b == b'_'
                        || b.is_ascii_lowercase() && b != b'm'
                        || (b'2'..=b'9').contains(&b)
                }),
            field,
        ),
        _ => fixed(value, 32, field),
    }
}
/// # Errors
/// Normalizes local bio text and refuses unsafe scalars or excessive size.
pub fn normalize_bio(value: &str) -> Result<String, CodecError> {
    use unicode_general_category::{GeneralCategory as C, get_general_category};
    use unicode_normalization::UnicodeNormalization;
    use unicode_security::{GeneralSecurityProfile, general_security_profile::IdentifierType};
    need(value.len() <= 2048, "bio")?;
    let result: String = value.trim().nfc().collect();
    need(
        result.len() <= 560
            && result.chars().count() <= 140
            && result.chars().all(|c| {
                c.identifier_type() != Some(IdentifierType::Default_Ignorable)
                    && !matches!(
                        get_general_category(c),
                        C::Control
                            | C::Format
                            | C::Surrogate
                            | C::PrivateUse
                            | C::Unassigned
                            | C::LineSeparator
                            | C::ParagraphSeparator
                    )
            }),
        "bio",
    )?;
    Ok(result)
}
impl<T: Wire> Wire for Signed<T> {
    const LIMIT: usize = T::LIMIT;
    fn validate(&self) -> Result<(), CodecError> {
        self.body.validate()?;
        fixed(&self.signature, 64, "signature")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for UsernameBindingBody {
    const LIMIT: usize = 1024;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.name;
            text(v, "name")?;
        }
        {
            let v = &self.node;
            text(v, "node")?;
        }
        {
            let v = &self.principal_commitment;
            text(v, "principal_commitment")?;
        }
        {
            let v = &self.epoch;
            safe(*v, "epoch")?;
        }
        positive(self.epoch, "epoch")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for ProfileRef {
    const LIMIT: usize = 128;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.version;
            safe(u64::from(*v), "version")?;
        }
        {
            let v = &self.epoch;
            safe(*v, "epoch")?;
        }
        {
            let v = &self.hash;
            if let Some(v) = v {
                text(v, "hash")?;
            }
        }
        need(self.version <= 2, "version")?;
        need(
            if self.version == 0 {
                self.epoch == 0 && self.hash.is_none()
            } else {
                self.epoch > 0 && self.hash.is_some()
            },
            "profile_ref",
        )?;
        within(self, Self::LIMIT)
    }
}

impl Wire for AvatarRef {
    const LIMIT: usize = 260;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.content_hash;
            text(v, "content_hash")?;
        }
        {
            let v = &self.size;
            safe(*v, "size")?;
        }
        {
            let v = &self.relay_ref;
            text(v, "relay_ref")?;
        }
        need((1..=524_288).contains(&self.size), "size")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for IdentityProfileV2Body {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.schema;
            text(v, "schema")?;
        }
        {
            let v = &self.principal_id;
            text(v, "principal_id")?;
        }
        {
            let v = &self.principal_commitment;
            text(v, "principal_commitment")?;
        }
        {
            let v = &self.display_name;
            text(v, "display_name")?;
        }
        {
            let v = &self.bio;
            text(v, "bio")?;
        }
        {
            let v = &self.avatar;
            if let Some(v) = v {
                (v).validate()?;
            }
        }
        {
            let v = &self.epoch;
            safe(*v, "epoch")?;
        }
        positive(self.epoch, "epoch")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for UsernameOperationBody {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.operation_id;
            text(v, "operation_id")?;
        }
        {
            let v = &self.principal_commitment;
            text(v, "principal_commitment")?;
        }
        {
            let v = &self.expected_epoch;
            safe(*v, "expected_epoch")?;
        }
        {
            let v = &self.next_epoch;
            safe(*v, "next_epoch")?;
        }
        {
            let v = &self.expected_profile;
            (v).validate()?;
        }
        {
            let v = &self.profile;
            (v).validate()?;
        }
        {
            let v = &self.old_name;
            if let Some(v) = v {
                text(v, "old_name")?;
            }
        }
        {
            let v = &self.binding;
            if let Some(v) = v {
                (v).validate()?;
            }
        }
        {
            let v = &self.issued_at;
            safe(*v, "issued_at")?;
        }
        {
            let v = &self.expires_at;
            safe(*v, "expires_at")?;
        }
        operation(self)?;
        within(self, Self::LIMIT)
    }
}

impl Wire for DirectoryReceiptBody {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.center_id;
            text(v, "center_id")?;
        }
        {
            let v = &self.operation_id;
            text(v, "operation_id")?;
        }
        {
            let v = &self.operation_hash;
            text(v, "operation_hash")?;
        }
        {
            let v = &self.principal_commitment;
            text(v, "principal_commitment")?;
        }
        {
            let v = &self.epoch;
            safe(*v, "epoch")?;
        }
        {
            let v = &self.binding_hash;
            if let Some(v) = v {
                text(v, "binding_hash")?;
            }
        }
        {
            let v = &self.profile;
            (v).validate()?;
        }
        {
            let v = &self.committed_at;
            safe(*v, "committed_at")?;
        }
        {
            let v = &self.expires_at;
            safe(*v, "expires_at")?;
        }
        positive(self.epoch, "epoch")?;
        need(self.profile.version == 2, "profile")?;
        need(self.expires_at > self.committed_at, "expires_at")?;
        if self.state == ReceiptState::Reserved {
            need(self.committed_at.checked_add(120) == Some(self.expires_at), "expires_at")?;
        }
        within(self, Self::LIMIT)
    }
}

impl Wire for DirectoryResolveBody {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.center_id;
            text(v, "center_id")?;
        }
        {
            let v = &self.name;
            text(v, "name")?;
        }
        {
            let v = &self.node;
            text(v, "node")?;
        }
        {
            let v = &self.principal_commitment;
            text(v, "principal_commitment")?;
        }
        {
            let v = &self.epoch;
            safe(*v, "epoch")?;
        }
        {
            let v = &self.binding_hash;
            text(v, "binding_hash")?;
        }
        {
            let v = &self.profile;
            (v).validate()?;
        }
        {
            let v = &self.request_nonce;
            text(v, "request_nonce")?;
        }
        {
            let v = &self.issued_at;
            safe(*v, "issued_at")?;
        }
        {
            let v = &self.expires_at;
            safe(*v, "expires_at")?;
        }
        positive(self.epoch, "epoch")?;
        need(self.profile.version == 2, "profile")?;
        duration(self.issued_at, self.expires_at, 60)?;
        within(self, Self::LIMIT)
    }
}

impl Wire for ReceiptDecision {
    const LIMIT: usize = 64;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.committed_at;
            safe(*v, "committed_at")?;
        }

        within(self, Self::LIMIT)
    }
}

impl Wire for RootRow {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.epoch;
            safe(*v, "epoch")?;
        }
        {
            let v = &self.name;
            if let Some(v) = v {
                text(v, "name")?;
            }
        }
        {
            let v = &self.node;
            text(v, "node")?;
        }
        {
            let v = &self.profile;
            (v).validate()?;
        }
        {
            let v = &self.binding_hash;
            if let Some(v) = v {
                text(v, "binding_hash")?;
            }
        }
        {
            let v = &self.current_binding;
            if let Some(v) = v {
                (v).validate()?;
            }
        }
        {
            let v = &self.receipt_decision;
            if let Some(v) = v {
                (v).validate()?;
            }
        }
        {
            let v = &self.last_operation_id;
            if let Some(v) = v {
                text(v, "last_operation_id")?;
            }
        }
        {
            let v = &self.last_operation_hash;
            if let Some(v) = v {
                text(v, "last_operation_hash")?;
            }
        }
        {
            let v = &self.pending_operation_id;
            if let Some(v) = v {
                text(v, "pending_operation_id")?;
            }
        }
        {
            let v = &self.changes;
            for v in v {
                safe(*v, "changes")?;
            }
        }
        {
            let v = &self.hold_deadlines;
            for v in v {
                safe(*v, "hold_deadlines")?;
            }
        }
        root_row(self)?;
        within(self, Self::LIMIT)
    }
}

impl Wire for NameRow {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.root;
            text(v, "root")?;
        }
        {
            let v = &self.operation_id;
            if let Some(v) = v {
                text(v, "operation_id")?;
            }
        }
        need((self.state == IndexState::Reserved) == self.operation_id.is_some(), "operation_id")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for SkeletonRow {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.name;
            text(v, "name")?;
        }
        {
            let v = &self.root;
            text(v, "root")?;
        }
        {
            let v = &self.operation_id;
            if let Some(v) = v {
                text(v, "operation_id")?;
            }
        }
        need((self.state == IndexState::Reserved) == self.operation_id.is_some(), "operation_id")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for HoldKey {
    const LIMIT: usize = 256;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.name;
            text(v, "name")?;
        }
        {
            let v = &self.skeleton;
            text(v, "skeleton")?;
        }
        need(
            crate::identity_name::username_comparison_key(&self.name)? == self.skeleton,
            "skeleton",
        )?;
        within(self, Self::LIMIT)
    }
}

impl Wire for HoldRow {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.release_at;
            safe(*v, "release_at")?;
        }
        {
            let v = &self.hold_until;
            safe(*v, "hold_until")?;
        }
        need(self.release_at.checked_add(2_592_000) == Some(self.hold_until), "hold_until")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for OperationKey {
    const LIMIT: usize = 256;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.root;
            text(v, "root")?;
        }
        {
            let v = &self.operation_id;
            text(v, "operation_id")?;
        }

        within(self, Self::LIMIT)
    }
}

impl Wire for OperationRow {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.operation;
            (v).validate()?;
        }
        {
            let v = &self.operation_hash;
            text(v, "operation_hash")?;
        }
        {
            let v = &self.reserved_at;
            safe(*v, "reserved_at")?;
        }
        {
            let v = &self.reservation_expires_at;
            safe(*v, "reservation_expires_at")?;
        }
        {
            let v = &self.finished_at;
            if let Some(v) = v {
                safe(*v, "finished_at")?;
            }
        }
        {
            let v = &self.retain_until;
            if let Some(v) = v {
                safe(*v, "retain_until")?;
            }
        }
        need(
            self.reserved_at.checked_add(120) == Some(self.reservation_expires_at),
            "reservation_expires_at",
        )?;
        if self.state == ReceiptState::Reserved {
            need(self.finished_at.is_none() && self.retain_until.is_none(), "finished_at")?;
        } else {
            let time = self.finished_at.ok_or(CodecError::Field("finished_at"))?;
            need(
                time >= self.reserved_at && time.checked_add(86400) == self.retain_until,
                "retain_until",
            )?;
            if self.state == ReceiptState::Committed {
                need(
                    time < self.reservation_expires_at && time < self.operation.body.expires_at,
                    "finished_at",
                )?;
            }
        }
        within(self, Self::LIMIT)
    }
}

impl Wire for OperationOwnerRow {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.root;
            text(v, "root")?;
        }
        {
            let v = &self.operation_hash;
            text(v, "operation_hash")?;
        }

        within(self, Self::LIMIT)
    }
}

impl Wire for DueRow {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.count;
            safe(*v, "count")?;
        }
        need((1..=400_000).contains(&self.count), "count")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for CounterRow {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.value;
            safe(*v, "value")?;
        }

        within(self, Self::LIMIT)
    }
}

impl Wire for ExpectedHead {
    const LIMIT: usize = 128;
    fn validate(&self) -> Result<(), CodecError> {
        safe(self.lsn, "lsn")?;
        fixed(&self.digest, 32, "digest")?;
        within(self, Self::LIMIT)
    }
}
impl Wire for DeletePreemptingPending {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        fixed(&self.tx_id, 32, "tx_id")?;
        self.operation.validate()?;
        need(self.operation.body.action == Action::Delete, "action")?;
        self.expected_head.validate()?;
        safe(self.requested_time, "requested_time")?;
        within(self, Self::LIMIT)
    }
}
impl Wire for BatchResult {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        fixed(&self.abort_digest, 32, "abort_digest")?;
        fixed(&self.delete_digest, 32, "delete_digest")?;
        safe(self.clock_floor, "clock_floor")?;
        within(self, Self::LIMIT)
    }
}
impl Wire for BatchRow {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<(), CodecError> {
        fixed(&self.batch_id, 32, "batch_id")?;
        fixed(&self.root, 32, "root")?;
        fixed(&self.request_hash, 32, "request_hash")?;
        fixed(&self.abort_tx_id, 32, "abort_tx_id")?;
        positive(self.lsn_n1, "lsn_n1")?;
        positive(self.lsn_n2, "lsn_n2")?;
        safe(self.retain_until, "retain_until")?;
        self.result.validate()?;
        need(self.abort_tx_id != self.batch_id, "abort_tx_id")?;
        need(self.lsn_n1.checked_add(1) == Some(self.lsn_n2), "lsn_n2")?;
        need(
            self.result
                .clock_floor
                .checked_add(86400)
                .is_some_and(|minimum| self.retain_until >= minimum),
            "retain_until",
        )?;
        within(self, Self::LIMIT)
    }
}

impl Wire for CheckpointDelta {
    const LIMIT: usize = 65536;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.tx_id;
            text(v, "tx_id")?;
        }
        {
            let v = &self.writer_incarnation;
            text(v, "writer_incarnation")?;
        }
        {
            let v = &self.clock_floor;
            safe(*v, "clock_floor")?;
        }
        {
            let v = &self.operation;
            if let Some(v) = v {
                (v).validate()?;
            }
        }
        {
            let v = &self.rows;
            for v in v {
                need(!matches!(v, Replacement::Batch { .. }), "batch")?;
                (v).validate()?;
            }
        }
        need(
            matches!(self.kind, DeltaKind::Reserve | DeltaKind::Commit) == self.operation.is_some(),
            "operation",
        )?;
        if self.kind == DeltaKind::Clock {
            need(self.rows.is_empty(), "rows")?;
        }
        if let Some(operation) = &self.operation {
            for replacement in &self.rows {
                if let Replacement::Operation { old, new, .. } = replacement {
                    for row in [old, new].into_iter().flatten() {
                        need(&row.operation == operation, "operation")?;
                    }
                }
            }
        }
        let mut previous: Option<(String, Vec<u8>)> = None;
        for row in &self.rows {
            let key = row.order_key()?;
            if let Some(old) = &previous {
                need(old < &key, "row_order")?;
            }
            previous = Some(key);
        }
        within(self, Self::LIMIT)
    }
}

impl Wire for Checkpoint {
    const LIMIT: usize = 67584;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.center_id;
            text(v, "center_id")?;
        }
        {
            let v = &self.generation;
            safe(*v, "generation")?;
        }
        {
            let v = &self.lsn;
            safe(*v, "lsn")?;
        }
        {
            let v = &self.previous_digest;
            text(v, "previous_digest")?;
        }
        {
            let v = &self.delta;
            (v).validate()?;
        }
        positive(self.generation, "generation")?;
        if self.lsn == 0 {
            need(
                self.previous_digest == crate::encode_base64url([0_u8; 32])
                    && self.delta.kind == DeltaKind::Clock
                    && self.delta.rows.is_empty(),
                "lsn",
            )?;
        }
        need(crate::canonical_json_bytes(&self.delta)?.len() <= 65536, "delta")?;
        within(self, Self::LIMIT)
    }
}

impl Wire for HomeRevalidateRequest {
    const LIMIT: usize = 1024;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.root;
            text(v, "root")?;
        }
        {
            let v = &self.known_directory_epoch;
            safe(*v, "known_directory_epoch")?;
        }
        {
            let v = &self.operation_id;
            if let Some(v) = v {
                text(v, "operation_id")?;
            }
        }
        {
            let v = &self.nonce;
            text(v, "nonce")?;
        }

        within(self, Self::LIMIT)
    }
}

impl Wire for HomeRevalidateResult {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.root;
            text(v, "root")?;
        }
        {
            let v = &self.nonce;
            text(v, "nonce")?;
        }
        {
            let v = &self.current_binding;
            if let Some(v) = v {
                (v).validate()?;
            }
        }
        {
            let v = &self.current_receipt;
            if let Some(v) = v {
                (v).validate()?;
            }
        }
        {
            let v = &self.pending_receipt;
            if let Some(v) = v {
                (v).validate()?;
            }
        }
        {
            let v = &self.issued_at;
            safe(*v, "issued_at")?;
        }
        {
            let v = &self.expires_at;
            safe(*v, "expires_at")?;
        }
        home_result(self)?;
        duration(self.issued_at, self.expires_at, 10)?;
        within(self, Self::LIMIT)
    }
}

impl Wire for DirectoryFailure {
    const LIMIT: usize = 1024;
    fn validate(&self) -> Result<(), CodecError> {
        {
            let v = &self.retry_after_ms;
            if let Some(v) = v {
                safe(*v, "retry_after_ms")?;
            }
        }
        let retry = matches!(
            self.code,
            DirectoryCode::RateLimited
                | DirectoryCode::Capacity
                | DirectoryCode::DirectoryUnavailable
                | DirectoryCode::OperationPending
        );
        need(retry == self.retry_after_ms.is_some(), "retry_after_ms")?;
        if let Some(n) = self.retry_after_ms {
            need((1000..=60000).contains(&n), "retry_after_ms")?;
        }
        within(self, Self::LIMIT)
    }
}

fn operation(op: &UsernameOperationBody) -> Result<(), CodecError> {
    need(op.expected_epoch.checked_add(1) == Some(op.next_epoch), "next_epoch")?;
    need(op.profile.version == 2, "profile")?;
    if op.expected_epoch == 0 {
        need(
            matches!(op.action, Action::Claim | Action::ProfileUpdate)
                && op.expected_profile.version == 0
                && op.binding.is_some() == (op.action == Action::Claim),
            "expected_epoch",
        )?;
    } else {
        need(op.expected_profile.version == 2, "expected_profile")?;
        if op.action == Action::ProfileUpdate {
            need(op.expected_profile.epoch.checked_add(1) == Some(op.profile.epoch), "profile")?;
        } else {
            need(op.profile == op.expected_profile, "profile")?;
        }
    }
    if let Some(binding) = &op.binding {
        need(
            binding.body.principal_commitment == op.principal_commitment
                && binding.body.epoch == op.next_epoch,
            "binding",
        )?;
    }
    match op.action {
        Action::Claim => need(op.old_name.is_none() && op.binding.is_some(), "old_name")?,
        Action::Rename => {
            let old = op.old_name.as_deref().ok_or(CodecError::Field("old_name"))?;
            let new = op.binding.as_ref().ok_or(CodecError::Field("binding"))?;
            need(
                old != new.body.name
                    && crate::identity_name::username_comparison_key(old)?
                        != crate::identity_name::username_comparison_key(&new.body.name)?,
                "name",
            )?;
        }
        Action::Release | Action::Delete => {
            need(op.binding.is_none() && !op.discoverable, "binding")?;
            if op.action == Action::Release {
                need(op.old_name.is_some(), "old_name")?;
            }
        }
        Action::SetVisibility | Action::MoveHome | Action::ProfileUpdate => need(
            op.old_name.as_deref() == op.binding.as_ref().map(|b| b.body.name.as_str()),
            "old_name",
        )?,
    }
    if matches!(op.action, Action::Claim | Action::Rename) {
        let name = &op.binding.as_ref().ok_or(CodecError::Field("binding"))?.body.name;
        let key = crate::identity_name::username_comparison_key(name)?;
        for reserved in [
            "admin",
            "administrator",
            "root",
            "system",
            "support",
            "security",
            "ramflux",
            "official",
            "moderator",
            "notify",
            "federation",
        ] {
            let skel: String = unicode_security::skeleton(reserved).collect();
            need(name != reserved && key != skel, "name")?;
        }
        for prefix in ["ramflux_", "system_"] {
            let skel: String = unicode_security::skeleton(prefix).collect();
            need(!name.starts_with(prefix) && !key.starts_with(&skel), "name")?;
        }
    }
    need(op.issued_at.checked_add(300) == Some(op.expires_at), "expires_at")
}
fn root_row(row: &RootRow) -> Result<(), CodecError> {
    let committed = row.epoch > 0;
    need(
        row.last_operation_id.is_some() == committed
            && row.last_operation_hash.is_some() == committed
            && row.receipt_decision.is_some() == committed,
        "receipt_decision",
    )?;
    need(
        if committed {
            row.profile.version == 2
        } else {
            row.profile.version == 0 && row.name.is_none()
        },
        "profile",
    )?;
    need(
        row.name.is_some() == row.binding_hash.is_some()
            && row.name.is_some() == row.current_binding.is_some(),
        "current_binding",
    )?;
    if let Some(b) = &row.current_binding {
        need(
            Some(&b.body.name) == row.name.as_ref()
                && b.body.node == row.node
                && b.body.epoch == row.epoch,
            "current_binding",
        )?;
    }
    need(
        row.changes.len() <= 3
            && row.changes.windows(2).all(|w| w[1].checked_sub(w[0]).is_some_and(|n| n >= 86400)),
        "changes",
    )?;
    need(
        row.hold_deadlines.len() <= if row.deleted { 4 } else { 3 }
            && row.hold_deadlines.windows(2).all(|w| w[0] <= w[1]),
        "hold_deadlines",
    )?;
    if row.deleted {
        need(
            row.name.is_none()
                && row.pending_operation_id.is_none()
                && !row.discoverable
                && committed,
            "deleted",
        )?;
    }
    if let Some(id) = &row.pending_operation_id {
        need(Some(id) != row.last_operation_id.as_ref(), "pending_operation_id")?;
    }
    Ok(())
}
fn home_result(row: &HomeRevalidateResult) -> Result<(), CodecError> {
    if let Some(b) = &row.current_binding {
        need(b.body.principal_commitment == row.root, "current_binding")?;
    }
    if let Some(r) = &row.current_receipt {
        need(
            r.body.principal_commitment == row.root && r.body.state == ReceiptState::Committed,
            "current_receipt",
        )?;
        need(r.body.binding_hash.is_some() == row.current_binding.is_some(), "current_binding")?;
        if let Some(b) = &row.current_binding {
            need(b.body.epoch == r.body.epoch, "epoch")?;
        }
    } else {
        need(row.current_binding.is_none(), "current_receipt")?;
    }
    if let Some(p) = &row.pending_receipt {
        need(
            p.body.principal_commitment == row.root && p.body.state == ReceiptState::Reserved,
            "pending_receipt",
        )?;
        let expected_epoch = row
            .current_receipt
            .as_ref()
            .map_or(Some(1), |current| current.body.epoch.checked_add(1));
        need(expected_epoch == Some(p.body.epoch), "pending_epoch")?;
        if let Some(current) = &row.current_receipt {
            need(current.body.center_id == p.body.center_id, "center_id")?;
        }
    }
    if row.lookup_allowed {
        need(
            row.current_binding.is_some()
                && row.current_receipt.as_ref().is_some_and(|r| r.body.discoverable),
            "lookup_allowed",
        )?;
    }
    Ok(())
}
impl Wire for DueKey {
    const LIMIT: usize = 1024;
    fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Hold { at, name, skeleton } => {
                safe(*at, "at")?;
                validate_username(name)?;
                need(
                    crate::identity_name::username_comparison_key(name)? == *skeleton,
                    "skeleton",
                )?;
            }
            Self::Operation { at, root, operation_id, .. } => {
                safe(*at, "at")?;
                fixed(root, 32, "root")?;
                fixed(operation_id, 32, "operation_id")?;
            }
            Self::RootWindow { at, root } => {
                safe(*at, "at")?;
                fixed(root, 32, "root")?;
            }
            Self::HomeHoldCredit { at, home } => {
                safe(*at, "at")?;
                node(home)?;
            }
        }
        within(self, Self::LIMIT)
    }
}
impl Wire for CounterKey {
    const LIMIT: usize = 1024;
    fn validate(&self) -> Result<(), CodecError> {
        if let Self::Home { home, .. } = self {
            node(home)?;
        }
        within(self, Self::LIMIT)
    }
}
fn images<T: Wire + PartialEq>(old: Option<&T>, new: Option<&T>) -> Result<(), CodecError> {
    need(old != new, "images")?;
    if let Some(v) = old {
        v.validate()?;
    }
    if let Some(v) = new {
        v.validate()?;
    }
    Ok(())
}
impl Replacement {
    /// Canonical set ordering does not substitute for stateful transaction validation.
    /// # Errors
    /// Propagates serialization errors for invalid keys.
    pub fn order_key(&self) -> Result<(String, Vec<u8>), CodecError> {
        let v = serde_json::to_value(self)?;
        let table =
            v.get("table").and_then(serde_json::Value::as_str).ok_or(CodecError::Field("table"))?;
        let key = v.get("key").ok_or(CodecError::Field("key"))?;
        Ok((table.to_owned(), crate::canonical_json_bytes(key)?))
    }
}
impl Wire for Replacement {
    const LIMIT: usize = 65536;
    fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Batch { key, old, new } => {
                fixed(key, 32, "batch_id")?;
                images(old.as_ref(), new.as_ref())?;
                for row in [old, new].into_iter().flatten() {
                    need(row.batch_id == *key, "batch_id")?;
                }
            }
            Self::Root { key, old, new } => {
                fixed(key, 32, "root")?;
                images(old.as_ref(), new.as_ref())?;
                let next = new.as_ref().ok_or(CodecError::Field("root"))?;
                if let Some(previous) = old {
                    need(!previous.deleted || next.deleted, "deleted")?;
                    need(next.epoch >= previous.epoch, "epoch")?;
                }
                for row in [old, new].into_iter().flatten() {
                    if let Some(b) = &row.current_binding {
                        need(b.body.principal_commitment == *key, "current_binding")?;
                    }
                }
            }
            Self::Name { key, old, new } => {
                validate_username(key)?;
                images(old.as_ref(), new.as_ref())?;
            }
            Self::Skeleton { key, old, new } => {
                text(key, "skeleton")?;
                images(old.as_ref(), new.as_ref())?;
                for row in [old, new].into_iter().flatten() {
                    need(
                        crate::identity_name::username_comparison_key(&row.name)? == *key,
                        "skeleton",
                    )?;
                }
            }
            Self::Hold { key, old, new } => {
                key.validate()?;
                images(old.as_ref(), new.as_ref())?;
            }
            Self::Operation { key, old, new } => {
                key.validate()?;
                images(old.as_ref(), new.as_ref())?;
                for row in [old, new].into_iter().flatten() {
                    need(
                        row.operation.body.principal_commitment == key.root
                            && row.operation.body.operation_id == key.operation_id,
                        "operation",
                    )?;
                }
            }
            Self::OpOwner { key, old, new } => {
                fixed(key, 32, "operation_id")?;
                images(old.as_ref(), new.as_ref())?;
            }
            Self::Due { key, old, new } => {
                key.validate()?;
                images(old.as_ref(), new.as_ref())?;
                if !matches!(key, DueKey::HomeHoldCredit { .. }) {
                    for row in [old, new].into_iter().flatten() {
                        need(row.count == 1, "count")?;
                    }
                }
            }
            Self::Counter { key, old, new } => {
                key.validate()?;
                images(old.as_ref(), new.as_ref())?;
                let (metric, home) = match key {
                    CounterKey::Global { metric } => (*metric, false),
                    CounterKey::Home { metric, .. } => (*metric, true),
                };
                let max = match metric {
                    Metric::RootSlots | Metric::ActiveNames | Metric::PendingOperations => {
                        if home {
                            100_000
                        } else {
                            1_000_000
                        }
                    }
                    Metric::HeldNames => {
                        if home {
                            400_000
                        } else {
                            4_000_000
                        }
                    }
                    Metric::OperationDetails => {
                        if home {
                            800_000
                        } else {
                            8_000_000
                        }
                    }
                };
                for row in [old, new].into_iter().flatten() {
                    need(row.value <= max, "value")?;
                }
            }
        }
        within(self, Self::LIMIT)
    }
}
impl Wire for ServeCandidate {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<(), CodecError> {
        macro_rules! check {
            ($generation:expr,$boot:expr,$writer:expr,$lsn:expr,$digest:expr,$call:expr,$response:expr) => {{
                positive(*$generation, "generation")?;
                fixed($boot, 32, "witness_boot")?;
                fixed($writer, 32, "writer_incarnation")?;
                safe(*$lsn, "primary_lsn")?;
                fixed($digest, 32, "primary_digest")?;
                fixed($call, 32, "call_id")?;
                $response.validate()?;
            }};
        }
        match self {
            Self::Receipt {
                generation,
                witness_boot,
                writer_incarnation,
                primary_lsn,
                primary_digest,
                call_id,
                response,
            }
            | Self::Status {
                generation,
                witness_boot,
                writer_incarnation,
                primary_lsn,
                primary_digest,
                call_id,
                response,
            } => check!(
                generation,
                witness_boot,
                writer_incarnation,
                primary_lsn,
                primary_digest,
                call_id,
                response
            ),
            Self::Resolve {
                generation,
                witness_boot,
                writer_incarnation,
                primary_lsn,
                primary_digest,
                call_id,
                response,
            } => check!(
                generation,
                witness_boot,
                writer_incarnation,
                primary_lsn,
                primary_digest,
                call_id,
                response
            ),
            Self::Refusal {
                generation,
                witness_boot,
                writer_incarnation,
                primary_lsn,
                primary_digest,
                call_id,
                response,
            } => check!(
                generation,
                witness_boot,
                writer_incarnation,
                primary_lsn,
                primary_digest,
                call_id,
                response
            ),
        }
        within(self, Self::LIMIT)
    }
}

/// Body-specific frozen transcript domains reuse the existing custody grammar.
pub trait SigningBody: Wire {
    const DOMAIN: &'static str;
}
macro_rules! signing_body {
    ($ty:ty,$domain:expr) => {
        impl SigningBody for $ty {
            const DOMAIN: &'static str = $domain;
        }
    };
}
signing_body!(UsernameBindingBody, crate::domain::USERNAME_BINDING);
signing_body!(IdentityProfileV2Body, crate::domain::IDENTITY_PROFILE_V2);
signing_body!(UsernameOperationBody, crate::domain::USERNAME_OPERATION);
signing_body!(DirectoryReceiptBody, crate::domain::USERNAME_RECEIPT);
signing_body!(DirectoryResolveBody, crate::domain::USERNAME_RESOLVE);
/// # Errors
/// Rejects invalid bodies; returns the existing E(domain,body) transcript, without signing.
pub fn signing_bytes<T: SigningBody>(body: &T) -> Result<Vec<u8>, CodecError> {
    body.validate()?;
    Ok(crate::custody::signing_bytes(T::DOMAIN, body)?)
}
impl DirectoryCode {
    #[must_use]
    pub const fn requires_retry(self) -> bool {
        matches!(
            self,
            Self::RateLimited
                | Self::Capacity
                | Self::DirectoryUnavailable
                | Self::OperationPending
        )
    }
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::AuthenticationRequired => 401,
            Self::InvalidUsername
            | Self::InvalidProfile
            | Self::InvalidAvatar
            | Self::UnsupportedVersion => 400,
            Self::SignatureInvalid => 403,
            Self::NotFound => 404,
            Self::RateLimited => 429,
            Self::Capacity | Self::DirectoryUnavailable | Self::ClockUnsafe => 503,
            _ => 409,
        }
    }
}
impl DirectoryFailure {
    /// Bounds local hints only. Remote hints are rejected, never clamped, by decode.
    #[must_use]
    pub fn new(code: DirectoryCode, retry_hint_ms: u64) -> Self {
        Self {
            code,
            retry_after_ms: code.requires_retry().then_some(retry_hint_ms.clamp(1000, 60000)),
        }
    }
}

fn strings(v: &serde_json::Value) -> Result<(), CodecError> {
    match v {
        serde_json::Value::String(s) => need(s.len() <= 2048, "string"),
        serde_json::Value::Array(a) => {
            for x in a {
                strings(x)?;
            }
            Ok(())
        }
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                need(k.len() <= 2048, "string")?;
                strings(x)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

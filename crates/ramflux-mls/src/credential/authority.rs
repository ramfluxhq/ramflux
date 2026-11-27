// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device authority: the directory path, the pure record verifier and the removal proofs of a
//! `dm`/`self` commit (card MLS-DM r3 sections 2.4 and 2.5).
//!
//! Two paths, one verifier:
//!
//! * **Directory path** ([`DeviceAuthority`]): the SDK's custody directory answers "what is the
//!   current verified record of this anchor". Used for application messages, own commits,
//!   Welcome / `KeyPackage` checks and display. It may use local knowledge.
//! * **Pure path** ([`verify_record`], [`ProofVerifier`]): every decision on a received commit
//!   (Add, Remove, rejoin) uses only the records the commit carries in its authenticated data
//!   (`rf-dm-aad-v1`), the hash-bound inputs they reference, and the orderer-signed
//!   `accepted_at`. No pins, no I/O, no clock. Every receiver therefore decides identically.
//!   [`verify_record`] wraps `ramflux_crypto::custody::verify_record`; there is no second
//!   verifier.
//!
//! Principle: local knowledge never rejects a commit. A missing hash-bound input (the compacted
//! revocation list, the custodian record) is [`MlsError::ProofInputUnavailable`]: the receiver
//! HOLDS the commit and retries. Only a content mismatch rejects.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use ed25519_dalek::{Signature, VerifyingKey};
use ramflux_protocol::custody::{
    CLOCK_SKEW_SECONDS, CustodyKind, DeviceRef, DeviceSet, Envelope, MAX_RECORD_BYTES, decode_epoch,
};
use ramflux_protocol::domain::MLS_REJOIN_V1;
use ramflux_protocol::message::outer::MAX_COMPLETE_FRAME_BYTES;
use ramflux_protocol::{DeviceSetStatus, decode_base64url};

pub use ramflux_crypto::custody::VerifiedRecord;

use super::VerifiedMember;
use super::device::DEVICE_CAPABILITY;
use crate::MlsError;

/// Tag that opens every commit authenticated data of a `dm`/`self` group.
pub const DM_AAD_TAG: &str = "rf-dm-aad-v1";
/// Most device records one commit carries: one per account anchor (two for a `dm`).
pub const MAX_AAD_RECORDS: usize = 4;
/// Most entries one commit carries (every Add and every Remove, `dm` leaf bound 2 x 50 plus the
/// removed leaves).
pub const MAX_AAD_ENTRIES: usize = 256;
/// Room kept for the commit itself and the frame header inside one federation frame.
pub const AAD_FRAME_HEADROOM: usize = 64 * 1024;
/// Largest encoded commit authenticated data: bounded by the 1 MiB frame, not by a per-entry cap.
/// A proof that would exceed it is sent as a `replace` built from the directory path instead.
pub const DM_AAD_MAX_BYTES: usize = MAX_COMPLETE_FRAME_BYTES - AAD_FRAME_HEADROOM;
/// A rejoin signed at epoch `E` is valid for commits at epochs `E ..= E + REJOIN_EPOCH_WINDOW`.
pub const REJOIN_EPOCH_WINDOW: u64 = 8;
/// The committer accepts a rejoin whose `issued_at` is within this many seconds of its clock.
pub const REJOIN_COMMITTER_FRESH_SECS: u64 = 600;
/// A key-mismatch removal needs the proving record to be at least this old (24 h).
pub const KEY_MISMATCH_GRACE_SECS: u64 = 24 * 3600;
/// The committer submits a lease-expiry removal only this long after the deadline (margin for the
/// difference to the orderer's clock).
pub const LEASE_EXPIRED_COMMITTER_MARGIN_SECS: u64 = 300;

const NO_RECORD: u8 = 0xFF;

fn reject(what: &str) -> MlsError {
    MlsError::CredentialRejected(what.to_owned())
}

fn policy(what: &str) -> MlsError {
    MlsError::PolicyRejected(what.to_owned())
}

// ---------------------------------------------------------------- directory path

/// The directory path: the current verified record of an account anchor, if the directory has one.
///
/// `anchor` is the UTF-8 of the canonical base64url account anchor.
pub trait DeviceAuthority: Send + Sync {
    /// The current verified head record of `anchor`, or `None` when it is unknown.
    fn current(&self, anchor: &[u8]) -> Option<VerifiedRecord>;
}

/// The default authority: knows nothing, so every device credential answers `authority_needed`.
pub struct NoAuthority;

impl DeviceAuthority for NoAuthority {
    fn current(&self, _anchor: &[u8]) -> Option<VerifiedRecord> {
        None
    }
}

// ---------------------------------------------------------------- pure verifier

/// What a record references besides itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordNeeds {
    /// `list_hash` of the signed revocation checkpoint: the compacted id list must be fetched by
    /// this hash and passed to [`verify_record`].
    pub compacted_list_hash: Option<String>,
    /// The record belongs to an `ExternalHuman` account: the human custodian's record is needed.
    pub custodian_record: bool,
}

fn parse_record(record_bytes: &[u8]) -> Result<Envelope<DeviceSet>, MlsError> {
    if record_bytes.len() > MAX_RECORD_BYTES {
        return Err(MlsError::TooLarge(format!(
            "device record {} bytes, cap {MAX_RECORD_BYTES}",
            record_bytes.len()
        )));
    }
    Envelope::<DeviceSet>::from_wire_bytes(record_bytes)
        .map_err(|error| reject(&format!("device record: {error}")))
}

/// Which inputs besides the record bytes the verifier needs, so the caller can fetch them by hash
/// before it calls [`verify_record`] (or hold the commit while they are missing).
///
/// # Errors
/// The record is oversized or malformed.
pub fn record_needs(record_bytes: &[u8]) -> Result<RecordNeeds, MlsError> {
    let envelope = parse_record(record_bytes)?;
    Ok(RecordNeeds {
        compacted_list_hash: envelope
            .body
            .revoked_device_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.body.list_hash.clone()),
        custodian_record: envelope.body.master_certificate.body.custody_kind
            == CustodyKind::ExternalHuman,
    })
}

/// Verify a device record carried in a commit. Pure: no pins, no I/O, no side effects; it wraps
/// the one custody verifier (`ramflux_crypto::custody::verify_record`).
///
/// * `anchor`: UTF-8 of the account anchor the record must belong to.
/// * `compacted_ids`: the compacted revocation list (fetched by the checkpoint's `list_hash`);
///   required when the record has a signed checkpoint.
/// * `custodian_record`: the human custodian's record bytes; required for an `ExternalHuman`
///   account.
/// * `at_epoch`: the record must be at least this new (`record.device_set_epoch >= at_epoch`).
/// * `now`: the time of the decision, `ctx.accepted_at`.
///
/// # Errors
/// [`MlsError::ProofInputUnavailable`] when a required input is missing (the caller holds and
/// retries, it never rejects on this), [`MlsError::TooLarge`] for an oversized record, and
/// [`MlsError::CredentialRejected`] for any content mismatch.
pub fn verify_record(
    anchor: &[u8],
    record_bytes: &[u8],
    compacted_ids: Option<&[String]>,
    custodian_record: Option<&[u8]>,
    at_epoch: u64,
    now: u64,
) -> Result<VerifiedRecord, MlsError> {
    let envelope = parse_record(record_bytes)?;
    let body = &envelope.body;
    if body.account_anchor.as_bytes() != anchor {
        return Err(reject("record belongs to another account anchor"));
    }
    if body.device_set_epoch < at_epoch {
        return Err(reject("record is older than the epoch the proof needs"));
    }
    if let Some(checkpoint) = &body.revoked_device_checkpoint
        && compacted_ids.is_none()
    {
        return Err(MlsError::ProofInputUnavailable(format!(
            "compacted revocation list {}",
            checkpoint.body.list_hash
        )));
    }
    let custodian = if body.master_certificate.body.custody_kind == CustodyKind::ExternalHuman {
        let bytes = custodian_record
            .ok_or_else(|| MlsError::ProofInputUnavailable("human custodian record".to_owned()))?;
        let custodian_envelope = parse_record(bytes)?;
        let custodian_needs_list = custodian_envelope.body.revoked_device_checkpoint.is_some();
        if custodian_needs_list {
            return Err(MlsError::ProofInputUnavailable(
                "compacted revocation list of the custodian".to_owned(),
            ));
        }
        Some(
            ramflux_crypto::custody::verify_record(&custodian_envelope, now, None, None)
                .map_err(|error| reject(&format!("custodian record: {error}")))?,
        )
    } else {
        None
    };
    ramflux_crypto::custody::verify_record(&envelope, now, compacted_ids, custodian.as_ref())
        .map_err(|error| reject(&format!("device record: {error}")))
}

/// The hash-bound inputs of a removal proof, supplied from local caches (never fetched here).
pub trait ProofSource {
    /// The compacted revocation id list whose `list_hash` is `list_hash`.
    fn compacted_ids(&self, list_hash: &str) -> Option<Vec<String>>;
    /// The current human custodian record of an `ExternalHuman` account anchor.
    fn custodian_record(&self, anchor: &[u8]) -> Option<Vec<u8>>;
}

/// A source with no cached inputs: every proof that needs one is held.
pub struct NoProofSource;

impl ProofSource for NoProofSource {
    fn compacted_ids(&self, _list_hash: &str) -> Option<Vec<String>> {
        None
    }

    fn custodian_record(&self, _anchor: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

// ---------------------------------------------------------------- AAD codec

/// Ground of a removal, as one byte in the authenticated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ground {
    /// G1: the removed principal is the committer's own.
    Own,
    /// G2: a newer record shows the device revoked or absent.
    Revoked,
    /// G3: the record shows the device's lease expired at `accepted_at`.
    LeaseExpired,
    /// G4: a newer record shows another leased key for the device.
    KeyMismatch,
    /// G5: the same commit adds a successor of the device, proven by its rejoin.
    Rejoin,
}

impl Ground {
    fn code(self) -> u8 {
        match self {
            Self::Own => 1,
            Self::Revoked => 2,
            Self::LeaseExpired => 3,
            Self::KeyMismatch => 4,
            Self::Rejoin => 5,
        }
    }

    fn from_code(code: u8) -> Result<Option<Self>, MlsError> {
        match code {
            0 => Ok(None),
            1 => Ok(Some(Self::Own)),
            2 => Ok(Some(Self::Revoked)),
            3 => Ok(Some(Self::LeaseExpired)),
            4 => Ok(Some(Self::KeyMismatch)),
            5 => Ok(Some(Self::Rejoin)),
            _ => Err(policy("unknown removal ground")),
        }
    }
}

/// A device's signed request to be re-added after it lost its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejoinProof {
    /// Signature of the successor's device signing key over [`rejoin_message`].
    pub sig: [u8; 64],
    /// Hash of the successor's `KeyPackage`.
    pub kp_hash: [u8; 32],
    /// MLS epoch the device read with `fetch{status}` when it signed.
    pub epoch: u64,
    /// Seconds timestamp; only the committer looks at it.
    pub issued_at: u64,
}

/// The bytes a rejoin signs: `MLS_REJOIN_V1 || group_id || kp_hash || u64 epoch || u64 issued_at`.
#[must_use]
pub fn rejoin_message(group_id: &[u8], kp_hash: &[u8; 32], epoch: u64, issued_at: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(MLS_REJOIN_V1.len() + group_id.len() + 32 + 16);
    message.extend_from_slice(MLS_REJOIN_V1.as_bytes());
    message.extend_from_slice(group_id);
    message.extend_from_slice(kp_hash);
    message.extend_from_slice(&epoch.to_be_bytes());
    message.extend_from_slice(&issued_at.to_be_bytes());
    message
}

/// Verify a rejoin signature under the successor's device signing key. Pure.
///
/// # Errors
/// [`MlsError::CredentialRejected`] for a weak key or a bad signature.
pub fn verify_rejoin_signature(
    device_signing_pk: &[u8; 32],
    group_id: &[u8],
    rejoin: &RejoinProof,
) -> Result<(), MlsError> {
    let key = VerifyingKey::from_bytes(device_signing_pk)
        .map_err(|_| reject("rejoin device signing key"))?;
    if key.is_weak() {
        return Err(reject("rejoin device signing key is weak"));
    }
    key.verify_strict(
        &rejoin_message(group_id, &rejoin.kp_hash, rejoin.epoch, rejoin.issued_at),
        &Signature::from_bytes(&rejoin.sig),
    )
    .map_err(|_| reject("rejoin signature"))
}

/// The epoch window every receiver applies: `rejoin.epoch <= commit_epoch <= rejoin.epoch + 8`.
/// No clock is involved.
///
/// # Errors
/// [`MlsError::PolicyRejected`] when the commit epoch is outside the window.
pub fn check_rejoin_epoch(rejoin: &RejoinProof, commit_epoch: u64) -> Result<(), MlsError> {
    if rejoin.epoch <= commit_epoch
        && commit_epoch <= rejoin.epoch.saturating_add(REJOIN_EPOCH_WINDOW)
    {
        Ok(())
    } else {
        Err(policy("rejoin is outside its epoch window"))
    }
}

/// The committer-only freshness check (`|own_now - issued_at| <= 600 s`). Receivers never run it.
///
/// # Errors
/// [`MlsError::PolicyRejected`] when the rejoin is stale or from the future.
pub fn check_rejoin_committer_fresh(rejoin: &RejoinProof, own_now: u64) -> Result<(), MlsError> {
    if own_now.abs_diff(rejoin.issued_at) <= REJOIN_COMMITTER_FRESH_SECS {
        Ok(())
    } else {
        Err(policy("rejoin is stale"))
    }
}

/// One proof entry of the authenticated data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AadEntry {
    /// An added `KeyPackage` hash (32 bytes) or a removed leaf index (4 bytes, big endian).
    pub leaf_ref: Vec<u8>,
    /// `None` for an Add entry, the ground for a Remove entry.
    pub ground: Option<Ground>,
    /// Index into [`DmAad::records`] of the account record that proves the entry.
    pub record_index: Option<u8>,
    /// The rejoin of a G5 removal.
    pub rejoin: Option<RejoinProof>,
}

impl AadEntry {
    /// An Add entry for the `KeyPackage` with this hash, proven by `records[record_index]`.
    #[must_use]
    pub fn add(kp_hash: [u8; 32], record_index: u8) -> Self {
        Self {
            leaf_ref: kp_hash.to_vec(),
            ground: None,
            record_index: Some(record_index),
            rejoin: None,
        }
    }

    /// A Remove entry for the leaf at `leaf_index`.
    #[must_use]
    pub fn remove(
        leaf_index: u32,
        ground: Ground,
        record_index: Option<u8>,
        rejoin: Option<RejoinProof>,
    ) -> Self {
        Self {
            leaf_ref: leaf_index.to_be_bytes().to_vec(),
            ground: Some(ground),
            record_index,
            rejoin,
        }
    }
}

/// Commit authenticated data `rf-dm-aad-v1`: one record per account anchor (M3: a large record
/// is carried once, never once per device) and the entries that point into it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DmAad {
    /// Device records, at most one per anchor, each at most `MAX_RECORD_BYTES`.
    pub records: Vec<Vec<u8>>,
    /// Entries, one per added `KeyPackage` and one per removed leaf.
    pub entries: Vec<AadEntry>,
}

impl DmAad {
    /// Encode. Empty for a pure Update (no records, no entries): the caller sends no AAD then.
    ///
    /// # Errors
    /// [`MlsError::TooLarge`] when a bound is exceeded (the proof then goes by `replace`).
    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        if self.records.len() > MAX_AAD_RECORDS || self.entries.len() > MAX_AAD_ENTRIES {
            return Err(MlsError::TooLarge("commit proof has too many records or entries".into()));
        }
        let mut out = DM_AAD_TAG.as_bytes().to_vec();
        out.push(u8::try_from(self.records.len()).map_err(|_| policy("record count"))?);
        for record in &self.records {
            if record.len() > MAX_RECORD_BYTES {
                return Err(MlsError::TooLarge("device record exceeds its cap".into()));
            }
            let len = u32::try_from(record.len()).map_err(|_| policy("record length"))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(record);
        }
        let count = u16::try_from(self.entries.len()).map_err(|_| policy("entry count"))?;
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            out.push(entry.ground.map_or(0, Ground::code));
            out.push(u8::try_from(entry.leaf_ref.len()).map_err(|_| policy("leaf ref length"))?);
            out.extend_from_slice(&entry.leaf_ref);
            out.push(entry.record_index.unwrap_or(NO_RECORD));
            match &entry.rejoin {
                None => out.push(0),
                Some(rejoin) => {
                    out.push(1);
                    out.extend_from_slice(&rejoin.sig);
                    out.extend_from_slice(&rejoin.kp_hash);
                    out.extend_from_slice(&rejoin.epoch.to_be_bytes());
                    out.extend_from_slice(&rejoin.issued_at.to_be_bytes());
                }
            }
        }
        if out.len() > DM_AAD_MAX_BYTES {
            return Err(MlsError::TooLarge(format!(
                "commit proof {} bytes, cap {DM_AAD_MAX_BYTES}",
                out.len()
            )));
        }
        Ok(out)
    }

    /// Strict, bounded decode: tag, structure and bounds are checked before anything is
    /// allocated from a length field; no trailing bytes.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] or [`MlsError::TooLarge`] for any malformed or oversized input.
    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        if bytes.len() > DM_AAD_MAX_BYTES {
            return Err(MlsError::TooLarge(format!(
                "commit proof {} bytes, cap {DM_AAD_MAX_BYTES}",
                bytes.len()
            )));
        }
        let mut reader = Reader { rest: bytes };
        if reader.take(DM_AAD_TAG.len())? != DM_AAD_TAG.as_bytes() {
            return Err(policy("commit proof tag"));
        }
        let record_count = usize::from(reader.u8()?);
        if record_count > MAX_AAD_RECORDS {
            return Err(policy("too many records"));
        }
        let mut records = Vec::new();
        for _ in 0..record_count {
            let len = usize::try_from(reader.u32()?).map_err(|_| policy("record length"))?;
            if len > MAX_RECORD_BYTES {
                return Err(MlsError::TooLarge("device record exceeds its cap".into()));
            }
            records.push(reader.take(len)?.to_vec());
        }
        let entry_count = usize::from(reader.u16()?);
        if entry_count > MAX_AAD_ENTRIES {
            return Err(policy("too many entries"));
        }
        let mut entries = Vec::new();
        for _ in 0..entry_count {
            let ground = Ground::from_code(reader.u8()?)?;
            let ref_len = usize::from(reader.u8()?);
            let leaf_ref = reader.take(ref_len)?.to_vec();
            let record_index = match reader.u8()? {
                NO_RECORD => None,
                index if usize::from(index) < record_count => Some(index),
                _ => return Err(policy("record index out of range")),
            };
            let rejoin = match reader.u8()? {
                0 => None,
                1 => Some(RejoinProof {
                    sig: reader.array::<64>()?,
                    kp_hash: reader.array::<32>()?,
                    epoch: u64::from_be_bytes(reader.array::<8>()?),
                    issued_at: u64::from_be_bytes(reader.array::<8>()?),
                }),
                _ => return Err(policy("rejoin flag")),
            };
            let well_formed = match ground {
                None => leaf_ref.len() == 32 && record_index.is_some() && rejoin.is_none(),
                Some(Ground::Own) => {
                    leaf_ref.len() == 4 && record_index.is_none() && rejoin.is_none()
                }
                Some(Ground::Rejoin) => {
                    leaf_ref.len() == 4 && record_index.is_none() && rejoin.is_some()
                }
                Some(_) => leaf_ref.len() == 4 && record_index.is_some() && rejoin.is_none(),
            };
            if !well_formed {
                return Err(policy("malformed proof entry"));
            }
            entries.push(AadEntry { leaf_ref, ground, record_index, rejoin });
        }
        if !reader.rest.is_empty() {
            return Err(policy("trailing bytes in the commit proof"));
        }
        Ok(Self { records, entries })
    }
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], MlsError> {
        let (head, rest) =
            self.rest.split_at_checked(len).ok_or_else(|| policy("truncated commit proof"))?;
        self.rest = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], MlsError> {
        self.take(N)?.try_into().map_err(|_| policy("truncated commit proof"))
    }

    fn u8(&mut self) -> Result<u8, MlsError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, MlsError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, MlsError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }
}

// ---------------------------------------------------------------- pure predicates

/// Pure removal-proof checks over one commit's authenticated data (G1-G5, Add records).
///
/// Inputs: the decoded AAD, the hash-bound input source, `now = ctx.accepted_at`. Nothing else.
pub struct ProofVerifier<'a> {
    aad: &'a DmAad,
    source: &'a dyn ProofSource,
    now: u64,
    range_floor: BTreeMap<String, u64>,
    cache: RefCell<BTreeMap<u8, Rc<VerifiedRecord>>>,
}

impl<'a> ProofVerifier<'a> {
    /// A verifier for one commit decided at `now` (the orderer-signed `accepted_at`).
    #[must_use]
    pub fn new(aad: &'a DmAad, source: &'a dyn ProofSource, now: u64) -> Self {
        Self {
            aad,
            source,
            now,
            range_floor: BTreeMap::new(),
            cache: RefCell::new(BTreeMap::new()),
        }
    }

    /// Refuse records whose custody range is below the highest range already present in the
    /// tree's credentials for that anchor (a retired, compromised self-signing key cannot be
    /// replayed through an insider committer).
    ///
    /// # Errors
    /// A credential names an unsafe epoch.
    pub fn with_tree(mut self, members: &[VerifiedMember]) -> Result<Self, MlsError> {
        for member in members {
            let (range, _) = decode_epoch(member.device_set_epoch)
                .map_err(|_| reject("credential device-set epoch"))?;
            let floor = self.range_floor.entry(member.root_commitment.clone()).or_insert(0);
            *floor = (*floor).max(range);
        }
        Ok(self)
    }

    /// The verified record of an entry. One record per anchor is carried, so it is verified once.
    fn record(&self, index: u8, anchor: &str) -> Result<Rc<VerifiedRecord>, MlsError> {
        if let Some(hit) = self
            .cache
            .try_borrow()
            .map_err(|_| MlsError::internal("proof cache borrowed"))?
            .get(&index)
        {
            if hit.envelope().body.account_anchor != anchor {
                return Err(reject("one record serves two anchors"));
            }
            return Ok(Rc::clone(hit));
        }
        let bytes = self
            .aad
            .records
            .get(usize::from(index))
            .ok_or_else(|| policy("record index out of range"))?;
        let needs = record_needs(bytes)?;
        let compacted = match &needs.compacted_list_hash {
            Some(hash) => Some(self.source.compacted_ids(hash).ok_or_else(|| {
                MlsError::ProofInputUnavailable(format!("compacted revocation list {hash}"))
            })?),
            None => None,
        };
        let custodian = if needs.custodian_record {
            Some(self.source.custodian_record(anchor.as_bytes()).ok_or_else(|| {
                MlsError::ProofInputUnavailable("human custodian record".to_owned())
            })?)
        } else {
            None
        };
        let verified = Rc::new(verify_record(
            anchor.as_bytes(),
            bytes,
            compacted.as_deref(),
            custodian.as_deref(),
            0,
            self.now,
        )?);
        if let Some(floor) = self.range_floor.get(anchor) {
            let (range, _) = decode_epoch(verified.envelope().body.device_set_epoch)
                .map_err(|_| reject("record device-set epoch"))?;
            if range < *floor {
                return Err(reject("record range is below the range already in the tree"));
            }
        }
        self.cache
            .try_borrow_mut()
            .map_err(|_| MlsError::internal("proof cache borrowed"))?
            .insert(index, Rc::clone(&verified));
        Ok(verified)
    }

    fn entry_record(
        &self,
        entry: &AadEntry,
        member: &VerifiedMember,
    ) -> Result<Rc<VerifiedRecord>, MlsError> {
        let index = entry.record_index.ok_or_else(|| policy("entry has no record"))?;
        self.record(index, &member.root_commitment)
    }

    /// `may_add`: one entry for the added `KeyPackage`, a record at least as new as the
    /// credential showing the device Active, leased at `accepted_at` (`deadline + skew >=
    /// accepted_at`) with the leased branch key equal to the credential's device key.
    ///
    /// # Errors
    /// [`MlsError::ProofInputUnavailable`] to hold; otherwise a typed rejection.
    pub fn check_add(&self, added: &VerifiedMember) -> Result<(), MlsError> {
        let kp_hash = added
            .kp_hash
            .ok_or_else(|| MlsError::internal("added member has no key package hash"))?;
        let entry = self.add_entry(&kp_hash)?;
        let record = self.entry_record(entry, added)?;
        if record.envelope().body.device_set_epoch < added.device_set_epoch {
            return Err(reject("record is older than the credential"));
        }
        let reference = reference(added);
        let probe = self.now.saturating_sub(CLOCK_SKEW_SECONDS);
        let deadline = record
            .authorization_deadline(&reference, DEVICE_CAPABILITY, probe)
            .map_err(|error| reject(&format!("added device lease: {error}")))?;
        if deadline.saturating_add(CLOCK_SKEW_SECONDS) < self.now {
            return Err(reject("added device lease expired"));
        }
        let cert = record
            .authorize(&reference, DEVICE_CAPABILITY, probe)
            .map_err(|error| reject(&format!("added device lease: {error}")))?;
        if decode_base64url(&cert.branch_signing_public_key).ok().as_deref()
            != Some(added.device_signing_pk.as_slice())
        {
            return Err(reject("added device key is not the leased branch key"));
        }
        Ok(())
    }

    fn add_entry(&self, kp_hash: &[u8; 32]) -> Result<&AadEntry, MlsError> {
        self.aad
            .entries
            .iter()
            .find(|entry| entry.ground.is_none() && entry.leaf_ref == kp_hash.as_slice())
            .ok_or_else(|| policy("no proof entry for the added key package"))
    }

    fn remove_entry(&self, leaf_index: u32) -> Result<&AadEntry, MlsError> {
        let wanted = leaf_index.to_be_bytes();
        self.aad
            .entries
            .iter()
            .find(|entry| entry.ground.is_some() && entry.leaf_ref == wanted.as_slice())
            .ok_or_else(|| policy("no proof entry for the removed leaf"))
    }

    /// `may_remove`: exactly one ground proven by the entry. Returns the ground.
    ///
    /// `added` are the members the same commit adds (needed by G5); `commit_epoch` is
    /// `ctx.epoch`; `group_id` is the group the rejoin was signed for.
    ///
    /// # Errors
    /// [`MlsError::ProofInputUnavailable`] to hold; otherwise a typed rejection.
    pub fn check_remove(
        &self,
        group_id: &[u8],
        commit_epoch: u64,
        committer: &VerifiedMember,
        removed: &VerifiedMember,
        added: &[VerifiedMember],
    ) -> Result<Ground, MlsError> {
        let leaf = removed
            .leaf_index
            .ok_or_else(|| MlsError::internal("removed member has no leaf index"))?;
        let entry = self.remove_entry(leaf)?;
        let ground =
            entry.ground.ok_or_else(|| MlsError::internal("remove entry has no ground"))?;
        match ground {
            Ground::Own => {
                if removed.root_commitment != committer.root_commitment {
                    return Err(policy("own-device removal of another principal"));
                }
            }
            Ground::Revoked => {
                let record = self.entry_record(entry, removed)?;
                if record.envelope().body.device_set_epoch <= removed.device_set_epoch {
                    return Err(reject("record is not newer than the removed credential"));
                }
                let device = find_device(&record, &removed.device_id);
                let revoked = record.revoked_ids().contains(&removed.device_id)
                    || device.is_none_or(|device| device.status != DeviceSetStatus::Active);
                if !revoked {
                    return Err(reject("record does not show the device revoked"));
                }
            }
            Ground::LeaseExpired => {
                let record = self.entry_record(entry, removed)?;
                if record.envelope().body.device_set_epoch < removed.device_set_epoch {
                    return Err(reject("record is older than the removed credential"));
                }
                let deadline = lease_deadline(&record, removed)?;
                if deadline.saturating_add(CLOCK_SKEW_SECONDS) >= self.now {
                    return Err(reject("the device lease has not expired"));
                }
            }
            Ground::KeyMismatch => {
                let record = self.entry_record(entry, removed)?;
                let body = &record.envelope().body;
                if body.device_set_epoch <= removed.device_set_epoch {
                    return Err(reject("record is not newer than the removed credential"));
                }
                let device = find_device(&record, &removed.device_id)
                    .filter(|device| {
                        device.status == DeviceSetStatus::Active
                            && !record.revoked_ids().contains(&removed.device_id)
                    })
                    .ok_or_else(|| reject("record does not show the device active"))?;
                let leased = device
                    .branch_certificate
                    .as_ref()
                    .and_then(|cert| decode_base64url(&cert.body.branch_signing_public_key).ok())
                    .ok_or_else(|| reject("record has no leased key for the device"))?;
                if leased.as_slice() == removed.device_signing_pk.as_slice() {
                    return Err(reject("the leased key is the leaf's key"));
                }
                if body.issued_at.saturating_add(KEY_MISMATCH_GRACE_SECS) >= self.now {
                    return Err(reject("the key change is too recent to remove"));
                }
            }
            Ground::Rejoin => {
                self.check_rejoin_removal(entry, group_id, commit_epoch, removed, added)?
            }
        }
        Ok(ground)
    }

    fn check_rejoin_removal(
        &self,
        entry: &AadEntry,
        group_id: &[u8],
        commit_epoch: u64,
        removed: &VerifiedMember,
        added: &[VerifiedMember],
    ) -> Result<(), MlsError> {
        let rejoin =
            entry.rejoin.as_ref().ok_or_else(|| policy("rejoin entry carries no rejoin"))?;
        let successor = added
            .iter()
            .find(|candidate| {
                candidate.root_commitment == removed.root_commitment
                    && candidate.device_id == removed.device_id
                    && candidate.kp_hash == Some(rejoin.kp_hash)
            })
            .ok_or_else(|| policy("the commit does not add the rejoining device"))?;
        if successor.device_epoch < removed.device_epoch {
            return Err(reject("successor has an older device epoch"));
        }
        self.check_add(successor)?;
        verify_rejoin_signature(&successor.device_signing_pk, group_id, rejoin)?;
        check_rejoin_epoch(rejoin, commit_epoch)
    }

    /// `check_delta`: every Remove has exactly one entry and every Add exactly one, no extra and
    /// no duplicate entries, no unused record.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] when the entries do not match the commit.
    pub fn check_delta(
        &self,
        added: &[VerifiedMember],
        removed: &[VerifiedMember],
    ) -> Result<(), MlsError> {
        let add_entries = self.aad.entries.iter().filter(|entry| entry.ground.is_none()).count();
        let remove_entries = self.aad.entries.len() - add_entries;
        if add_entries != added.len() || remove_entries != removed.len() {
            return Err(policy("proof entries do not match the commit"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for entry in &self.aad.entries {
            if !seen.insert((entry.ground.is_none(), entry.leaf_ref.clone())) {
                return Err(policy("duplicate proof entry"));
            }
        }
        for member in added {
            let kp_hash = member
                .kp_hash
                .ok_or_else(|| MlsError::internal("added member has no key package hash"))?;
            self.add_entry(&kp_hash)?;
        }
        for member in removed {
            let leaf = member
                .leaf_index
                .ok_or_else(|| MlsError::internal("removed member has no leaf index"))?;
            self.remove_entry(leaf)?;
        }
        for index in 0..self.aad.records.len() {
            let used = self
                .aad
                .entries
                .iter()
                .any(|entry| entry.record_index.is_some_and(|at| usize::from(at) == index));
            if !used {
                return Err(policy("unused record in the commit proof"));
            }
        }
        Ok(())
    }
}

fn reference(member: &VerifiedMember) -> DeviceRef {
    DeviceRef {
        account_anchor: member.root_commitment.clone(),
        device_id: member.device_id.clone(),
        device_epoch: member.device_epoch,
    }
}

fn find_device<'r>(
    record: &'r VerifiedRecord,
    device_id: &str,
) -> Option<&'r ramflux_protocol::custody::Device> {
    record.envelope().body.devices.iter().find(|device| device.device_id == device_id)
}

/// Latest instant the record accepts the device's `message` lease (including skew). The record is
/// asked at the lease's own start, so an already expired lease still yields its deadline.
fn lease_deadline(record: &VerifiedRecord, member: &VerifiedMember) -> Result<u64, MlsError> {
    let device = find_device(record, &member.device_id)
        .filter(|device| {
            device.status == DeviceSetStatus::Active && device.device_epoch == member.device_epoch
        })
        .ok_or_else(|| reject("record does not show the device active"))?;
    let not_before = device
        .branch_certificate
        .as_ref()
        .map(|cert| cert.body.not_before)
        .ok_or_else(|| reject("record has no lease for the device"))?;
    record
        .authorization_deadline(&reference(member), DEVICE_CAPABILITY, not_before)
        .map_err(|error| reject(&format!("device lease: {error}")))
}

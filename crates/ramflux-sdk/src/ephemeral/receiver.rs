// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded in-memory ephemeral receiver channel, dedup, generation lock, I-LED.

use super::lifetime::{
    HoldLease, ReceiverClock, ReceiverDropReason, ReceiverLifetime, admit_authenticated_ciphertext,
    authenticate, poll_stored_hold,
};
use ramflux_protocol::Envelope;
use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

/// Inclusive channel frame cap, including the in-flight write and held frames.
pub const RECEIVER_CHANNEL_FRAMES: usize = 64;
/// Inclusive channel byte cap, including the in-flight write and held frames.
pub const RECEIVER_CHANNEL_BYTES: usize = 262_144;
/// Inclusive live dedup bound.
pub const RECEIVER_DEDUP_BOUND: usize = 4_096;
/// Bytes of one stored `(key, payload hash, D)` tuple.
pub const RECEIVER_DEDUP_ENTRY_BYTES: usize = 32 + 32 + 8;
/// Inclusive retained-tuple budget at [`RECEIVER_DEDUP_BOUND`].
pub const RECEIVER_DEDUP_BUDGET_BYTES: usize = RECEIVER_DEDUP_BOUND * RECEIVER_DEDUP_ENTRY_BYTES;
/// Inclusive whole-frame cap for one complete received frame.
pub const RECEIVER_MAX_FRAME_BYTES: usize = 32_768;

const TEST_POLL_RETRY_METADATA: u8 = 1 << 0;
const TEST_SIZE_RESERIALIZED: u8 = 1 << 1;
const TEST_SKIP_START_RECHECK: u8 = 1 << 2;
const TEST_SKIP_DEADLINE_COMPARE: u8 = 1 << 3;

/// Outcome of admitting one authenticated ephemeral envelope into the receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiverAdmit {
    Displayed { expires_at_ms: u64 },
    Held(HoldLease),
    Duplicate,
    HashConflict,
    DroppedNew,
    DroppedLocked,
    Expired,
    Drop(ReceiverDropReason),
}

/// Terminal dequeue of one queued ciphertext: delivered, dropped, or empty.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiverDequeue {
    Delivered { bytes: Vec<u8>, expires_at_ms: u64 },
    Dropped(ReceiverDropReason),
    Empty,
}

/// S6b ledger effects the receiver must never produce (I-LED).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LedgerProbe {
    pub w0: u64,
    pub receipt: u64,
    pub ack: u64,
    pub offered_coverage: u64,
}

#[derive(Deserialize)]
struct CompleteReceivedFrame {
    frame_type: String,
    envelope: Envelope,
    expires_at_ms: u64,
}

#[cfg(test)]
#[derive(Serialize)]
struct CompleteReceivedFrameRef<'a> {
    frame_type: &'static str,
    envelope: &'a Envelope,
    expires_at_ms: u64,
}

struct DedupEntry {
    payload_hash: [u8; 32],
    expires_at_ms: u64,
}

struct ChannelEntry {
    digest: [u8; 32],
    bytes: Vec<u8>,
    created_at: i64,
    expires_at_ms: u64,
}

struct HeldEntry {
    created_at: i64,
    ttl_seconds: u32,
    expires_at_ms: u64,
    lease: HoldLease,
    payload: [u8; 32],
    bytes: Vec<u8>,
}

/// Volatile receiver: channel, holds and dedup. Nothing is journaled or backed up.
#[derive(Default)]
pub struct EphemeralReceiver {
    generation: u64,
    locked: bool,
    channel: VecDeque<ChannelEntry>,
    inflight: Option<ChannelEntry>,
    channel_bytes: usize,
    dedup: HashMap<[u8; 32], DedupEntry>,
    holds: HashMap<[u8; 32], HeldEntry>,
    ledger: LedgerProbe,
    #[cfg(test)]
    test_flags: u8,
}

fn digest_key(source_device_id: &str, envelope_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("ramflux.ephemeral.receiver.dedup.v1");
    for part in [source_device_id, envelope_id] {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_be_bytes());
        hasher.update(part.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn payload_digest(payload_hash: &str) -> [u8; 32] {
    *blake3::hash(payload_hash.as_bytes()).as_bytes()
}

#[cfg(test)]
fn encode_complete_frame(envelope: &Envelope, expires_at_ms: u64) -> Option<Vec<u8>> {
    serde_json::to_vec(&CompleteReceivedFrameRef {
        frame_type: "ephemeral",
        envelope,
        expires_at_ms,
    })
    .ok()
}

impl EphemeralReceiver {
    /// Empty receiver at generation 0, unlocked.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current S2 generation. A bump drops channel, holds and dedup.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// I-LED: always the zero probe. Admission never records W0, receipt, ACK or coverage.
    #[must_use]
    pub fn ledger_probe(&self) -> LedgerProbe {
        self.ledger
    }

    /// Offered S6b coverage. Ephemeral frames never move it.
    #[must_use]
    pub fn offered_coverage(&self) -> u64 {
        0
    }

    /// Channel occupancy including the in-flight write and held frames: `(frames, bytes)`.
    #[must_use]
    pub fn occupancy(&self) -> (usize, usize) {
        (self.frame_occupancy(), self.channel_bytes)
    }

    /// Live dedup occupancy.
    #[must_use]
    pub fn dedup_len(&self) -> usize {
        self.dedup.len()
    }

    /// Live hold occupancy.
    #[must_use]
    pub fn hold_len(&self) -> usize {
        self.holds.len()
    }

    /// Drop channel, holds and dedup, then refuse further admits until [`Self::unlock`].
    pub fn lock(&mut self) {
        self.clear_transient();
        self.locked = true;
    }

    /// Clear the lock flag. Held and queued frames are not replayed.
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// S2 generation bump: drop channel, holds and dedup, then lock.
    pub fn bump_generation(&mut self) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.lock();
        self.generation
    }

    /// Admit one complete received-frame byte vector under injected clocks.
    ///
    /// Size and aggregate occupancy use the original byte length. Decode and
    /// authentication run on those same bytes; retained state is those bytes
    /// plus the envelope's own authenticated metadata.
    pub fn admit(
        &mut self,
        bytes: &[u8],
        clock: ReceiverClock,
        expected_source_principal_id: &str,
        signing_public_key: &str,
    ) -> ReceiverAdmit {
        self.expire_due(clock);
        if self.locked {
            return ReceiverAdmit::DroppedLocked;
        }
        if !self.sizes_reserialized() && bytes.len() > RECEIVER_MAX_FRAME_BYTES {
            return ReceiverAdmit::DroppedNew;
        }
        let frame = match serde_json::from_slice::<CompleteReceivedFrame>(bytes) {
            Ok(frame) if frame.frame_type == "ephemeral" => frame,
            _ => return ReceiverAdmit::Drop(ReceiverDropReason::InvalidDeliveryMode),
        };
        let counted = self.counted_frame_len(bytes, &frame.envelope, frame.expires_at_ms);
        if counted > RECEIVER_MAX_FRAME_BYTES {
            return ReceiverAdmit::DroppedNew;
        }
        let ciphertext =
            match authenticate(&frame.envelope, expected_source_principal_id, signing_public_key) {
                Ok(ciphertext) => ciphertext,
                Err(reason) => return ReceiverAdmit::Drop(reason),
            };
        let envelope = ciphertext.envelope();
        let digest = digest_key(&envelope.source_device_id, &envelope.envelope_id);
        let payload = payload_digest(&envelope.payload_hash);
        if let Some(held) = self.holds.get(&digest) {
            if held.payload != payload {
                return ReceiverAdmit::HashConflict;
            }
            let lease = held.lease;
            let retry_poll = self.polls_retry_metadata();
            if retry_poll {
                let handoff = admit_authenticated_ciphertext(&ciphertext, clock, Some(lease));
                return self.finish_held(digest, payload, handoff.lifetime);
            }
            return ReceiverAdmit::Duplicate;
        }
        if let Some(existing) = self.dedup.get(&digest) {
            if existing.payload_hash != payload {
                return ReceiverAdmit::HashConflict;
            }
            return ReceiverAdmit::Duplicate;
        }
        let handoff = admit_authenticated_ciphertext(&ciphertext, clock, None);
        match handoff.lifetime {
            ReceiverLifetime::Drop(ReceiverDropReason::Expired) => ReceiverAdmit::Expired,
            ReceiverLifetime::Drop(reason) => ReceiverAdmit::Drop(reason),
            ReceiverLifetime::Hold(lease) => {
                if self.deadline_mismatch(frame.expires_at_ms, lease.expires_at_ms) {
                    return ReceiverAdmit::Drop(ReceiverDropReason::ReceivedDeadlineMismatch);
                }
                self.admit_hold(
                    digest,
                    HeldEntry {
                        created_at: envelope.created_at,
                        ttl_seconds: envelope.ttl,
                        expires_at_ms: lease.expires_at_ms,
                        lease,
                        payload,
                        bytes: bytes.to_vec(),
                    },
                    counted,
                )
            }
            ReceiverLifetime::Display { expires_at_ms } => {
                if self.deadline_mismatch(frame.expires_at_ms, expires_at_ms) {
                    return ReceiverAdmit::Drop(ReceiverDropReason::ReceivedDeadlineMismatch);
                }
                self.admit_display(
                    digest,
                    payload,
                    ChannelEntry {
                        digest,
                        bytes: bytes.to_vec(),
                        created_at: envelope.created_at,
                        expires_at_ms,
                    },
                    counted,
                )
            }
        }
    }

    /// Advance holds from stored authenticated metadata with injected clocks.
    /// A retry is not required; the signed interval is never taken from a later frame.
    pub fn poll(&mut self, now_wall: u64, now_mono: u64) {
        let clock = ReceiverClock { local_now_ms: now_wall, monotonic_ms: now_mono };
        self.drop_expired_holds(clock);
        self.promote_holds(clock);
    }

    /// Move the oldest queued frame to in-flight, or drop it when `now_wall` ≥ D.
    /// Occupancy of a delivered frame is unchanged until [`Self::complete`].
    /// Holds advance first from stored metadata (no re-admission).
    pub fn pop(&mut self, now_wall: u64, now_mono: u64) -> ReceiverDequeue {
        self.poll(now_wall, now_mono);
        if self.inflight.is_some() {
            return ReceiverDequeue::Empty;
        }
        let Some(entry) = self.channel.pop_front() else {
            return ReceiverDequeue::Empty;
        };
        if now_wall >= entry.expires_at_ms {
            self.channel_bytes = self.channel_bytes.saturating_sub(entry.bytes.len());
            self.dedup.remove(&entry.digest);
            return ReceiverDequeue::Dropped(ReceiverDropReason::Expired);
        }
        if !self.skips_start_recheck() {
            let start_ms = i128::from(entry.created_at) * 1_000;
            if i128::from(now_wall) < start_ms {
                self.channel.push_front(entry);
                return ReceiverDequeue::Empty;
            }
        }
        let bytes = entry.bytes.clone();
        let expires_at_ms = entry.expires_at_ms;
        self.inflight = Some(entry);
        ReceiverDequeue::Delivered { bytes, expires_at_ms }
    }

    /// Release the in-flight frame from occupancy. Dedup remains until exclusive D.
    pub fn complete(&mut self) {
        if let Some(entry) = self.inflight.take() {
            self.channel_bytes = self.channel_bytes.saturating_sub(entry.bytes.len());
        }
    }

    fn frame_occupancy(&self) -> usize {
        self.channel
            .len()
            .saturating_add(usize::from(self.inflight.is_some()))
            .saturating_add(self.holds.len())
    }

    fn expire_due(&mut self, clock: ReceiverClock) {
        let now_ms = clock.local_now_ms;
        let mut bytes = self.channel_bytes;
        self.channel.retain(|entry| {
            if now_ms < entry.expires_at_ms {
                true
            } else {
                bytes = bytes.saturating_sub(entry.bytes.len());
                false
            }
        });
        if let Some(entry) = self.inflight.take_if(|entry| now_ms >= entry.expires_at_ms) {
            bytes = bytes.saturating_sub(entry.bytes.len());
        }
        self.channel_bytes = bytes;
        self.dedup.retain(|_, entry| now_ms < entry.expires_at_ms);
        self.drop_expired_holds(clock);
    }

    fn drop_expired_holds(&mut self, clock: ReceiverClock) {
        let keys: Vec<[u8; 32]> = self.holds.keys().copied().collect();
        for digest in keys {
            let Some(held) = self.holds.get(&digest) else {
                continue;
            };
            let payload = held.payload;
            match poll_entry(held, clock) {
                ReceiverLifetime::Drop(reason) => {
                    let _outcome =
                        self.finish_held(digest, payload, ReceiverLifetime::Drop(reason));
                }
                ReceiverLifetime::Hold(_) | ReceiverLifetime::Display { .. } => {}
            }
        }
    }

    fn promote_holds(&mut self, clock: ReceiverClock) {
        let keys: Vec<[u8; 32]> = self.holds.keys().copied().collect();
        for digest in keys {
            let Some(held) = self.holds.get(&digest) else {
                continue;
            };
            let payload = held.payload;
            match poll_entry(held, clock) {
                ReceiverLifetime::Hold(_) => {}
                lifetime => {
                    let _outcome = self.finish_held(digest, payload, lifetime);
                }
            }
        }
    }

    fn clear_transient(&mut self) {
        self.channel.clear();
        self.inflight = None;
        self.channel_bytes = 0;
        self.dedup.clear();
        self.holds.clear();
    }

    fn finish_held(
        &mut self,
        digest: [u8; 32],
        payload: [u8; 32],
        lifetime: ReceiverLifetime,
    ) -> ReceiverAdmit {
        match lifetime {
            ReceiverLifetime::Hold(lease) => ReceiverAdmit::Held(lease),
            ReceiverLifetime::Display { expires_at_ms } => {
                let Some(held) = self.holds.remove(&digest) else {
                    return ReceiverAdmit::DroppedNew;
                };
                self.record_terminal(digest, payload, expires_at_ms);
                self.channel.push_back(ChannelEntry {
                    digest,
                    bytes: held.bytes,
                    created_at: held.created_at,
                    expires_at_ms,
                });
                ReceiverAdmit::Displayed { expires_at_ms }
            }
            ReceiverLifetime::Drop(reason) => {
                let Some(held) = self.holds.remove(&digest) else {
                    return ReceiverAdmit::DroppedNew;
                };
                self.channel_bytes = self.channel_bytes.saturating_sub(held.bytes.len());
                if reason == ReceiverDropReason::Expired {
                    ReceiverAdmit::Expired
                } else {
                    self.record_terminal(digest, payload, held.expires_at_ms);
                    ReceiverAdmit::Drop(reason)
                }
            }
        }
    }

    fn record_terminal(&mut self, digest: [u8; 32], payload: [u8; 32], expires_at_ms: u64) {
        self.dedup.insert(digest, DedupEntry { payload_hash: payload, expires_at_ms });
    }

    fn admit_hold(&mut self, digest: [u8; 32], held: HeldEntry, counted: usize) -> ReceiverAdmit {
        if self.cannot_retain(counted) || self.dedup_saturated() {
            return ReceiverAdmit::DroppedNew;
        }
        let lease = held.lease;
        self.channel_bytes = self.channel_bytes.saturating_add(counted);
        self.holds.insert(digest, held);
        ReceiverAdmit::Held(lease)
    }

    fn admit_display(
        &mut self,
        digest: [u8; 32],
        payload: [u8; 32],
        entry: ChannelEntry,
        counted: usize,
    ) -> ReceiverAdmit {
        if self.cannot_retain(counted) || self.dedup_saturated() {
            return ReceiverAdmit::DroppedNew;
        }
        let expires_at_ms = entry.expires_at_ms;
        self.record_terminal(digest, payload, expires_at_ms);
        self.channel_bytes = self.channel_bytes.saturating_add(counted);
        self.channel.push_back(entry);
        ReceiverAdmit::Displayed { expires_at_ms }
    }

    fn cannot_retain(&self, counted: usize) -> bool {
        counted > RECEIVER_MAX_FRAME_BYTES
            || self.frame_occupancy() >= RECEIVER_CHANNEL_FRAMES
            || counted > RECEIVER_CHANNEL_BYTES.saturating_sub(self.channel_bytes)
    }

    fn dedup_saturated(&self) -> bool {
        self.dedup.len().saturating_add(self.holds.len()) >= RECEIVER_DEDUP_BOUND
    }

    fn counted_frame_len(&self, original: &[u8], envelope: &Envelope, expires_at_ms: u64) -> usize {
        #[cfg(test)]
        if self.sizes_reserialized() {
            return encode_complete_frame(envelope, expires_at_ms)
                .map_or(original.len(), |encoded| encoded.len());
        }
        let _ = (self, envelope, expires_at_ms);
        original.len()
    }

    fn sizes_reserialized(&self) -> bool {
        self.test_flag(TEST_SIZE_RESERIALIZED)
    }

    fn polls_retry_metadata(&self) -> bool {
        self.test_flag(TEST_POLL_RETRY_METADATA)
    }

    fn deadline_mismatch(&self, wrapper_expires_at_ms: u64, authenticated_d: u64) -> bool {
        if self.skips_deadline_compare() {
            return false;
        }
        wrapper_expires_at_ms != authenticated_d
    }

    fn skips_start_recheck(&self) -> bool {
        self.test_flag(TEST_SKIP_START_RECHECK)
    }

    fn skips_deadline_compare(&self) -> bool {
        self.test_flag(TEST_SKIP_DEADLINE_COMPARE)
    }

    fn test_flag(&self, bit: u8) -> bool {
        #[cfg(test)]
        {
            self.test_flags & bit != 0
        }
        #[cfg(not(test))]
        {
            let _ = (self, bit);
            false
        }
    }

    #[cfg(test)]
    fn set_test_flag(&mut self, bit: u8, value: bool) {
        if value {
            self.test_flags |= bit;
        } else {
            self.test_flags &= !bit;
        }
    }

    #[cfg(test)]
    pub fn set_poll_retry_metadata(&mut self, value: bool) {
        self.set_test_flag(TEST_POLL_RETRY_METADATA, value);
    }

    #[cfg(test)]
    pub fn set_size_reserialized(&mut self, value: bool) {
        self.set_test_flag(TEST_SIZE_RESERIALIZED, value);
    }

    #[cfg(test)]
    pub fn set_skip_start_recheck(&mut self, value: bool) {
        self.set_test_flag(TEST_SKIP_START_RECHECK, value);
    }

    #[cfg(test)]
    pub fn set_skip_deadline_compare(&mut self, value: bool) {
        self.set_test_flag(TEST_SKIP_DEADLINE_COMPARE, value);
    }
}

fn stored_deadline_ms(created_at: i64, ttl: u32) -> Option<u64> {
    created_at
        .checked_add(i64::from(ttl))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .and_then(|seconds| seconds.checked_mul(1_000))
}

fn poll_entry(held: &HeldEntry, clock: ReceiverClock) -> ReceiverLifetime {
    let expires_at_ms =
        stored_deadline_ms(held.created_at, held.ttl_seconds).unwrap_or(held.expires_at_ms);
    let lease = HoldLease {
        display_at_ms: held.lease.display_at_ms,
        monotonic_deadline_ms: held.lease.monotonic_deadline_ms,
        expires_at_ms,
    };
    poll_stored_hold(held.created_at, lease, clock)
}

#[cfg(test)]
mod tests {
    use super::{
        CompleteReceivedFrameRef, EphemeralReceiver, LedgerProbe, ReceiverAdmit, ReceiverDequeue,
    };
    use crate::ephemeral::{ReceiverClock, ReceiverDropReason};
    use ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION;
    use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
    use serde_json::Value;
    use std::collections::BTreeMap;

    const NOW_MS: u64 = 1_000_000;
    const MONOTONIC_MS: u64 = 50_000;
    const PRINCIPAL: &str = "principal";
    const SEED: [u8; 32] = [7; 32];
    const CHANNEL_FRAMES: usize = 64;
    const CHANNEL_BYTES: usize = 262_144;
    const MAX_FRAME: usize = 32_768;
    const OVERSIZE_FRAME: usize = 32_769;
    const OVERSIZE_CHANNEL: usize = 262_145;
    const DEDUP_BOUND: usize = 4_096;
    const DEDUP_BUDGET: usize = 294_912;
    const DEDUP_ENTRY: usize = 72;
    const EXPIRES_AT_MS: u64 = 1_005_000;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn clocks(local_now_ms: u64, monotonic_ms: u64) -> ReceiverClock {
        ReceiverClock { local_now_ms, monotonic_ms }
    }

    fn signing_public_key() -> String {
        ramflux_crypto::public_key_base64url_from_seed(SEED)
    }

    fn sign_envelope(envelope: &mut Envelope) {
        let bytes = ramflux_protocol::envelope_sender_signed_bytes(envelope);
        assert!(bytes.is_ok(), "canonical sender bytes");
        if let Ok(bytes) = bytes {
            envelope.signed.signature =
                ramflux_crypto::sign_canonical_bytes_with_seed(&bytes, SEED);
        }
    }

    fn base_envelope() -> Envelope {
        let mut extensions = BTreeMap::new();
        extensions
            .insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("ephemeral".to_owned()));
        Envelope {
            schema: "ramflux.envelope.v1".to_owned(),
            version: 1,
            domain: "ramflux.message".to_owned(),
            ext: Ext { ext: extensions },
            signed: SignedFields {
                signing_key_id: "key".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: String::new(),
            },
            envelope_id: "envelope".to_owned(),
            source_principal_id: PRINCIPAL.to_owned(),
            source_device_id: "device".to_owned(),
            target_delivery_id: "target".to_owned(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Low,
            ttl: 5,
            created_at: 1_000,
            encrypted_payload: "ct".to_owned(),
            payload_hash: "hash".to_owned(),
        }
    }

    fn signed(change: impl FnOnce(&mut Envelope)) -> Envelope {
        let mut envelope = base_envelope();
        change(&mut envelope);
        sign_envelope(&mut envelope);
        envelope
    }

    fn wrapper_expires_at_ms(envelope: &Envelope) -> u64 {
        envelope
            .created_at
            .checked_add(i64::from(envelope.ttl))
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(1_000))
            .unwrap_or(0)
    }

    fn complete_frame_bytes(envelope: &Envelope, expires_at_ms: u64) -> Option<Vec<u8>> {
        serde_json::to_vec(&serde_json::json!({
            "frame_type": "ephemeral",
            "envelope": envelope,
            "expires_at_ms": expires_at_ms,
        }))
        .ok()
    }

    fn frame_builds(envelope: &Envelope, expires_at_ms: u64) -> Result<Vec<u8>, std::io::Error> {
        complete_frame_bytes(envelope, expires_at_ms)
            .ok_or_else(|| std::io::Error::other("frame builds"))
    }

    fn admit(rx: &mut EphemeralReceiver, envelope: &Envelope, now_ms: u64) -> ReceiverAdmit {
        admit_at(rx, envelope, now_ms, MONOTONIC_MS)
    }

    fn admit_at(
        rx: &mut EphemeralReceiver,
        envelope: &Envelope,
        local_now_ms: u64,
        monotonic_ms: u64,
    ) -> ReceiverAdmit {
        match complete_frame_bytes(envelope, wrapper_expires_at_ms(envelope)) {
            Some(bytes) => admit_bytes(rx, &bytes, local_now_ms, monotonic_ms),
            None => ReceiverAdmit::DroppedNew,
        }
    }

    fn admit_bytes(
        rx: &mut EphemeralReceiver,
        bytes: &[u8],
        local_now_ms: u64,
        monotonic_ms: u64,
    ) -> ReceiverAdmit {
        rx.admit(bytes, clocks(local_now_ms, monotonic_ms), PRINCIPAL, &signing_public_key())
    }

    fn drain(rx: &mut EphemeralReceiver, now_ms: u64) {
        if let ReceiverDequeue::Delivered { .. } = rx.pop(now_ms, MONOTONIC_MS) {
            rx.complete();
        }
    }

    fn pad_to_frame_len(id: &str, frame_len: usize) -> Envelope {
        let mut lo = 1_usize;
        let mut hi = frame_len;
        let mut found = None;
        for _ in 0..frame_len.saturating_add(2) {
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2).max(1);
            let envelope = signed(|e| {
                e.envelope_id = id.to_owned();
                e.encrypted_payload = "x".repeat(mid);
            });
            let Some(encoded) = complete_frame_bytes(&envelope, EXPIRES_AT_MS) else {
                break;
            };
            match encoded.len().cmp(&frame_len) {
                std::cmp::Ordering::Equal => {
                    found = Some(envelope);
                    break;
                }
                std::cmp::Ordering::Less => lo = mid.saturating_add(1),
                std::cmp::Ordering::Greater => {
                    assert!(mid > 1, "base complete frame exceeds {frame_len}");
                    hi = mid.saturating_sub(1);
                }
            }
            if lo > hi {
                break;
            }
        }
        assert!(found.is_some(), "could not hit exact complete-frame length {frame_len}");
        match found {
            Some(envelope) => envelope,
            None => signed(|e| e.envelope_id = id.to_owned()),
        }
    }

    fn row_dedup_bound_drops_new() {
        let mut rx = EphemeralReceiver::new();
        let first = signed(|e| e.envelope_id = "first".to_owned());
        assert!(matches!(admit(&mut rx, &first, NOW_MS), ReceiverAdmit::Displayed { .. }));
        drain(&mut rx, NOW_MS);
        for i in 1..DEDUP_BOUND {
            let envelope = signed(|e| e.envelope_id = format!("id-{i}"));
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
            drain(&mut rx, NOW_MS);
        }
        assert_eq!(rx.dedup_len(), DEDUP_BOUND);
        assert_eq!(DEDUP_BUDGET, DEDUP_BOUND * DEDUP_ENTRY);
        let extra = signed(|e| e.envelope_id = "overflow".to_owned());
        assert_eq!(admit(&mut rx, &extra, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(rx.dedup_len(), DEDUP_BOUND);
        assert_eq!(admit(&mut rx, &first, NOW_MS), ReceiverAdmit::Duplicate);
    }

    fn row_conflicting_hash_rejected() {
        let mut rx = EphemeralReceiver::new();
        let original = signed(|e| {
            e.envelope_id = "same".to_owned();
            e.payload_hash = "hash-a".to_owned();
        });
        assert!(matches!(admit(&mut rx, &original, NOW_MS), ReceiverAdmit::Displayed { .. }));
        let conflict = signed(|e| {
            e.envelope_id = "same".to_owned();
            e.payload_hash = "hash-b".to_owned();
        });
        assert_eq!(admit(&mut rx, &conflict, NOW_MS), ReceiverAdmit::HashConflict);
        assert_eq!(admit(&mut rx, &original, NOW_MS), ReceiverAdmit::Duplicate);
        assert_eq!(rx.dedup_len(), 1);
    }

    fn row_channel_frame_cap() {
        let mut rx = EphemeralReceiver::new();
        for i in 0..CHANNEL_FRAMES {
            let envelope = signed(|e| e.envelope_id = format!("f-{i}"));
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        }
        assert_eq!(rx.occupancy().0, CHANNEL_FRAMES);
        let extra = signed(|e| e.envelope_id = "f-64".to_owned());
        assert_eq!(admit(&mut rx, &extra, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(rx.occupancy().0, CHANNEL_FRAMES);
        assert_eq!(rx.dedup_len(), CHANNEL_FRAMES);
    }

    fn row_whole_frame_cap() -> Result<(), Box<dyn std::error::Error>> {
        let mut at_cap = EphemeralReceiver::new();
        let exact = pad_to_frame_len("bytes-32768", MAX_FRAME);
        let exact_bytes = frame_builds(&exact, EXPIRES_AT_MS)?;
        assert_eq!(exact_bytes.len(), MAX_FRAME);
        assert!(matches!(
            admit_bytes(&mut at_cap, &exact_bytes, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::Displayed { .. }
        ));
        assert_eq!(at_cap.occupancy(), (1, MAX_FRAME));
        assert_eq!(
            at_cap.pop(NOW_MS, MONOTONIC_MS),
            ReceiverDequeue::Delivered { bytes: exact_bytes.clone(), expires_at_ms: EXPIRES_AT_MS }
        );

        let mut over = EphemeralReceiver::new();
        let too_big = pad_to_frame_len("bytes-32769", OVERSIZE_FRAME);
        let over_bytes = frame_builds(&too_big, EXPIRES_AT_MS)?;
        assert_eq!(over_bytes.len(), OVERSIZE_FRAME);
        assert_eq!(
            admit_bytes(&mut over, &over_bytes, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::DroppedNew
        );
        assert_eq!(over.occupancy(), (0, 0));
        assert_eq!(over.dedup_len(), 0);
        Ok(())
    }

    fn row_aggregate_byte_cap() -> Result<(), Box<dyn std::error::Error>> {
        let mut rx = EphemeralReceiver::new();
        for i in 0..8 {
            let envelope = pad_to_frame_len(&format!("agg-{i}"), MAX_FRAME);
            let bytes = frame_builds(&envelope, EXPIRES_AT_MS)?;
            assert_eq!(bytes.len(), MAX_FRAME);
            assert!(matches!(
                admit_bytes(&mut rx, &bytes, NOW_MS, MONOTONIC_MS),
                ReceiverAdmit::Displayed { .. }
            ));
        }
        assert_eq!(rx.occupancy(), (8, CHANNEL_BYTES));
        assert_eq!(CHANNEL_BYTES.saturating_add(1), OVERSIZE_CHANNEL);
        let extra = signed(|e| e.envelope_id = "agg-8".to_owned());
        let extra_bytes = frame_builds(&extra, EXPIRES_AT_MS)?;
        assert!(extra_bytes.len() >= OVERSIZE_CHANNEL.saturating_sub(CHANNEL_BYTES));
        assert_eq!(
            admit_bytes(&mut rx, &extra_bytes, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::DroppedNew
        );
        assert_eq!(rx.occupancy(), (8, CHANNEL_BYTES));
        Ok(())
    }

    fn row_negative_received_byte_vector() {
        let oversize = vec![b'x'; OVERSIZE_FRAME];
        assert_eq!(oversize.len(), OVERSIZE_FRAME);
        let mut rx = EphemeralReceiver::new();
        assert_eq!(
            admit_bytes(&mut rx, &oversize, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::DroppedNew
        );
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.dedup_len(), 0);
    }

    fn row_whitespace_padded_over_cap_refused() -> Result<(), Box<dyn std::error::Error>> {
        let envelope = signed(|e| e.envelope_id = "padded".to_owned());
        let compact = frame_builds(&envelope, EXPIRES_AT_MS)?;
        assert!(compact.len() < OVERSIZE_FRAME);
        let mut padded = compact.clone();
        padded.resize(OVERSIZE_FRAME, b' ');
        assert_eq!(padded.len(), OVERSIZE_FRAME);
        let mut compact_rx = EphemeralReceiver::new();
        assert!(matches!(
            admit_bytes(&mut compact_rx, &compact, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::Displayed { .. }
        ));
        let mut padded_rx = EphemeralReceiver::new();
        assert_eq!(
            admit_bytes(&mut padded_rx, &padded, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::DroppedNew
        );
        assert_eq!(padded_rx.occupancy(), (0, 0));
        assert_eq!(padded_rx.dedup_len(), 0);
        Ok(())
    }

    fn row_independent_received_byte_identity() -> Result<(), Box<dyn std::error::Error>> {
        let envelope = signed(|e| e.envelope_id = "identity".to_owned());
        let bytes = frame_builds(&envelope, EXPIRES_AT_MS)?;
        let mut rx = EphemeralReceiver::new();
        assert!(matches!(
            admit_bytes(&mut rx, &bytes, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::Displayed { .. }
        ));
        assert_eq!(
            rx.pop(NOW_MS, MONOTONIC_MS),
            ReceiverDequeue::Delivered { bytes: bytes.clone(), expires_at_ms: EXPIRES_AT_MS }
        );
        let invalid = br#"{"frame_type":"ephemeral","envelope":{"#.to_vec();
        let mut bad = EphemeralReceiver::new();
        assert_eq!(
            admit_bytes(&mut bad, &invalid, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::Drop(ReceiverDropReason::InvalidDeliveryMode)
        );
        assert_eq!(invalid, br#"{"frame_type":"ephemeral","envelope":{"#.to_vec());
        assert_eq!(bad.occupancy(), (0, 0));
        Ok(())
    }

    fn row_inflight_counts() {
        let mut rx = EphemeralReceiver::new();
        for i in 0..CHANNEL_FRAMES {
            let envelope = signed(|e| e.envelope_id = format!("q-{i}"));
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        }
        assert!(matches!(rx.pop(NOW_MS, MONOTONIC_MS), ReceiverDequeue::Delivered { .. }));
        assert_eq!(rx.occupancy().0, CHANNEL_FRAMES);
        let extra = signed(|e| e.envelope_id = "q-extra".to_owned());
        assert_eq!(admit(&mut rx, &extra, NOW_MS), ReceiverAdmit::DroppedNew);
        rx.complete();
        assert_eq!(rx.occupancy().0, CHANNEL_FRAMES.saturating_sub(1));
        assert!(matches!(admit(&mut rx, &extra, NOW_MS), ReceiverAdmit::Displayed { .. }));
    }

    fn row_generation_lock_iled() {
        let mut rx = EphemeralReceiver::new();
        let live = signed(|e| e.envelope_id = "live".to_owned());
        assert!(matches!(admit(&mut rx, &live, NOW_MS), ReceiverAdmit::Displayed { .. }));
        let early = signed(|e| {
            e.envelope_id = "hold".to_owned();
            e.created_at = 1_002;
            e.ttl = 1;
        });
        assert!(matches!(admit(&mut rx, &early, NOW_MS), ReceiverAdmit::Held(_)));
        assert_eq!(rx.hold_len(), 1);
        assert_eq!(rx.ledger_probe(), LedgerProbe::default());
        assert_eq!(rx.offered_coverage(), 0);

        assert_eq!(rx.bump_generation(), 1);
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.dedup_len(), 0);
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(admit(&mut rx, &live, NOW_MS), ReceiverAdmit::DroppedLocked);

        rx.unlock();
        assert!(matches!(admit(&mut rx, &live, NOW_MS), ReceiverAdmit::Displayed { .. }));
        assert_eq!(rx.ledger_probe(), LedgerProbe::default());
        assert_eq!(rx.offered_coverage(), 0);
        rx.lock();
        let late = signed(|e| e.envelope_id = "late".to_owned());
        assert_eq!(admit(&mut rx, &late, NOW_MS), ReceiverAdmit::DroppedLocked);
        rx.unlock();
        assert_eq!(rx.occupancy(), (0, 0));
        assert!(matches!(admit(&mut rx, &late, NOW_MS), ReceiverAdmit::Displayed { .. }));
    }

    fn row_expiry_frees_dedup() {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| {
            e.envelope_id = "exp".to_owned();
            e.ttl = 1;
        });
        assert_eq!(
            admit(&mut rx, &envelope, NOW_MS),
            ReceiverAdmit::Displayed { expires_at_ms: 1_001_000 }
        );
        drain(&mut rx, NOW_MS);
        assert_eq!(admit(&mut rx, &envelope, 1_000_999), ReceiverAdmit::Duplicate);
        assert_eq!(admit(&mut rx, &envelope, 1_001_000), ReceiverAdmit::Expired);
        assert_eq!(rx.dedup_len(), 0);
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
    }

    fn row_pop_delivers_at_deadline_minus_one() {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| {
            e.envelope_id = "pop-live".to_owned();
            e.ttl = 1;
        });
        assert_eq!(
            admit(&mut rx, &envelope, 1_000_999),
            ReceiverAdmit::Displayed { expires_at_ms: 1_001_000 }
        );
        assert!(matches!(
            rx.pop(1_000_999, MONOTONIC_MS),
            ReceiverDequeue::Delivered { expires_at_ms: 1_001_000, .. }
        ));
        assert_eq!(rx.occupancy().0, 1);
    }

    fn row_pop_drops_expired_at_deadline() {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| {
            e.envelope_id = "pop-exp".to_owned();
            e.ttl = 1;
        });
        assert_eq!(
            admit(&mut rx, &envelope, 1_000_999),
            ReceiverAdmit::Displayed { expires_at_ms: 1_001_000 }
        );
        assert_eq!(
            rx.pop(1_001_000, MONOTONIC_MS),
            ReceiverDequeue::Dropped(ReceiverDropReason::Expired)
        );
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.dedup_len(), 0);
    }

    fn hold_envelope() -> Envelope {
        signed(|e| {
            e.envelope_id = "held".to_owned();
            e.created_at = 1_002;
            e.ttl = 1;
        })
    }

    fn row_hold_release_delivers_once() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        let original = frame_builds(&envelope, 1_003_000)?;
        let first = admit_bytes(&mut rx, &original, NOW_MS, MONOTONIC_MS);
        assert!(matches!(first, ReceiverAdmit::Held(_)));
        assert_eq!(rx.hold_len(), 1);
        assert_eq!(rx.dedup_len(), 0);
        assert_eq!(rx.occupancy().0, 1);
        rx.poll(1_002_000, MONOTONIC_MS);
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(rx.dedup_len(), 1);
        assert_eq!(
            rx.pop(1_002_000, MONOTONIC_MS),
            ReceiverDequeue::Delivered { bytes: original, expires_at_ms: 1_003_000 }
        );
        assert_eq!(admit_at(&mut rx, &envelope, 1_002_000, MONOTONIC_MS), ReceiverAdmit::Duplicate);
        Ok(())
    }

    fn row_hold_cap_boundaries() {
        let envelope = hold_envelope();
        let cap = MONOTONIC_MS + 2_000;

        let mut keep = EphemeralReceiver::new();
        assert!(matches!(admit(&mut keep, &envelope, NOW_MS), ReceiverAdmit::Held(_)));
        keep.poll(NOW_MS, cap.saturating_sub(1));
        assert_eq!(keep.hold_len(), 1);
        assert_eq!(keep.dedup_len(), 0);

        let mut drop_at_cap = EphemeralReceiver::new();
        assert!(matches!(admit(&mut drop_at_cap, &envelope, NOW_MS), ReceiverAdmit::Held(_)));
        drop_at_cap.poll(NOW_MS, cap);
        assert_eq!(drop_at_cap.hold_len(), 0);
        assert_eq!(drop_at_cap.occupancy(), (0, 0));
        assert_eq!(drop_at_cap.dedup_len(), 1);
    }

    fn row_duplicate_while_held_not_double_delivered() {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Held(_)));
        let occupancy = rx.occupancy();
        assert_eq!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Duplicate);
        assert_eq!(rx.occupancy(), occupancy);
        assert_eq!(rx.hold_len(), 1);
        assert_eq!(rx.dedup_len(), 0);
        assert_eq!(rx.pop(NOW_MS, MONOTONIC_MS), ReceiverDequeue::Empty);
    }

    fn row_resigned_retry_does_not_mutate_hold() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let original_env = hold_envelope();
        let original = frame_builds(&original_env, 1_003_000)?;
        assert!(matches!(
            admit_bytes(&mut rx, &original, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::Held(_)
        ));
        let retry = signed(|e| {
            e.envelope_id = "held".to_owned();
            e.created_at = 1_000;
            e.ttl = 5;
        });
        assert_eq!(admit_at(&mut rx, &retry, 1_001_000, 51_000), ReceiverAdmit::Duplicate);
        assert_eq!(rx.hold_len(), 1);
        assert_eq!(rx.dedup_len(), 0);
        rx.poll(1_001_000, 51_000);
        assert_eq!(rx.hold_len(), 1);
        assert_eq!(rx.pop(1_001_000, 51_000), ReceiverDequeue::Empty);
        rx.poll(1_002_000, 51_000);
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(
            rx.pop(1_002_000, 51_000),
            ReceiverDequeue::Delivered { bytes: original, expires_at_ms: 1_003_000 }
        );
        assert_eq!(admit_at(&mut rx, &retry, 1_002_000, 51_000), ReceiverAdmit::Duplicate);
        Ok(())
    }

    fn row_hold_released_by_time_alone() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        let original = frame_builds(&envelope, 1_003_000)?;
        assert!(matches!(
            admit_bytes(&mut rx, &original, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::Held(_)
        ));
        assert_eq!(
            rx.pop(1_002_000, MONOTONIC_MS),
            ReceiverDequeue::Delivered { bytes: original, expires_at_ms: 1_003_000 }
        );
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(rx.dedup_len(), 1);
        Ok(())
    }

    fn row_hold_cap_by_monotonic_alone() {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Held(_)));
        rx.poll(NOW_MS, MONOTONIC_MS + 2_000);
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.dedup_len(), 1);
        assert_eq!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Duplicate);
    }

    fn row_one_terminal_per_ciphertext() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        let original = frame_builds(&envelope, 1_003_000)?;
        assert!(matches!(
            admit_bytes(&mut rx, &original, NOW_MS, MONOTONIC_MS),
            ReceiverAdmit::Held(_)
        ));
        rx.poll(1_002_000, MONOTONIC_MS);
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(rx.dedup_len(), 1);
        assert_eq!(
            rx.pop(1_002_000, MONOTONIC_MS),
            ReceiverDequeue::Delivered { bytes: original, expires_at_ms: 1_003_000 }
        );
        rx.complete();
        assert_eq!(admit(&mut rx, &envelope, 1_002_000), ReceiverAdmit::Duplicate);
        assert_eq!(admit(&mut rx, &envelope, 1_003_000), ReceiverAdmit::Expired);
        assert_eq!(rx.dedup_len(), 0);
        Ok(())
    }

    fn row_pop_rechecks_signed_start_after_promotion() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        let original = frame_builds(&envelope, 1_003_000)?;
        assert!(matches!(
            admit_bytes(&mut rx, &original, 1_000_000, 50_000),
            ReceiverAdmit::Held(_)
        ));
        rx.poll(1_002_000, 51_000);
        assert_eq!(rx.hold_len(), 0);
        let occupancy = rx.occupancy();
        assert_eq!(rx.pop(1_001_000, 51_001), ReceiverDequeue::Empty);
        assert_eq!(rx.occupancy(), occupancy);
        assert_eq!(
            rx.pop(1_002_000, 51_001),
            ReceiverDequeue::Delivered { bytes: original, expires_at_ms: 1_003_000 }
        );
        Ok(())
    }

    fn row_received_deadline_zero_refused() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| e.envelope_id = "dl-zero".to_owned());
        let bytes = frame_builds(&envelope, 0)?;
        assert_eq!(
            admit_bytes(&mut rx, &bytes, 1_000_000, 50_000),
            ReceiverAdmit::Drop(ReceiverDropReason::ReceivedDeadlineMismatch)
        );
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.dedup_len(), 0);
        Ok(())
    }

    fn row_received_deadline_max_refused() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| e.envelope_id = "dl-max".to_owned());
        let bytes = frame_builds(&envelope, u64::MAX)?;
        assert_eq!(
            admit_bytes(&mut rx, &bytes, 1_000_000, 50_000),
            ReceiverAdmit::Drop(ReceiverDropReason::ReceivedDeadlineMismatch)
        );
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.dedup_len(), 0);
        Ok(())
    }

    fn row_received_deadline_match_pop_returns_verified_d() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| e.envelope_id = "dl-match".to_owned());
        let bytes = frame_builds(&envelope, 1_005_000)?;
        assert_eq!(
            admit_bytes(&mut rx, &bytes, 1_000_000, 50_000),
            ReceiverAdmit::Displayed { expires_at_ms: 1_005_000 }
        );
        assert_eq!(
            rx.pop(1_000_000, 50_000),
            ReceiverDequeue::Delivered { bytes, expires_at_ms: 1_005_000 }
        );
        Ok(())
    }

    fn row_hold_received_deadline_zero_refused() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| {
            e.envelope_id = "hold-dl-zero".to_owned();
            e.created_at = 1_002;
            e.ttl = 1;
        });
        let bytes = frame_builds(&envelope, 0)?;
        assert_eq!(
            admit_bytes(&mut rx, &bytes, 1_000_000, 50_000),
            ReceiverAdmit::Drop(ReceiverDropReason::ReceivedDeadlineMismatch)
        );
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(rx.dedup_len(), 0);
        Ok(())
    }

    fn row_hold_received_deadline_max_refused() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| {
            e.envelope_id = "hold-dl-max".to_owned();
            e.created_at = 1_002;
            e.ttl = 1;
        });
        let bytes = frame_builds(&envelope, u64::MAX)?;
        assert_eq!(
            admit_bytes(&mut rx, &bytes, 1_000_000, 50_000),
            ReceiverAdmit::Drop(ReceiverDropReason::ReceivedDeadlineMismatch)
        );
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(rx.dedup_len(), 0);
        Ok(())
    }

    fn row_hold_received_deadline_match_held() -> TestResult {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        let bytes = frame_builds(&envelope, 1_003_000)?;
        assert!(matches!(admit_bytes(&mut rx, &bytes, 1_000_000, 50_000), ReceiverAdmit::Held(_)));
        assert_eq!(rx.hold_len(), 1);
        assert_eq!(rx.occupancy().0, 1);
        assert_eq!(rx.dedup_len(), 0);
        Ok(())
    }

    #[test]
    fn ephemeral_receiver_bounds_and_lock() -> TestResult {
        let mut flags = EphemeralReceiver::new();
        flags.set_poll_retry_metadata(false);
        flags.set_size_reserialized(false);
        flags.set_skip_start_recheck(false);
        flags.set_skip_deadline_compare(false);
        row_dedup_bound_drops_new();
        row_conflicting_hash_rejected();
        row_channel_frame_cap();
        row_whole_frame_cap()?;
        row_aggregate_byte_cap()?;
        row_negative_received_byte_vector();
        row_whitespace_padded_over_cap_refused()?;
        row_independent_received_byte_identity()?;
        row_inflight_counts();
        row_generation_lock_iled();
        row_expiry_frees_dedup();
        row_pop_delivers_at_deadline_minus_one();
        row_pop_drops_expired_at_deadline();
        row_hold_release_delivers_once()?;
        row_hold_cap_boundaries();
        row_duplicate_while_held_not_double_delivered();
        row_resigned_retry_does_not_mutate_hold()?;
        row_hold_released_by_time_alone()?;
        row_hold_cap_by_monotonic_alone();
        row_one_terminal_per_ciphertext()?;
        row_pop_rechecks_signed_start_after_promotion()?;
        row_received_deadline_zero_refused()?;
        row_received_deadline_max_refused()?;
        row_received_deadline_match_pop_returns_verified_d()?;
        row_hold_received_deadline_zero_refused()?;
        row_hold_received_deadline_max_refused()?;
        row_hold_received_deadline_match_held()?;
        Ok(())
    }

    fn row_live_duplicate_before_d() {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| e.ttl = 1);
        assert_eq!(
            admit(&mut rx, &envelope, NOW_MS),
            ReceiverAdmit::Displayed { expires_at_ms: 1_001_000 }
        );
        assert_eq!(admit(&mut rx, &envelope, 1_000_999), ReceiverAdmit::Duplicate);
        assert_eq!(admit(&mut rx, &envelope, 1_001_000), ReceiverAdmit::Expired);
        assert_eq!(rx.dedup_len(), 0);
    }

    fn row_router_restart_receiver_survives() {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| e.envelope_id = "restart".to_owned());
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        assert_eq!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Duplicate);
        let mut restarted_router_same_receiver = rx;
        assert_eq!(
            admit(&mut restarted_router_same_receiver, &envelope, NOW_MS),
            ReceiverAdmit::Duplicate
        );
        let mut process_restart = EphemeralReceiver::new();
        assert!(matches!(
            admit(&mut process_restart, &envelope, NOW_MS),
            ReceiverAdmit::Displayed { .. }
        ));
        assert_eq!(admit(&mut process_restart, &envelope, 1_005_000), ReceiverAdmit::Expired);
    }

    fn row_repeated_restarts_duplicate_only_before_d() {
        let envelope = signed(|e| {
            e.envelope_id = "rep".to_owned();
            e.ttl = 1;
        });
        for _ in 0..3 {
            let mut rx = EphemeralReceiver::new();
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
            assert_eq!(admit(&mut rx, &envelope, 1_000_999), ReceiverAdmit::Duplicate);
            assert_eq!(admit(&mut rx, &envelope, 1_001_000), ReceiverAdmit::Expired);
        }
    }

    fn row_lock_unlock_replays_nothing() {
        let mut rx = EphemeralReceiver::new();
        let envelope = signed(|e| e.envelope_id = "queued".to_owned());
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        rx.lock();
        rx.unlock();
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.dedup_len(), 0);
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
    }

    fn row_hold_cleared_on_bump() {
        let mut rx = EphemeralReceiver::new();
        let early = hold_envelope();
        assert!(matches!(admit(&mut rx, &early, NOW_MS), ReceiverAdmit::Held(_)));
        let _ = rx.bump_generation();
        rx.unlock();
        assert_eq!(rx.hold_len(), 0);
        assert!(matches!(admit(&mut rx, &early, NOW_MS), ReceiverAdmit::Held(_)));
    }

    fn row_lifetime_refusals_isolated() {
        let mut rx = EphemeralReceiver::new();
        let durable = signed(|e| {
            e.ext.ext.remove(DELIVERY_MODE_EXTENSION);
        });
        assert_eq!(
            admit(&mut rx, &durable, NOW_MS),
            ReceiverAdmit::Drop(ReceiverDropReason::NotEphemeral)
        );
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.ledger_probe(), LedgerProbe::default());
    }

    #[test]
    fn ephemeral_restart_window() {
        let mut flags = EphemeralReceiver::new();
        flags.set_poll_retry_metadata(false);
        flags.set_size_reserialized(false);
        flags.set_skip_start_recheck(false);
        flags.set_skip_deadline_compare(false);
        row_live_duplicate_before_d();
        row_router_restart_receiver_survives();
        row_repeated_restarts_duplicate_only_before_d();
        row_lock_unlock_replays_nothing();
        row_hold_cleared_on_bump();
        row_lifetime_refusals_isolated();
    }

    #[test]
    fn complete_frame_ref_shape_is_stable() {
        let envelope = signed(|e| e.envelope_id = "shape".to_owned());
        let encoded = serde_json::to_vec(&CompleteReceivedFrameRef {
            frame_type: "ephemeral",
            envelope: &envelope,
            expires_at_ms: EXPIRES_AT_MS,
        });
        assert!(encoded.is_ok(), "shape");
        if let Ok(encoded) = encoded {
            assert!(encoded.starts_with(br#"{"frame_type":"ephemeral""#));
        }
    }
}

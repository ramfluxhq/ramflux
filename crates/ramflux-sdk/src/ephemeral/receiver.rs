// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded in-memory ephemeral receiver channel, dedup, generation lock, I-LED.

use super::{
    AuthenticatedCiphertext, HoldLease, ReceiverClock, ReceiverDropReason, ReceiverLifetime,
    admit_authenticated_ciphertext,
};
use ramflux_protocol::Envelope;
use serde::{Deserialize, Serialize};
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
    Delivered(Vec<u8>),
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

#[derive(Serialize, Deserialize)]
struct CompleteReceivedFrame {
    frame_type: String,
    envelope: Envelope,
    expires_at_ms: u64,
}

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
    expires_at_ms: u64,
}

struct HeldEntry {
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

    /// Refuse a complete received-frame byte vector that exceeds the whole-frame cap.
    /// Decode is not attempted; occupancy is unchanged.
    pub fn admit_complete_frame(&mut self, bytes: &[u8]) -> ReceiverAdmit {
        if bytes.len() > RECEIVER_MAX_FRAME_BYTES {
            return ReceiverAdmit::DroppedNew;
        }
        match serde_json::from_slice::<CompleteReceivedFrame>(bytes) {
            Ok(_) => ReceiverAdmit::DroppedNew,
            Err(_) => ReceiverAdmit::Drop(ReceiverDropReason::InvalidDeliveryMode),
        }
    }

    /// Admit an authenticated still-encrypted envelope under injected clocks.
    pub fn admit(
        &mut self,
        ciphertext: &AuthenticatedCiphertext<'_>,
        clock: ReceiverClock,
    ) -> ReceiverAdmit {
        self.expire_due(clock.local_now_ms);
        if self.locked {
            return ReceiverAdmit::DroppedLocked;
        }
        let envelope = ciphertext.envelope();
        let digest = digest_key(&envelope.source_device_id, &envelope.envelope_id);
        let payload = payload_digest(&envelope.payload_hash);
        if let Some(held) = self.holds.get(&digest) {
            if held.payload != payload {
                return ReceiverAdmit::HashConflict;
            }
            let lease = held.lease;
            let handoff = admit_authenticated_ciphertext(ciphertext, clock, Some(lease));
            return self.finish_held(digest, payload, handoff.lifetime);
        }
        if let Some(existing) = self.dedup.get(&digest) {
            if existing.payload_hash != payload {
                return ReceiverAdmit::HashConflict;
            }
            return ReceiverAdmit::Duplicate;
        }
        let handoff = admit_authenticated_ciphertext(ciphertext, clock, None);
        match handoff.lifetime {
            ReceiverLifetime::Drop(ReceiverDropReason::Expired) => ReceiverAdmit::Expired,
            ReceiverLifetime::Drop(reason) => ReceiverAdmit::Drop(reason),
            ReceiverLifetime::Hold(lease) => self.admit_hold(digest, payload, envelope, lease),
            ReceiverLifetime::Display { expires_at_ms } => {
                self.admit_display(digest, payload, envelope, expires_at_ms)
            }
        }
    }

    /// Move the oldest queued frame to in-flight, or drop it when `now_ms` ≥ D.
    /// Occupancy of a delivered frame is unchanged until [`Self::complete`].
    pub fn pop(&mut self, now_ms: u64) -> ReceiverDequeue {
        if self.inflight.is_some() {
            return ReceiverDequeue::Empty;
        }
        let Some(entry) = self.channel.pop_front() else {
            return ReceiverDequeue::Empty;
        };
        if now_ms >= entry.expires_at_ms {
            self.channel_bytes = self.channel_bytes.saturating_sub(entry.bytes.len());
            self.dedup.remove(&entry.digest);
            return ReceiverDequeue::Dropped(ReceiverDropReason::Expired);
        }
        let bytes = entry.bytes.clone();
        self.inflight = Some(entry);
        ReceiverDequeue::Delivered(bytes)
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

    fn expire_due(&mut self, now_ms: u64) {
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
        self.holds.retain(|_, held| {
            if now_ms < held.lease.expires_at_ms {
                true
            } else {
                bytes = bytes.saturating_sub(held.bytes.len());
                false
            }
        });
        self.channel_bytes = bytes;
        self.dedup.retain(|_, entry| now_ms < entry.expires_at_ms);
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
                self.channel.push_back(ChannelEntry { digest, bytes: held.bytes, expires_at_ms });
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
                    self.record_terminal(digest, payload, held.lease.expires_at_ms);
                    ReceiverAdmit::Drop(reason)
                }
            }
        }
    }

    fn record_terminal(&mut self, digest: [u8; 32], payload: [u8; 32], expires_at_ms: u64) {
        self.dedup.insert(digest, DedupEntry { payload_hash: payload, expires_at_ms });
    }

    fn admit_hold(
        &mut self,
        digest: [u8; 32],
        payload: [u8; 32],
        envelope: &Envelope,
        lease: HoldLease,
    ) -> ReceiverAdmit {
        let Some(bytes) = encode_complete_frame(envelope, lease.expires_at_ms) else {
            return ReceiverAdmit::DroppedNew;
        };
        if self.cannot_retain(&bytes) || self.dedup_saturated() {
            return ReceiverAdmit::DroppedNew;
        }
        self.channel_bytes = self.channel_bytes.saturating_add(bytes.len());
        self.holds.insert(digest, HeldEntry { lease, payload, bytes });
        ReceiverAdmit::Held(lease)
    }

    fn admit_display(
        &mut self,
        digest: [u8; 32],
        payload: [u8; 32],
        envelope: &Envelope,
        expires_at_ms: u64,
    ) -> ReceiverAdmit {
        let Some(bytes) = encode_complete_frame(envelope, expires_at_ms) else {
            return ReceiverAdmit::DroppedNew;
        };
        if self.cannot_retain(&bytes) || self.dedup_saturated() {
            return ReceiverAdmit::DroppedNew;
        }
        self.record_terminal(digest, payload, expires_at_ms);
        self.channel_bytes = self.channel_bytes.saturating_add(bytes.len());
        self.channel.push_back(ChannelEntry { digest, bytes, expires_at_ms });
        ReceiverAdmit::Displayed { expires_at_ms }
    }

    fn cannot_retain(&self, bytes: &[u8]) -> bool {
        bytes.len() > RECEIVER_MAX_FRAME_BYTES
            || self.frame_occupancy() >= RECEIVER_CHANNEL_FRAMES
            || bytes.len() > RECEIVER_CHANNEL_BYTES.saturating_sub(self.channel_bytes)
    }

    fn dedup_saturated(&self) -> bool {
        self.dedup.len().saturating_add(self.holds.len()) >= RECEIVER_DEDUP_BOUND
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompleteReceivedFrameRef, EphemeralReceiver, LedgerProbe, ReceiverAdmit, ReceiverDequeue,
        encode_complete_frame,
    };
    use crate::ephemeral::{ReceiverClock, ReceiverDropReason, authenticate};
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

    fn admit(rx: &mut EphemeralReceiver, envelope: &Envelope, now_ms: u64) -> ReceiverAdmit {
        admit_at(rx, envelope, now_ms, MONOTONIC_MS)
    }

    fn admit_at(
        rx: &mut EphemeralReceiver,
        envelope: &Envelope,
        local_now_ms: u64,
        monotonic_ms: u64,
    ) -> ReceiverAdmit {
        let authenticated = authenticate(envelope, PRINCIPAL, &signing_public_key());
        assert!(authenticated.is_ok());
        match authenticated {
            Ok(authenticated) => rx.admit(&authenticated, clocks(local_now_ms, monotonic_ms)),
            Err(_) => ReceiverAdmit::DroppedNew,
        }
    }

    fn drain(rx: &mut EphemeralReceiver, now_ms: u64) {
        if let ReceiverDequeue::Delivered(_) = rx.pop(now_ms) {
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
            let Some(encoded) = encode_complete_frame(&envelope, EXPIRES_AT_MS) else {
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

    fn row_whole_frame_cap() {
        let mut at_cap = EphemeralReceiver::new();
        let exact = pad_to_frame_len("bytes-32768", MAX_FRAME);
        assert!(matches!(admit(&mut at_cap, &exact, NOW_MS), ReceiverAdmit::Displayed { .. }));
        assert_eq!(at_cap.occupancy(), (1, MAX_FRAME));

        let mut over = EphemeralReceiver::new();
        let too_big = pad_to_frame_len("bytes-32769", OVERSIZE_FRAME);
        assert_eq!(admit(&mut over, &too_big, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(over.occupancy(), (0, 0));
        assert_eq!(over.dedup_len(), 0);
    }

    fn row_aggregate_byte_cap() {
        let mut rx = EphemeralReceiver::new();
        for i in 0..8 {
            let envelope = pad_to_frame_len(&format!("agg-{i}"), MAX_FRAME);
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        }
        assert_eq!(rx.occupancy(), (8, CHANNEL_BYTES));
        assert_eq!(CHANNEL_BYTES.saturating_add(1), OVERSIZE_CHANNEL);
        let extra = signed(|e| e.envelope_id = "agg-8".to_owned());
        assert_eq!(admit(&mut rx, &extra, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(rx.occupancy(), (8, CHANNEL_BYTES));
    }

    fn row_negative_received_byte_vector() {
        let oversize = vec![b'x'; OVERSIZE_FRAME];
        assert_eq!(oversize.len(), OVERSIZE_FRAME);
        let mut rx = EphemeralReceiver::new();
        assert_eq!(rx.admit_complete_frame(&oversize), ReceiverAdmit::DroppedNew);
        assert_eq!(rx.occupancy(), (0, 0));
        assert_eq!(rx.dedup_len(), 0);
    }

    fn row_inflight_counts() {
        let mut rx = EphemeralReceiver::new();
        for i in 0..CHANNEL_FRAMES {
            let envelope = signed(|e| e.envelope_id = format!("q-{i}"));
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        }
        assert!(matches!(rx.pop(NOW_MS), ReceiverDequeue::Delivered(_)));
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
        assert!(matches!(rx.pop(1_000_999), ReceiverDequeue::Delivered(_)));
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
        assert_eq!(rx.pop(1_001_000), ReceiverDequeue::Dropped(ReceiverDropReason::Expired));
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

    fn row_hold_release_delivers_once() {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        let first = admit(&mut rx, &envelope, NOW_MS);
        assert!(matches!(first, ReceiverAdmit::Held(_)));
        assert_eq!(rx.hold_len(), 1);
        assert_eq!(rx.dedup_len(), 0);
        assert_eq!(rx.occupancy().0, 1);
        assert_eq!(
            admit_at(&mut rx, &envelope, 1_002_000, MONOTONIC_MS),
            ReceiverAdmit::Displayed { expires_at_ms: 1_003_000 }
        );
        assert_eq!(rx.hold_len(), 0);
        assert_eq!(rx.dedup_len(), 1);
        assert!(matches!(rx.pop(1_002_000), ReceiverDequeue::Delivered(_)));
        assert_eq!(admit_at(&mut rx, &envelope, 1_002_000, MONOTONIC_MS), ReceiverAdmit::Duplicate);
    }

    fn row_hold_cap_boundaries() {
        let envelope = hold_envelope();
        let cap = MONOTONIC_MS + 2_000;

        let mut keep = EphemeralReceiver::new();
        assert!(matches!(admit(&mut keep, &envelope, NOW_MS), ReceiverAdmit::Held(_)));
        assert!(matches!(
            admit_at(&mut keep, &envelope, NOW_MS, cap.saturating_sub(1)),
            ReceiverAdmit::Held(_)
        ));
        assert_eq!(keep.hold_len(), 1);
        assert_eq!(keep.dedup_len(), 0);

        let mut drop_at_cap = EphemeralReceiver::new();
        assert!(matches!(admit(&mut drop_at_cap, &envelope, NOW_MS), ReceiverAdmit::Held(_)));
        assert_eq!(
            admit_at(&mut drop_at_cap, &envelope, NOW_MS, cap),
            ReceiverAdmit::Drop(ReceiverDropReason::HoldCapExceeded)
        );
        assert_eq!(drop_at_cap.hold_len(), 0);
        assert_eq!(drop_at_cap.occupancy(), (0, 0));
    }

    fn row_duplicate_while_held_not_double_delivered() {
        let mut rx = EphemeralReceiver::new();
        let envelope = hold_envelope();
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Held(_)));
        let occupancy = rx.occupancy();
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Held(_)));
        assert_eq!(rx.occupancy(), occupancy);
        assert_eq!(rx.hold_len(), 1);
        assert_eq!(rx.dedup_len(), 0);
        assert_eq!(rx.pop(NOW_MS), ReceiverDequeue::Empty);
    }

    #[test]
    fn ephemeral_receiver_bounds_and_lock() {
        row_dedup_bound_drops_new();
        row_conflicting_hash_rejected();
        row_channel_frame_cap();
        row_whole_frame_cap();
        row_aggregate_byte_cap();
        row_negative_received_byte_vector();
        row_inflight_counts();
        row_generation_lock_iled();
        row_expiry_frees_dedup();
        row_pop_delivers_at_deadline_minus_one();
        row_pop_drops_expired_at_deadline();
        row_hold_release_delivers_once();
        row_hold_cap_boundaries();
        row_duplicate_while_held_not_double_delivered();
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

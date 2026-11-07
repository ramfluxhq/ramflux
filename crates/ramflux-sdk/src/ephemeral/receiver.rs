// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded in-memory ephemeral receiver channel, dedup set, generation lock, I-LED.

use super::{
    AuthenticatedCiphertext, HoldLease, ReceiverClock, ReceiverDropReason, ReceiverLifetime,
    admit_authenticated_ciphertext,
};
use std::collections::{HashMap, VecDeque};

/// Inclusive channel frame cap, including the in-flight write.
pub const RECEIVER_CHANNEL_FRAMES: usize = 64;
/// Inclusive channel byte cap, including the in-flight write.
pub const RECEIVER_CHANNEL_BYTES: usize = 262_144;
/// Inclusive live dedup bound.
pub const RECEIVER_DEDUP_BOUND: usize = 4_096;
/// Bytes of one stored `(key, payload hash, D)` tuple.
pub const RECEIVER_DEDUP_ENTRY_BYTES: usize = 32 + 32 + 8;
/// Inclusive retained-tuple budget at [`RECEIVER_DEDUP_BOUND`].
pub const RECEIVER_DEDUP_BUDGET_BYTES: usize = RECEIVER_DEDUP_BOUND * RECEIVER_DEDUP_ENTRY_BYTES;
/// Maximum ephemeral frame payload counted toward the channel.
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

/// S6b ledger effects the receiver must never produce (I-LED).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LedgerProbe {
    pub w0: u64,
    pub receipt: u64,
    pub ack: u64,
    pub offered_coverage: u64,
}

struct DedupEntry {
    payload_hash: [u8; 32],
    expires_at_ms: u64,
}

struct ChannelEntry {
    bytes: Vec<u8>,
    expires_at_ms: u64,
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
    holds: HashMap<[u8; 32], HoldLease>,
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

    /// Channel occupancy including the in-flight write: `(frames, bytes)`.
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
        if let Some(existing) = self.dedup.get(&digest) {
            if existing.payload_hash != payload {
                return ReceiverAdmit::HashConflict;
            }
            return ReceiverAdmit::Duplicate;
        }
        let hold = self.holds.get(&digest).copied();
        let handoff = admit_authenticated_ciphertext(ciphertext, clock, hold);
        match handoff.lifetime {
            ReceiverLifetime::Drop(ReceiverDropReason::Expired) => ReceiverAdmit::Expired,
            ReceiverLifetime::Drop(reason) => ReceiverAdmit::Drop(reason),
            ReceiverLifetime::Hold(lease) => self.admit_hold(digest, payload, lease),
            ReceiverLifetime::Display { expires_at_ms } => self.admit_display(
                digest,
                payload,
                envelope.encrypted_payload.as_bytes(),
                expires_at_ms,
            ),
        }
    }

    /// Move the oldest queued frame to in-flight. Occupancy is unchanged until [`Self::complete`].
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        if self.inflight.is_some() {
            return None;
        }
        let entry = self.channel.pop_front()?;
        let bytes = entry.bytes.clone();
        self.inflight = Some(entry);
        Some(bytes)
    }

    /// Release the in-flight frame from occupancy. Dedup remains until exclusive D.
    pub fn complete(&mut self) {
        if let Some(entry) = self.inflight.take() {
            self.channel_bytes = self.channel_bytes.saturating_sub(entry.bytes.len());
        }
    }

    fn frame_occupancy(&self) -> usize {
        self.channel.len().saturating_add(usize::from(self.inflight.is_some()))
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
        self.channel_bytes = bytes;
        self.dedup.retain(|_, entry| now_ms < entry.expires_at_ms);
        self.holds.retain(|_, lease| now_ms < lease.expires_at_ms);
    }

    fn clear_transient(&mut self) {
        self.channel.clear();
        self.inflight = None;
        self.channel_bytes = 0;
        self.dedup.clear();
        self.holds.clear();
    }

    fn admit_hold(
        &mut self,
        digest: [u8; 32],
        payload: [u8; 32],
        lease: HoldLease,
    ) -> ReceiverAdmit {
        if self.dedup.len() >= RECEIVER_DEDUP_BOUND {
            return ReceiverAdmit::DroppedNew;
        }
        self.dedup.insert(
            digest,
            DedupEntry { payload_hash: payload, expires_at_ms: lease.expires_at_ms },
        );
        self.holds.insert(digest, lease);
        ReceiverAdmit::Held(lease)
    }

    fn admit_display(
        &mut self,
        digest: [u8; 32],
        payload: [u8; 32],
        bytes: &[u8],
        expires_at_ms: u64,
    ) -> ReceiverAdmit {
        if self.dedup.len() >= RECEIVER_DEDUP_BOUND {
            return ReceiverAdmit::DroppedNew;
        }
        if self.frame_occupancy() >= RECEIVER_CHANNEL_FRAMES
            || bytes.len() > RECEIVER_CHANNEL_BYTES.saturating_sub(self.channel_bytes)
        {
            return ReceiverAdmit::DroppedNew;
        }
        self.dedup.insert(digest, DedupEntry { payload_hash: payload, expires_at_ms });
        self.channel_bytes = self.channel_bytes.saturating_add(bytes.len());
        self.channel.push_back(ChannelEntry { bytes: bytes.to_vec(), expires_at_ms });
        ReceiverAdmit::Displayed { expires_at_ms }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EphemeralReceiver, LedgerProbe, RECEIVER_CHANNEL_BYTES, RECEIVER_CHANNEL_FRAMES,
        RECEIVER_DEDUP_BOUND, RECEIVER_DEDUP_BUDGET_BYTES, RECEIVER_DEDUP_ENTRY_BYTES,
        RECEIVER_MAX_FRAME_BYTES, ReceiverAdmit,
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

    fn clock(local_now_ms: u64) -> ReceiverClock {
        ReceiverClock { local_now_ms, monotonic_ms: MONOTONIC_MS }
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
        let authenticated = authenticate(envelope, PRINCIPAL, &signing_public_key());
        assert!(authenticated.is_ok());
        if let Ok(authenticated) = authenticated {
            rx.admit(&authenticated, clock(now_ms))
        } else {
            ReceiverAdmit::DroppedNew
        }
    }

    fn drain(rx: &mut EphemeralReceiver) {
        if rx.pop().is_some() {
            rx.complete();
        }
    }

    fn row_dedup_bound_drops_new() {
        let mut rx = EphemeralReceiver::new();
        let first = signed(|e| e.envelope_id = "first".to_owned());
        assert!(matches!(admit(&mut rx, &first, NOW_MS), ReceiverAdmit::Displayed { .. }));
        drain(&mut rx);
        for i in 1..RECEIVER_DEDUP_BOUND {
            let envelope = signed(|e| e.envelope_id = format!("id-{i}"));
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
            drain(&mut rx);
        }
        assert_eq!(rx.dedup_len(), RECEIVER_DEDUP_BOUND);
        assert_eq!(RECEIVER_DEDUP_BUDGET_BYTES, RECEIVER_DEDUP_BOUND * RECEIVER_DEDUP_ENTRY_BYTES);
        assert_eq!(RECEIVER_DEDUP_BUDGET_BYTES, 294_912);
        let extra = signed(|e| e.envelope_id = "overflow".to_owned());
        assert_eq!(admit(&mut rx, &extra, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(rx.dedup_len(), RECEIVER_DEDUP_BOUND);
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
        for i in 0..RECEIVER_CHANNEL_FRAMES {
            let envelope = signed(|e| e.envelope_id = format!("f-{i}"));
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        }
        assert_eq!(rx.occupancy().0, RECEIVER_CHANNEL_FRAMES);
        let extra = signed(|e| e.envelope_id = "f-64".to_owned());
        assert_eq!(admit(&mut rx, &extra, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(rx.occupancy().0, RECEIVER_CHANNEL_FRAMES);
        assert_eq!(rx.dedup_len(), RECEIVER_CHANNEL_FRAMES);
    }

    fn row_channel_byte_cap() {
        let mut at_cap = EphemeralReceiver::new();
        let exact = signed(|e| {
            e.envelope_id = "bytes".to_owned();
            e.encrypted_payload = "x".repeat(RECEIVER_CHANNEL_BYTES);
        });
        assert!(matches!(admit(&mut at_cap, &exact, NOW_MS), ReceiverAdmit::Displayed { .. }));
        assert_eq!(at_cap.occupancy(), (1, RECEIVER_CHANNEL_BYTES));
        let extra = signed(|e| {
            e.envelope_id = "one-more".to_owned();
            e.encrypted_payload = "y".to_owned();
        });
        assert_eq!(admit(&mut at_cap, &extra, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(at_cap.occupancy(), (1, RECEIVER_CHANNEL_BYTES));

        let mut over = EphemeralReceiver::new();
        let too_big = signed(|e| {
            e.envelope_id = "over".to_owned();
            e.encrypted_payload = "x".repeat(RECEIVER_CHANNEL_BYTES.saturating_add(1));
        });
        assert_eq!(admit(&mut over, &too_big, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(over.occupancy(), (0, 0));
        assert_eq!(over.dedup_len(), 0);
    }

    fn row_eight_max_frames() {
        let mut rx = EphemeralReceiver::new();
        for i in 0..8 {
            let envelope = signed(|e| {
                e.envelope_id = format!("m-{i}");
                e.encrypted_payload = "z".repeat(RECEIVER_MAX_FRAME_BYTES);
            });
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        }
        assert_eq!(rx.occupancy(), (8, RECEIVER_CHANNEL_BYTES));
        let ninth = signed(|e| {
            e.envelope_id = "m-8".to_owned();
            e.encrypted_payload = "z".repeat(RECEIVER_MAX_FRAME_BYTES);
        });
        assert_eq!(admit(&mut rx, &ninth, NOW_MS), ReceiverAdmit::DroppedNew);
        assert_eq!(rx.occupancy(), (8, RECEIVER_CHANNEL_BYTES));
    }

    fn row_inflight_counts() {
        let mut rx = EphemeralReceiver::new();
        for i in 0..RECEIVER_CHANNEL_FRAMES {
            let envelope = signed(|e| e.envelope_id = format!("q-{i}"));
            assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
        }
        assert!(rx.pop().is_some());
        assert_eq!(rx.occupancy().0, RECEIVER_CHANNEL_FRAMES);
        let extra = signed(|e| e.envelope_id = "q-extra".to_owned());
        assert_eq!(admit(&mut rx, &extra, NOW_MS), ReceiverAdmit::DroppedNew);
        rx.complete();
        assert_eq!(rx.occupancy().0, RECEIVER_CHANNEL_FRAMES.saturating_sub(1));
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
        drain(&mut rx);
        assert_eq!(admit(&mut rx, &envelope, 1_000_999), ReceiverAdmit::Duplicate);
        assert_eq!(admit(&mut rx, &envelope, 1_001_000), ReceiverAdmit::Expired);
        assert_eq!(rx.dedup_len(), 0);
        assert!(matches!(admit(&mut rx, &envelope, NOW_MS), ReceiverAdmit::Displayed { .. }));
    }

    #[test]
    fn ephemeral_receiver_bounds_and_lock() {
        row_dedup_bound_drops_new();
        row_conflicting_hash_rejected();
        row_channel_frame_cap();
        row_channel_byte_cap();
        row_eight_max_frames();
        row_inflight_counts();
        row_generation_lock_iled();
        row_expiry_frees_dedup();
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
        let early = signed(|e| {
            e.envelope_id = "early".to_owned();
            e.created_at = 1_002;
            e.ttl = 1;
        });
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
}

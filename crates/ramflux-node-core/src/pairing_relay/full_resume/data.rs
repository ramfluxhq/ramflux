// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared ciphertext queues. Header permits, original bodies and current native checks agree.
use super::{
    Arc, ChargedFullBody, FullNativeAdmission, FullResumeServer, FullRoute, FullSendPermit,
    PairingRelayError, Zeroizing, wire,
};
use std::ops::Range;

#[derive(Clone)]
pub struct FullDataFrame {
    body: Arc<ChargedFullBody>,
    range: Range<usize>,
    counter: u64,
}
impl FullDataFrame {
    /// Exact packet JSON slice excludes the sender's role token; no re-encoding/ciphertext copy.
    #[must_use]
    pub fn packet_bytes(&self) -> &[u8] {
        &self.body.as_bytes()[self.range.clone()]
    }
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }
}
#[derive(Clone, Copy)]
struct Stamp {
    counter: u64,
    hash: [u8; 32],
}
#[derive(Default)]
pub(super) struct DirectionQueue {
    frames: [Option<FullDataFrame>; 2],
    history: [Option<Stamp>; 2],
    next: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullDataAccepted {
    Accepted(u64),
    Duplicate(u64),
}
impl FullResumeServer {
    pub(in crate::pairing_relay) fn accept_send(
        &mut self,
        permit: FullSendPermit,
        body: Vec<u8>,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullDataAccepted, PairingRelayError> {
        let mut body = Zeroizing::new(body);
        let view = permit.verify_body(&body)?;
        let (index, signer) = self.authenticate(
            &FullRoute {
                lease_id: &permit.lease_id,
                epoch: &permit.epoch,
                role: &permit.role,
                token: &permit.token,
            },
            admission,
        )?;
        let ready = &mut self.ready[index];
        if !ready.control_sent {
            return Err(PairingRelayError::WrongContext);
        }
        let counter = view.packet.counter.0;
        // Local exact-retry fingerprint only, not a new signed/wire cryptographic domain.
        let hash = *blake3::hash(view.packet.ciphertext.as_bytes()).as_bytes();
        let queue = &mut ready.queues[signer];
        if counter < queue.next {
            return if queue
                .history
                .iter()
                .flatten()
                .any(|saved| saved.counter == counter && saved.hash == hash)
            {
                Ok(FullDataAccepted::Duplicate(counter))
            } else {
                Err(PairingRelayError::Replay)
            };
        }
        if counter != queue.next {
            return Err(PairingRelayError::Replay);
        }
        let position = queue
            .frames
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| PairingRelayError::busy(self.clock.monotonic_ms()))?;
        let range = view.packet_range(&body).map_err(|error| wire(&error))?;
        // Consume the exact pre-body reservation; final Arc drop wipes before quota release.
        let retained = permit.body.attach(std::mem::take(&mut *body))?;
        queue.frames[position] = Some(FullDataFrame { body: Arc::new(retained), range, counter });
        queue.history[0] = queue.history[1];
        queue.history[1] = Some(Stamp { counter, hash });
        queue.next += 1;
        ready.last_activity[signer] = self.clock.monotonic_ms();
        if signer == 1 && counter == 0 {
            ready.control.take();
        }
        Ok(FullDataAccepted::Accepted(counter))
    }
    pub(in crate::pairing_relay) fn poll_data(
        &mut self,
        route: &FullRoute<'_>,
        acknowledged: Option<u64>,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<Option<FullDataFrame>, PairingRelayError> {
        let (index, signer) = self.authenticate(route, admission)?;
        let ready = &mut self.ready[index];
        let peer = 1 - signer;
        let queue = &mut ready.queues[peer];
        if let Some(counter) = acknowledged {
            if counter >= queue.next {
                return Err(PairingRelayError::Replay);
            }
            for frame in &mut queue.frames {
                if frame.as_ref().is_some_and(|frame| frame.counter <= counter) {
                    frame.take();
                }
            }
        }
        let next = queue.frames.iter().flatten().min_by_key(|frame| frame.counter);
        let mono = self.clock.monotonic_ms();
        // Bulk polling uses byte credit, not the ordinary two-per-second data limiter.
        if let Some(frame) = next.filter(|frame| frame.packet_bytes().len() > 16_384) {
            ready.resources.charge_bytes(frame.packet_bytes().len(), mono)?;
        } else {
            let credit = ready.data_poll_credit[signer]
                .saturating_add(mono.saturating_sub(ready.data_poll_updated[signer]))
                .min(1000);
            if credit < 500 {
                return Err(PairingRelayError::busy(mono));
            }
            ready.data_poll_credit[signer] = credit - 500;
            ready.data_poll_updated[signer] = ready.data_poll_updated[signer].max(mono);
        }
        ready.last_activity[signer] = mono;
        Ok(next.cloned())
    }
}

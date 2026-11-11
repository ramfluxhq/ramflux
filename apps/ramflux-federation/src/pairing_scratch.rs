// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Listener payload accounting only. All role tokens, permits and account slots stay on the node.
use ramflux_node_core::pairing_relay::PairingRelayError;
use std::sync::{Arc, Mutex, OnceLock};
const PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const REQUESTS: usize = 8;
#[derive(Default)]
struct State {
    bytes: usize,
    requests: usize,
}
#[derive(Clone, Default)]
pub(crate) struct FullListenerScratch(Arc<Mutex<State>>);
pub(crate) struct FullScratchGuard {
    owner: FullListenerScratch,
    bytes: usize,
}
impl FullListenerScratch {
    pub(crate) fn global() -> Self {
        static OWNER: OnceLock<FullListenerScratch> = OnceLock::new();
        OWNER.get_or_init(Self::default).clone()
    }
    pub(crate) fn reserve(
        &self,
        request: usize,
        response: usize,
    ) -> Result<FullScratchGuard, PairingRelayError> {
        let bytes = request
            .checked_add(response)
            .ok_or(PairingRelayError::Busy { retry_after_ms: 1000 })?;
        let mut state =
            self.0.lock().map_err(|_| PairingRelayError::Busy { retry_after_ms: 1000 })?;
        let total = state
            .bytes
            .checked_add(bytes)
            .ok_or(PairingRelayError::Busy { retry_after_ms: 1000 })?;
        if bytes == 0 || total > PAYLOAD_BYTES || state.requests >= REQUESTS {
            return Err(PairingRelayError::Busy { retry_after_ms: 1000 });
        }
        state.bytes = total;
        state.requests += 1;
        Ok(FullScratchGuard { owner: self.clone(), bytes })
    }
}
impl Drop for FullScratchGuard {
    fn drop(&mut self) {
        let mut state = self.owner.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.bytes = state.bytes.saturating_sub(self.bytes);
        state.requests = state.requests.saturating_sub(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn full_listener_scratch_charges_both_copies_and_releases_only_its_owner() -> Result {
        let owner = FullListenerScratch::default();
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(owner.reserve(524_288, 524_288)?);
        }
        assert_eq!(owner.0.lock().map_err(|_| "lock")?.bytes, PAYLOAD_BYTES);
        assert!(owner.reserve(1, 1).is_err());
        held.pop();
        let small = owner.reserve(8192, 8192)?;
        drop(held);
        assert_eq!(owner.0.lock().map_err(|_| "lock")?.bytes, 16_384);
        drop(small);
        assert_eq!(owner.0.lock().map_err(|_| "lock")?.bytes, 0);
        let guards = (0..REQUESTS)
            .map(|_| owner.reserve(1, 1))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert!(owner.reserve(1, 1).is_err());
        drop(guards);
        assert!(owner.reserve(usize::MAX, 1).is_err());
        Ok(())
    }
}

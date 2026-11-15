// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One allocation owner for ordinary issued/live slots and full-data reconnect slots.
use super::{MAX_SLOTS, MAX_SLOTS_PER_ACCOUNT, PairingRelayError};
use std::sync::{Arc, Mutex};
struct Account {
    root: [u8; 32],
    count: usize,
}
struct State {
    total: usize,
    accounts: [Option<Account>; MAX_SLOTS],
}
#[derive(Clone)]
pub struct PairingAllocations {
    state: Arc<Mutex<State>>,
}
impl Default for PairingAllocations {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                total: 0,
                accounts: std::array::from_fn(|_| None),
            })),
        }
    }
}
impl PairingAllocations {
    /// Reserve before allocating an ordinary invitation or a fully proved data-only slot.
    /// Resource ownership grants no authentication or native authority.
    /// # Errors
    /// Busy at 64 combined slots, three/account or poisoned accounting.
    pub fn reserve(
        &self,
        root: [u8; 32],
        now: u64,
    ) -> Result<PairingAllocation, PairingRelayError> {
        let mut state = self.state.lock().map_err(|_| PairingRelayError::busy(now))?;
        if state.total >= MAX_SLOTS {
            return Err(PairingRelayError::busy(now));
        }
        if let Some(account) =
            state.accounts.iter_mut().flatten().find(|account| account.root == root)
        {
            if account.count >= MAX_SLOTS_PER_ACCOUNT {
                return Err(PairingRelayError::busy(now));
            }
            account.count += 1;
        } else {
            let account = state
                .accounts
                .iter_mut()
                .find(|account| account.is_none())
                .ok_or_else(|| PairingRelayError::busy(now))?;
            *account = Some(Account { root, count: 1 });
        }
        state.total += 1;
        Ok(PairingAllocation { state: Arc::clone(&self.state), root })
    }
    /// # Errors
    /// Refuses poisoned accounting state.
    pub fn counts(&self, root: &[u8; 32]) -> Result<(usize, usize), PairingRelayError> {
        let state = self.state.lock().map_err(|_| PairingRelayError::busy(0))?;
        Ok((
            state.total,
            state
                .accounts
                .iter()
                .flatten()
                .find(|account| &account.root == root)
                .map_or(0, |account| account.count),
        ))
    }
    #[must_use]
    pub const fn fixed_bytes() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Mutex<State>>()
            + 2 * std::mem::size_of::<usize>()
    }
}
/// One logical slot. Promotion moves its body while retaining this same reservation.
pub struct PairingAllocation {
    state: Arc<Mutex<State>>,
    root: [u8; 32],
}
impl Drop for PairingAllocation {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state
            .accounts
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|account| account.root == self.root))
        {
            if let Some(account) = entry.as_mut() {
                account.count = account.count.saturating_sub(1);
                if account.count == 0 {
                    *entry = None;
                }
            }
            state.total = state.total.saturating_sub(1);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn pairing_allocations_share_sixty_four_and_account_limits_across_owners() -> TestResult {
        let ordinary = PairingAllocations::default();
        let full = ordinary.clone();
        let mut held = Vec::new();
        for n in 0..64 {
            held.push(ordinary.reserve([n; 32], 0)?);
        }
        assert_eq!(full.counts(&[63; 32])?, (64, 1));
        assert!(full.reserve([65; 32], 0).is_err());
        drop(held.pop());
        let data = full.reserve([65; 32], 0)?;
        assert!(ordinary.reserve([66; 32], 0).is_err());
        drop(held);
        assert_eq!(ordinary.counts(&[65; 32])?, (1, 1));
        drop(data);
        let a = ordinary.reserve([1; 32], 0)?;
        let b = full.reserve([1; 32], 0)?;
        let c = full.reserve([1; 32], 0)?;
        assert!(ordinary.reserve([1; 32], 0).is_err());
        drop(a);
        drop(b);
        drop(c);
        assert_eq!(full.counts(&[1; 32])?, (0, 0));
        Ok(())
    }
}

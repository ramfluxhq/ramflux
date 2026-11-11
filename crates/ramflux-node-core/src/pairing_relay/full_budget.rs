// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resource ownership only. A budget permit is never a lease, branch proof or role token.
use super::PairingRelayError;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const SLOT_COUNT: usize = 2;
const BUFFER_COUNT: usize = 8;
const BUFFER_BYTES: usize = 524_288;
const TOTAL_BYTES: usize = 4_194_304;
const METADATA_BYTES: usize = 65_536;
const CONTROL_BYTES: usize = 16_384;

#[derive(Clone, Copy)]
pub enum FullDirection {
    Initiator,
    Responder,
}
impl FullDirection {
    const fn index(self) -> usize {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }
}
#[derive(Default)]
struct Direction {
    buffers: usize,
    large: usize,
}
struct Rate {
    tokens: u64,
    updated: u64,
    remainder: u64,
}
impl Rate {
    fn take(&mut self, bytes: usize, now: u64) -> Result<(), PairingRelayError> {
        let elapsed = now.saturating_sub(self.updated);
        let refill = u128::from(elapsed) * 4_194_304 + u128::from(self.remainder);
        let tokens = (u128::from(self.tokens) + refill / 1000).min(524_288);
        if tokens < bytes as u128 {
            return Err(PairingRelayError::busy(now));
        }
        self.tokens = u64::try_from(tokens)
            .map_err(|_| PairingRelayError::invalid("byte_credit"))?
            - u64::try_from(bytes).map_err(|_| PairingRelayError::invalid("body_size"))?;
        self.remainder = if tokens == 524_288 {
            0
        } else {
            u64::try_from(refill % 1000).map_err(|_| PairingRelayError::invalid("byte_credit"))?
        };
        self.updated = self.updated.max(now);
        Ok(())
    }
}
struct Slot {
    generation: u64,
    account: [u8; 32],
    directions: [Direction; 2],
    rate: Rate,
}
struct State {
    slots: [Option<Slot>; SLOT_COUNT],
    next: u64,
    bytes: usize,
    buffers: usize,
    owners: usize,
    external_metadata: usize,
}
impl State {
    fn metadata(&self, owners: usize, buffers: usize) -> usize {
        // Conservative owned metadata, including Arc counters and a charged body's future owner.
        self.external_metadata
            + std::mem::size_of::<Mutex<Self>>()
            + 2 * std::mem::size_of::<usize>()
            + owners * (std::mem::size_of::<Owner>() + 2 * std::mem::size_of::<usize>())
            + buffers * (std::mem::size_of::<ChargedFullBody>() + 2 * std::mem::size_of::<usize>())
    }
}
/// One node-owned meter shared by its two full-data slots, including retired in-flight bodies.
#[derive(Clone)]
pub struct FullBodyBudget {
    state: Arc<Mutex<State>>,
}
impl Default for FullBodyBudget {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                slots: std::array::from_fn(|_| None),
                next: 1,
                bytes: 0,
                buffers: 0,
                owners: 0,
                external_metadata: 0,
            })),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullBodyBudgetStats {
    pub slots: usize,
    pub buffers: usize,
    pub reserved_bytes: usize,
    pub metadata_bound_bytes: usize,
}
impl FullBodyBudget {
    /// Reserve a resource slot AFTER the verified-lease and BOTH fresh-branch proof owners agree.
    /// The caller must also reserve one of the node's shared 64 ordinary/full allocations.
    /// # Errors
    /// Busy at two full slots, one/account or the fixed metadata ceiling; poison fails closed.
    pub fn open_slot(
        &self,
        account: [u8; 32],
        now: u64,
    ) -> Result<FullBodySlot, PairingRelayError> {
        let mut state = self.state.lock().map_err(|_| PairingRelayError::busy(now))?;
        if state.slots.iter().flatten().any(|slot| slot.account == account)
            || state.metadata(state.owners + 1, state.buffers) > METADATA_BYTES
        {
            return Err(PairingRelayError::busy(now));
        }
        let index = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| PairingRelayError::busy(now))?;
        let generation = state.next;
        state.next = state.next.checked_add(1).ok_or_else(|| PairingRelayError::busy(now))?;
        state.slots[index] = Some(Slot {
            generation,
            account,
            directions: std::array::from_fn(|_| Direction::default()),
            rate: Rate { tokens: 524_288, updated: now, remainder: 0 },
        });
        state.owners += 1;
        Ok(FullBodySlot {
            owner: Arc::new(Owner { state: Arc::clone(&self.state), index, generation }),
        })
    }
    /// Charge bounded lease/challenge/queue metadata before creating its retained owner.
    /// The caller uses its compiled owner size plus bounded input capacities; no padding is allocated.
    /// # Errors
    /// Refuses zero/overflow charges, fixed metadata exhaustion or poisoned accounting.
    pub fn reserve_metadata(
        &self,
        bytes: usize,
        now: u64,
    ) -> Result<FullMetadataPermit, PairingRelayError> {
        let charged = bytes
            .checked_add(std::mem::size_of::<FullMetadataPermit>())
            .ok_or_else(|| PairingRelayError::busy(now))?;
        let mut state = self.state.lock().map_err(|_| PairingRelayError::busy(now))?;
        if bytes == 0
            || state
                .metadata(state.owners, state.buffers)
                .checked_add(charged)
                .is_none_or(|total| total > METADATA_BYTES)
        {
            return Err(PairingRelayError::busy(now));
        }
        state.external_metadata += charged;
        Ok(FullMetadataPermit { state: Arc::clone(&self.state), charged })
    }

    /// # Errors
    /// Refuses poisoned accounting state.
    pub fn stats(&self) -> Result<FullBodyBudgetStats, PairingRelayError> {
        let state = self.state.lock().map_err(|_| PairingRelayError::busy(0))?;
        Ok(FullBodyBudgetStats {
            slots: state.slots.iter().flatten().count(),
            buffers: state.buffers,
            reserved_bytes: state.bytes,
            metadata_bound_bytes: state.metadata(state.owners, state.buffers),
        })
    }
}
struct Owner {
    state: Arc<Mutex<State>>,
    index: usize,
    generation: u64,
}
impl Drop for Owner {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.slots[self.index].as_ref().is_some_and(|slot| slot.generation == self.generation) {
            state.slots[self.index] = None;
        }
        state.owners = state.owners.saturating_sub(1);
    }
}
/// Retained metadata remains charged until its actual owner is destroyed.
pub struct FullMetadataPermit {
    state: Arc<Mutex<State>>,
    charged: usize,
}
impl Drop for FullMetadataPermit {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.external_metadata = state.external_metadata.saturating_sub(self.charged);
    }
}

/// The authenticated relay slot keeps this owner; closing it cannot refund a borrowed body.
#[derive(Clone)]
pub struct FullBodySlot {
    owner: Arc<Owner>,
}
impl FullBodySlot {
    pub fn close(&self) {
        let mut state = self.owner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.slots[self.owner.index]
            .as_ref()
            .is_some_and(|slot| slot.generation == self.owner.generation)
        {
            state.slots[self.owner.index] = None;
        }
    }
    /// Charge the complete declared body BEFORE extending HTTP buffering past 16 KiB.
    /// Role-token authentication remains mandatory in the caller. One position/direction is
    /// reserved for a bounded control body; full-size data cannot occupy both positions.
    /// # Errors
    /// Refuses retired slots, excess bytes, full queues, metadata exhaustion and byte-rate Busy.
    pub fn reserve(
        &self,
        direction: FullDirection,
        bytes: usize,
        now: u64,
    ) -> Result<FullBodyPermit, PairingRelayError> {
        if bytes == 0 || bytes > BUFFER_BYTES {
            return Err(PairingRelayError::invalid("body_size"));
        }
        let mut state = self.owner.state.lock().map_err(|_| PairingRelayError::busy(now))?;
        let index = self.owner.index;
        let slot = state.slots[index]
            .as_ref()
            .filter(|slot| slot.generation == self.owner.generation)
            .ok_or(PairingRelayError::Retired)?;
        let role = direction.index();
        let large = bytes > CONTROL_BYTES;
        if state.buffers == BUFFER_COUNT
            || state.bytes.checked_add(bytes).is_none_or(|sum| sum > TOTAL_BYTES)
            || state.metadata(state.owners, state.buffers + 1) > METADATA_BYTES
            || slot.directions[role].buffers == 2
            || (large && slot.directions[role].large != 0)
        {
            return Err(PairingRelayError::busy(now));
        }
        let slot = state.slots[index].as_mut().ok_or(PairingRelayError::Retired)?;
        slot.rate.take(bytes, now)?;
        slot.directions[role].buffers += 1;
        slot.directions[role].large += usize::from(large);
        state.bytes += bytes;
        state.buffers += 1;
        Ok(FullBodyPermit {
            state: Arc::clone(&self.owner.state),
            index,
            generation: self.owner.generation,
            role,
            bytes,
            large,
        })
    }
}
/// Moves from the pre-body admission callback into the retained encrypted frame owner.
pub struct FullBodyPermit {
    state: Arc<Mutex<State>>,
    index: usize,
    generation: u64,
    role: usize,
    bytes: usize,
    large: bool,
}
impl Drop for FullBodyPermit {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.bytes = state.bytes.saturating_sub(self.bytes);
        state.buffers = state.buffers.saturating_sub(1);
        if let Some(slot) =
            state.slots[self.index].as_mut().filter(|slot| slot.generation == self.generation)
        {
            slot.directions[self.role].buffers =
                slot.directions[self.role].buffers.saturating_sub(1);
            slot.directions[self.role].large =
                slot.directions[self.role].large.saturating_sub(usize::from(self.large));
        }
    }
}
/// Wiped on last shared-frame release. Field order destroys the buffer before refunding credit.
pub struct ChargedFullBody {
    bytes: Zeroizing<Vec<u8>>,
    _permit: FullBodyPermit,
}
impl FullBodyPermit {
    /// Transfer the single already-charged allocation; no body copy or serialization occurs.
    /// # Errors
    /// Refuses a truncated body or an allocation capacity larger than its charged declaration.
    pub fn attach(self, bytes: Vec<u8>) -> Result<ChargedFullBody, PairingRelayError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != self.bytes || bytes.capacity() > self.bytes {
            return Err(PairingRelayError::invalid("body_capacity"));
        }
        Ok(ChargedFullBody { bytes, _permit: self })
    }
}
impl ChargedFullBody {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests;

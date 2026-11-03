// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reserve authenticated capacity, run durable work unlocked, then commit or roll back.
use super::{CustodyIngressLimiter, CustodyIngressPermit, State};
use crate::custody_budget_log::{CustodyAdmissionRefusal, node_retry, refuse};
use ramflux_protocol::custody::CustodyRefusal;
use std::time::{Duration, Instant};

struct Reservation<'a> {
    permit: &'a CustodyIngressPermit,
    reserved: bool,
    finished: bool,
}
impl CustodyIngressLimiter {
    fn grant_state<T>(&self, action: impl FnOnce(&mut State) -> T) -> T {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(test)]
        let started = Instant::now();
        let result = action(&mut state);
        #[cfg(test)]
        state.grant_lock_holds.push(started.elapsed());
        result
    }
}
impl CustodyIngressPermit {
    /// Reserve capacity, execute the callback without the limiter lock, then commit.
    /// Callers must clean up callback-created sessions if the final admission fails.
    /// # Errors
    /// Returns admission refusals, including revocation while the callback was running.
    pub fn grant<T>(
        &self,
        principal: &str,
        grant: impl FnOnce() -> T,
    ) -> Result<T, CustodyAdmissionRefusal> {
        self.try_grant(principal, || Ok::<T, std::convert::Infallible>(grant())).map(|r| match r {
            Ok(value) => value,
            Err(never) => match never {},
        })
    }
    /// Failed callbacks retain the original pre-authentication holder and deadline.
    /// The service admission lock orders durable callbacks against disconnect cleanup.
    /// # Errors
    /// Returns admission refusals; the nested result preserves callback errors.
    pub fn try_grant<T, E>(
        &self,
        principal: &str,
        grant: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, CustodyAdmissionRefusal> {
        self.try_grant_at(principal, Instant::now(), grant)
    }
    pub(super) fn try_grant_at<T, E>(
        &self,
        principal: &str,
        tick: Instant,
        grant: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, CustodyAdmissionRefusal> {
        let reserved = self.limiter.grant_state(|state| {
            CustodyIngressLimiter::prune(state, tick);
            let Some(h) = state.holders.get(&self.holder) else {
                return Err(refuse("unavailable_holder", 1, 0, CustodyRefusal::Busy, None));
            };
            if self.is_revoked() {
                return Err(refuse("revoked_holder", 1, 0, CustodyRefusal::Busy, None));
            }
            if principal.is_empty() || principal.len() > 512 {
                return Err(refuse(
                    "principal_bytes",
                    principal.len(),
                    if principal.is_empty() { 1 } else { 512 },
                    CustodyRefusal::Busy,
                    None,
                ));
            }
            if h.granting {
                return Err(refuse("grant_in_progress", 1, 0, CustodyRefusal::Busy, None));
            }
            if h.principal.as_ref().is_some_and(|current| current != principal) {
                return Err(refuse("principal_binding_mismatch", 1, 0, CustodyRefusal::Busy, None));
            }
            let reserved = h.principal.is_none();
            if reserved
                && let Some(limit) = self.limiter.authenticated_limit
                && state.authenticated >= limit
            {
                return Err(refuse(
                    "authenticated",
                    state.authenticated,
                    limit,
                    CustodyRefusal::Busy,
                    Some(node_retry()),
                ));
            }
            if let Some(h) = state.holders.get_mut(&self.holder) {
                h.granting = true;
            }
            if reserved {
                state.authenticated += 1;
            }
            Ok(reserved)
        })?;
        let mut reservation = Reservation { permit: self, reserved, finished: false };
        let result = grant();
        self.limiter.grant_state(|state| {
            // Real elapsed time matters even if no other arrival pruned this holder.
            CustodyIngressLimiter::prune(state, tick + tick.elapsed());
            reservation.release(state);
            reservation.finished = true;
            if self.is_revoked() {
                return Err(refuse("revoked_holder", 1, 0, CustodyRefusal::Busy, None));
            }
            let Some(mut h) = state.holders.remove(&self.holder) else {
                return Err(refuse("unavailable_holder", 1, 0, CustodyRefusal::Busy, None));
            };
            if result.is_ok() && reserved {
                state.deadlines.remove(&(h.deadline, self.holder));
                CustodyIngressLimiter::untrack_preauth(state, self.holder, &h);
                h.principal = Some(principal.to_owned());
                h.deadline = tick + Duration::from_mins(15);
                state.deadlines.insert((h.deadline, self.holder));
                state.authenticated += 1;
            }
            state.holders.insert(self.holder, h);
            Ok(result)
        })
    }
}
impl Reservation<'_> {
    fn release(&self, state: &mut State) {
        // Removal of a pre-auth holder leaves its A reservation to this owner.
        if self.reserved {
            state.authenticated -= 1;
        }
        if let Some(h) = state.holders.get_mut(&self.permit.holder) {
            h.granting = false;
        }
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.permit.limiter.grant_state(|state| self.release(state));
        }
    }
}

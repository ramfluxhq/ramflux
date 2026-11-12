// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Leadership among tabs as a state machine without I/O.
//!
//! Exactly one context holds the writer lock, the store and the gateway session. Leadership
//! moves only cooperatively: the holder drains, closes the store and the socket, and then
//! releases the lock. Nothing in this module can produce a steal.

/// Where this context stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaderState {
    /// No lock request is pending. The context is a follower or idle.
    Follower,
    /// An ordinary exclusive lock request is queued.
    Waiting,
    /// The lock is held and the store is being opened.
    OpeningStore,
    /// The lock is held, the store is open, the gateway session may exist.
    Leading,
    /// No new operation is admitted; in-flight operations finish or fail.
    Draining,
    /// Store and socket are being closed before the lock is released.
    Closing,
}

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaderEvent {
    /// The page wants a core.
    Start,
    /// The Web Locks callback ran: the lock is held.
    LockGranted,
    StoreOpened,
    StoreOpenFailed,
    /// This page became hidden while a follower is visible.
    HiddenWithVisibleFollower,
    /// The last in-flight operation finished or failed.
    Drained,
    /// Every database connection, OPFS handle and the socket are closed.
    Closed,
    /// A follower's ping to the leader went unanswered for five seconds.
    LeaderPingTimedOut,
    /// The page is going away.
    Shutdown,
}

/// What the host must do. The order within one transition is the order of the variants returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaderAction {
    /// `navigator.locks.request(name, { mode: "exclusive" })`. Never `steal`, never `ifAvailable`.
    RequestLock,
    OpenStore,
    /// Open one gateway session with `Resume`.
    OpenGatewaySession,
    StopAdmitting,
    FailInFlight,
    CloseStoreAndSocket,
    /// Resolve the lock callback's promise.
    ReleaseLock,
    /// Tell the page the leader is unavailable. This never opens a store or a session.
    ReportLeaderUnavailable,
    /// Ask again after a delay; the lock is released first.
    RetryLater,
}

/// Follower liveness probe period and deadline.
pub const LEADER_PING_TIMEOUT_MS: u32 = 5_000;
/// Delay before a context that failed to open the store queues for the lock again.
pub const STORE_RETRY_DELAY_MS: u32 = 5_000;

/// Advance the machine. An event that is not legal in the state changes nothing.
#[must_use]
pub fn step(state: LeaderState, event: LeaderEvent) -> (LeaderState, &'static [LeaderAction]) {
    use LeaderAction as A;
    use LeaderEvent as E;
    use LeaderState as S;
    match (state, event) {
        (S::Follower, E::Start) => (S::Waiting, &[A::RequestLock]),
        (S::Waiting, E::LockGranted) => (S::OpeningStore, &[A::OpenStore]),
        (S::OpeningStore, E::StoreOpened) => (S::Leading, &[A::OpenGatewaySession]),
        // A failed open leaves this context inactive: release, wait, queue again. No steal.
        (S::OpeningStore, E::StoreOpenFailed) => (S::Follower, &[A::ReleaseLock, A::RetryLater]),
        (S::Leading, E::HiddenWithVisibleFollower) => (S::Draining, &[A::StopAdmitting]),
        (S::Leading, E::Shutdown) => {
            (S::Closing, &[A::StopAdmitting, A::FailInFlight, A::CloseStoreAndSocket])
        }
        (S::Draining, E::Drained) => (S::Closing, &[A::CloseStoreAndSocket]),
        (S::Draining, E::Shutdown) => (S::Closing, &[A::FailInFlight, A::CloseStoreAndSocket]),
        (S::OpeningStore, E::Shutdown) => (S::Closing, &[A::CloseStoreAndSocket]),
        (S::Closing, E::Closed) => (S::Follower, &[A::ReleaseLock]),
        // An unanswered ping is a report, never an authorization.
        (S::Follower | S::Waiting, E::LeaderPingTimedOut) => (state, &[A::ReportLeaderUnavailable]),
        _ => (state, &[]),
    }
}

/// Whether this context may open OPFS or a gateway session.
#[must_use]
pub const fn may_own_store(state: LeaderState) -> bool {
    matches!(state, LeaderState::OpeningStore | LeaderState::Leading | LeaderState::Draining)
}

#[cfg(test)]
mod tests {
    use super::*;
    use LeaderAction as A;
    use LeaderEvent as E;
    use LeaderState as S;

    #[test]
    fn a_follower_becomes_leader_only_through_the_lock_and_an_open_store() {
        let (state, actions) = step(S::Follower, E::Start);
        assert_eq!((state, actions), (S::Waiting, &[A::RequestLock][..]));
        assert!(!may_own_store(state));
        let (state, actions) = step(state, E::LockGranted);
        assert_eq!(actions, &[A::OpenStore]);
        let (state, actions) = step(state, E::StoreOpened);
        assert_eq!((state, actions), (S::Leading, &[A::OpenGatewaySession][..]));
    }

    #[test]
    fn handoff_closes_everything_before_the_lock_is_released() {
        let (state, actions) = step(S::Leading, E::HiddenWithVisibleFollower);
        assert_eq!(actions, &[A::StopAdmitting]);
        let (state, actions) = step(state, E::Drained);
        assert_eq!(actions, &[A::CloseStoreAndSocket]);
        assert!(!may_own_store(state));
        let (state, actions) = step(state, E::Closed);
        assert_eq!((state, actions), (S::Follower, &[A::ReleaseLock][..]));
    }

    #[test]
    fn an_unanswered_ping_never_opens_a_store_or_requests_a_steal() {
        for state in [S::Follower, S::Waiting] {
            let (next, actions) = step(state, E::LeaderPingTimedOut);
            assert_eq!(next, state);
            assert_eq!(actions, &[A::ReportLeaderUnavailable]);
            assert!(!may_own_store(next));
        }
    }

    #[test]
    fn a_failed_store_open_releases_and_retries_without_leading() {
        let (state, actions) = step(S::OpeningStore, E::StoreOpenFailed);
        assert_eq!((state, actions), (S::Follower, &[A::ReleaseLock, A::RetryLater][..]));
    }

    #[test]
    fn a_thawed_former_leader_cannot_resume_its_store() {
        let (state, _) = step(S::Follower, E::StoreOpened);
        assert_eq!(state, S::Follower);
        let (state, actions) = step(S::Follower, E::Drained);
        assert_eq!((state, actions.len()), (S::Follower, 0));
    }
}

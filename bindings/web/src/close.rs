// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Close codes of the web listener and what the client does with each.

/// Close codes the gateway sends on the web listener.
pub mod code {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const UNSUPPORTED_DATA: u16 = 1003;
    pub const POLICY: u16 = 1008;
    pub const MESSAGE_TOO_BIG: u16 = 1009;
    pub const INTERNAL_ERROR: u16 = 1011;
    pub const BAD_FRAME: u16 = 4400;
    pub const REAUTH_REQUIRED: u16 = 4401;
    pub const AUTH_REFUSED: u16 = 4403;
    pub const TIMEOUT: u16 = 4408;
    pub const SESSION_REPLACED: u16 = 4409;
    pub const DEVICE_GONE: u16 = 4410;
    pub const WINDOW_EXCEEDED: u16 = 4413;
    pub const RATE_LIMITED: u16 = 4429;
    pub const NODE_UNAVAILABLE: u16 = 4503;
}

/// The only code and reason a browser sends.
pub const CLIENT_CLOSE_CODE: u16 = code::NORMAL;
pub const CLIENT_CLOSE_REASON: &str = "normal";

const DEFAULT_FIRST_DELAY_MS: u64 = 1_000;
const DEFAULT_MAX_DELAY_MS: u64 = 60_000;
const PROTOCOL_ERROR_MIN_DELAY_MS: u64 = 60_000;
const AUTH_REFUSED_MIN_DELAY_MS: u64 = 30_000;
const RATE_LIMITED_FIRST_DELAY_MS: u64 = 5_000;
const RATE_LIMITED_MAX_DELAY_MS: u64 = 300_000;
/// A session that lived this long resets the backoff.
pub const STABLE_SESSION_MS: u64 = 60_000;
/// Consecutive refusals after which the user is told the browser is no longer linked.
pub const AUTH_REFUSED_NOTICE_AFTER: u32 = 3;

/// What the client does after a close. The reason text is never shown and never trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseAction {
    /// Reconnect after the delay with a fresh `web_origin_bound` proof.
    Reconnect { delay_ms: u64 },
    /// Reconnect and additionally tell the user the browser may no longer be linked.
    ReconnectAndWarnUnlinked { delay_ms: u64 },
    /// Another context of this device holds the session. Do not reconnect.
    StopReplaced,
    /// The node expired or revoked this device. Stop, show "unlinked", offer a local wipe.
    /// Local data is never wiped automatically.
    StopUnlinked,
    /// The client itself closed. Nothing to do.
    Idle,
}

/// Reconnect policy state. Jitter comes from the caller so the policy stays deterministic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconnectPolicy {
    attempt: u32,
    auth_refused_in_a_row: u32,
}

impl ReconnectPolicy {
    /// Decide after a close. `locally_closed` is true when this client sent the Close;
    /// `session_lived_ms` is the time the gateway session existed; `jitter` is a uniform random
    /// value used for the ±20 % spread.
    pub fn on_close(
        &mut self,
        close_code: u16,
        locally_closed: bool,
        session_lived_ms: u64,
        jitter: u32,
    ) -> CloseAction {
        if locally_closed {
            return CloseAction::Idle;
        }
        if session_lived_ms >= STABLE_SESSION_MS {
            self.attempt = 0;
            self.auth_refused_in_a_row = 0;
        }
        if close_code != code::AUTH_REFUSED {
            self.auth_refused_in_a_row = 0;
        }
        match close_code {
            code::SESSION_REPLACED => CloseAction::StopReplaced,
            code::DEVICE_GONE => CloseAction::StopUnlinked,
            code::REAUTH_REQUIRED => CloseAction::Reconnect { delay_ms: 0 },
            code::AUTH_REFUSED => {
                self.auth_refused_in_a_row = self.auth_refused_in_a_row.saturating_add(1);
                let delay_ms = self.delay(AUTH_REFUSED_MIN_DELAY_MS, DEFAULT_MAX_DELAY_MS, jitter);
                if self.auth_refused_in_a_row >= AUTH_REFUSED_NOTICE_AFTER {
                    CloseAction::ReconnectAndWarnUnlinked { delay_ms }
                } else {
                    CloseAction::Reconnect { delay_ms }
                }
            }
            code::RATE_LIMITED => CloseAction::Reconnect {
                delay_ms: self.delay(RATE_LIMITED_FIRST_DELAY_MS, RATE_LIMITED_MAX_DELAY_MS, jitter),
            },
            code::PROTOCOL_ERROR | code::BAD_FRAME | code::UNSUPPORTED_DATA => {
                CloseAction::Reconnect {
                    delay_ms: self.delay(PROTOCOL_ERROR_MIN_DELAY_MS, PROTOCOL_ERROR_MIN_DELAY_MS, jitter),
                }
            }
            _ => CloseAction::Reconnect {
                delay_ms: self.delay(DEFAULT_FIRST_DELAY_MS, DEFAULT_MAX_DELAY_MS, jitter),
            },
        }
    }

    /// `first * 2^attempt`, capped, then spread by ±20 %.
    fn delay(&mut self, first_ms: u64, max_ms: u64, jitter: u32) -> u64 {
        let shift = self.attempt.min(16);
        self.attempt = self.attempt.saturating_add(1);
        let base = first_ms.saturating_mul(1_u64 << shift).min(max_ms.max(first_ms));
        let spread = base / 5;
        if spread == 0 {
            return base;
        }
        base - spread + u64::from(jitter) % (2 * spread + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_replaced_and_device_gone_never_reconnect() {
        let mut policy = ReconnectPolicy::default();
        assert_eq!(policy.on_close(code::SESSION_REPLACED, false, 0, 0), CloseAction::StopReplaced);
        assert_eq!(policy.on_close(code::DEVICE_GONE, false, 0, 0), CloseAction::StopUnlinked);
    }

    #[test]
    fn reauth_reconnects_immediately() {
        let mut policy = ReconnectPolicy::default();
        assert_eq!(
            policy.on_close(code::REAUTH_REQUIRED, false, 0, 0),
            CloseAction::Reconnect { delay_ms: 0 }
        );
    }

    #[test]
    fn auth_refused_waits_at_least_24_seconds_and_warns_on_the_third() {
        let mut policy = ReconnectPolicy::default();
        for _ in 0..2 {
            let CloseAction::Reconnect { delay_ms } = policy.on_close(code::AUTH_REFUSED, false, 0, 0)
            else {
                unreachable!("the first two refusals only back off")
            };
            assert!(delay_ms >= 24_000);
        }
        assert!(matches!(
            policy.on_close(code::AUTH_REFUSED, false, 0, 0),
            CloseAction::ReconnectAndWarnUnlinked { .. }
        ));
    }

    #[test]
    fn default_backoff_doubles_to_a_minute_within_the_jitter_band() {
        let mut policy = ReconnectPolicy::default();
        let mut last = 0;
        for _ in 0..10 {
            let CloseAction::Reconnect { delay_ms } = policy.on_close(code::TIMEOUT, false, 0, 7)
            else {
                unreachable!("a timeout reconnects")
            };
            assert!(delay_ms <= 72_000);
            last = delay_ms;
        }
        assert!(last >= 48_000);
    }

    #[test]
    fn a_stable_session_resets_the_backoff() {
        let mut policy = ReconnectPolicy::default();
        for _ in 0..6 {
            let _ = policy.on_close(code::TIMEOUT, false, 0, 0);
        }
        let CloseAction::Reconnect { delay_ms } =
            policy.on_close(code::TIMEOUT, false, STABLE_SESSION_MS, 0)
        else {
            unreachable!("a timeout reconnects")
        };
        assert!(delay_ms <= 1_200);
    }

    #[test]
    fn a_local_close_does_nothing() {
        let mut policy = ReconnectPolicy::default();
        assert_eq!(policy.on_close(code::NORMAL, true, 0, 0), CloseAction::Idle);
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::BTreeMap;

use crate::{ProtocolError, SignedRequest};

pub const REPLAY_WINDOW_SECONDS: i64 = 900;
pub const MAX_ENVELOPE_TTL_SECONDS: i64 = 604_800;
pub const MAX_ENVELOPE_TTL_SECONDS_U32: u32 = 604_800;
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 120;

#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    accepted: BTreeMap<String, i64>,
}

impl ReplayGuard {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks M1.1 `SignedRequest` replay rules and records the request key.
    ///
    /// # Errors
    /// Returns an error when the request is expired, valid for too long, or duplicated.
    pub fn check_signed_request(
        &mut self,
        request: &SignedRequest,
        now_unix_seconds: i64,
    ) -> Result<(), ProtocolError> {
        if now_unix_seconds > request.expires_at {
            return Err(ProtocolError::SignedRequestExpired);
        }
        if request.created_at > now_unix_seconds + MAX_CLOCK_SKEW_SECONDS {
            return Err(ProtocolError::SignedRequestFromFuture);
        }
        let validity_window = request.expires_at.saturating_sub(request.created_at);
        if validity_window > MAX_ENVELOPE_TTL_SECONDS {
            return Err(ProtocolError::SignedRequestExpiryTooLong);
        }

        self.prune(now_unix_seconds);
        let key = request.replay_tuple_key();
        if self.accepted.insert(key.clone(), request.expires_at).is_some() {
            return Err(ProtocolError::Replay(key));
        }
        Ok(())
    }

    fn prune(&mut self, now_unix_seconds: i64) {
        self.accepted.retain(|_key, expires_at| *expires_at >= now_unix_seconds);
    }
}

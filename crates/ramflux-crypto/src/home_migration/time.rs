// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent account-time and source-node-time bounds; timestamps never order heads.
use super::{CryptoError, reject};
use ramflux_protocol::{
    MAX_SAFE_JSON_INTEGER,
    home_migration::{
        Authorization, FORWARD_SECONDS, MAX_COMMIT_DELAY, MAX_SEAL_DELAY, Offer, Receipt,
        SKEW_SECONDS,
    },
};
/// Last possible source commit according to account-signed time, independent of B.
/// # Errors
/// Rejects overflow, unsafe integers and an unsupported delay.
pub fn hard_deadline(authorization: &Authorization) -> Result<u64, CryptoError> {
    if authorization.max_commit_delay == 0 || authorization.max_commit_delay > MAX_COMMIT_DELAY {
        return Err(reject("migration commit delay invalid"));
    }
    authorization
        .issued_at
        .checked_add(MAX_SEAL_DELAY)
        .and_then(|v| v.checked_add(authorization.max_commit_delay))
        .and_then(|v| v.checked_add(2 * SKEW_SECONDS))
        .filter(|v| *v <= MAX_SAFE_JSON_INTEGER)
        .ok_or_else(|| reject("migration deadline overflow"))
}
/// Check management-authorized time limits before signing or first commit.
/// # Errors
/// Rejects expired/future authorizations, invalid seal bounds and forwarding durations.
pub fn authorization_bounds(a: &Authorization, now: u64) -> Result<(), CryptoError> {
    if now > MAX_SAFE_JSON_INTEGER
        || a.issued_at > now.saturating_add(SKEW_SECONDS)
        || a.seal_until < a.issued_at
        || a.seal_until > a.issued_at.saturating_add(MAX_SEAL_DELAY)
        || now > hard_deadline(a)?
        || a.forward_seconds != FORWARD_SECONDS
        || a.next_home_epoch == 0
    {
        return Err(reject("migration authorization time bounds"));
    }
    Ok(())
}
/// Check a destination offer against the client's trusted clock.
/// # Errors
/// Rejects far-future/backdated offers, nonconstant lifetimes and unsupported policy.
pub fn offer_bounds(offer: &Offer, now: u64) -> Result<(), CryptoError> {
    if offer.issued_at.abs_diff(now) > SKEW_SECONDS
        || offer.accept_until
            != offer
                .issued_at
                .checked_add(MAX_SEAL_DELAY)
                .ok_or_else(|| reject("migration deadline overflow"))?
        || now > offer.accept_until
        || offer.max_commit_delay != MAX_COMMIT_DELAY
        || offer.forward_seconds != FORWARD_SECONDS
    {
        return Err(reject("migration offer time bounds"));
    }
    Ok(())
}
/// A's clock must meet both its account-bound maximum and B's actual seal deadline.
/// # Errors
/// Rejects forged seal clocks, mismatched limits and a late first commit.
pub fn commit_bounds(
    a: &Authorization,
    offer: &Offer,
    seal: &Receipt,
    now: u64,
) -> Result<u64, CryptoError> {
    authorization_bounds(a, now)?;
    let sealed = seal.sealed_at.ok_or_else(|| reject("migration seal time missing"))?;
    let deadline = sealed
        .checked_add(a.max_commit_delay)
        .ok_or_else(|| reject("migration deadline overflow"))?;
    if offer.issued_at > now.saturating_add(SKEW_SECONDS)
        || offer.max_commit_delay != MAX_COMMIT_DELAY
        || offer.forward_seconds != FORWARD_SECONDS
        || sealed < offer.issued_at.saturating_sub(SKEW_SECONDS)
        || a.seal_until > offer.accept_until
        || a.max_commit_delay > offer.max_commit_delay
        || offer.accept_until
            != offer
                .issued_at
                .checked_add(MAX_SEAL_DELAY)
                .ok_or_else(|| reject("migration deadline overflow"))?
        || sealed > a.seal_until
        || sealed < a.issued_at.saturating_sub(SKEW_SECONDS)
        || sealed > now.saturating_add(SKEW_SECONDS)
        || seal.commit_deadline != Some(deadline)
        || now > deadline
        || now > hard_deadline(a)?
    {
        return Err(reject("migration commit expired or seal bounds"));
    }
    Ok(deadline)
}

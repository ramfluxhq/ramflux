// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pure exclusive-deadline arithmetic. Authority, signatures, public-SPK selection
//! expiry and monotone clock trust must be established separately by the caller.

/// The selected native bootstrap mode; absence is distinct from an all-zero OPK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapMode {
    Opk,
    SpkOnly,
}

/// Public bounds from the authenticated lease/header, verified SPK and routed envelope.
/// `spk_validity_seconds` is the caller's checked difference of signed expiry/issue times.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlineInputs {
    pub mode: BootstrapMode,
    pub now: u64,
    pub deadline: u64,
    pub ttl: u64,
    pub spk_validity_seconds: u64,
    pub leased_at: u64,
    pub issued_at: u64,
    pub spk_expires_at: u64,
    pub envelope_created_at: u64,
}

/// Fail-closed time validation error; no arithmetic wraps or saturates a bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeadlineError {
    #[error("bootstrap time arithmetic overflow")]
    Overflow,
    #[error("bootstrap TTL or SPK validity exceeds policy")]
    Policy,
    #[error("lease timestamp exceeds custody clock skew")]
    FutureLease,
    #[error("bootstrap deadline expired")]
    Expired,
    #[error("bootstrap deadline exceeds a delivery bound")]
    ExceedsBound,
}

/// Compute the minimum delivery bound without extending it by clock skew.
/// # Errors
/// Rejects TTL/validity policy violations, future leases and any conversion/add overflow.
pub(crate) fn deadline_ceiling(input: &DeadlineInputs) -> Result<u64, DeadlineError> {
    let horizon =
        u64::try_from(crate::MAX_ENVELOPE_TTL_SECONDS).map_err(|_| DeadlineError::Overflow)?;
    let validity = horizon.checked_mul(2).ok_or(DeadlineError::Overflow)?;
    if input.ttl > horizon || input.spk_validity_seconds > validity {
        return Err(DeadlineError::Policy);
    }
    let latest_lease =
        input.now.checked_add(crate::custody::CLOCK_SKEW_SECONDS).ok_or(DeadlineError::Overflow)?;
    if input.leased_at > latest_lease {
        return Err(DeadlineError::FutureLease);
    }
    let start = match input.mode {
        BootstrapMode::Opk => input.leased_at,
        BootstrapMode::SpkOnly => input.issued_at,
    };
    let start_limit = start.checked_add(horizon).ok_or(DeadlineError::Overflow)?;
    let spk_limit = input.spk_expires_at.checked_add(horizon).ok_or(DeadlineError::Overflow)?;
    let envelope_limit =
        input.envelope_created_at.checked_add(input.ttl).ok_or(DeadlineError::Overflow)?;
    Ok(start_limit.min(spk_limit).min(envelope_limit))
}

/// Enforce `now < D` and all three independent, mode-correct upper bounds.
/// # Errors
/// Returns policy/overflow errors, expiry at equality, or a deadline beyond its ceiling.
pub fn validate_bootstrap_deadline(input: &DeadlineInputs) -> Result<(), DeadlineError> {
    let ceiling = deadline_ceiling(input)?;
    if input.now < input.deadline {
        if input.deadline <= ceiling { Ok(()) } else { Err(DeadlineError::ExceedsBound) }
    } else {
        Err(DeadlineError::Expired)
    }
}

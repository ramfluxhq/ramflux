// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Large-group client (LARGE-GROUP-01 P1): per-account group state, the token scheduler and the
//! member-side key checks. The host sees only pseudonym-signed requests (design 2.2).

pub(crate) mod check;
pub(crate) mod ops;
pub(crate) mod read;
pub(crate) mod state;

use ramflux_crypto::large_group::LgError;

use crate::SdkError;

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn lg_err(error: LgError) -> SdkError {
    SdkError::LocalBus(format!("large group: {error}"))
}

pub(crate) fn lg_msg(message: &str) -> SdkError {
    SdkError::LocalBus(format!("large group: {message}"))
}

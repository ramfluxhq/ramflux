// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission rules for new secrets: the six-digit account code and the backup archive
//! passphrase. The two rules never share a secret: a six-digit code is refused as an archive
//! passphrase.

mod archive;
mod code;
mod policy_error;

pub use archive::{
    MIN_ACCEPTED_PASSPHRASE_SCALARS, MIN_PASSPHRASE_SCALARS, check_new_archive_passphrase,
};
pub(crate) use code::admit_new_passphrase;
pub use code::{ACCOUNT_CODE_DIGITS, check_new_passphrase};
pub use policy_error::PassphrasePolicyError;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed service errors; lookup conceals every nonresolvable state.
use ramflux_protocol::username_directory::{DirectoryCode as Code, DirectoryFailure};

#[must_use]
pub fn failure(code: Code) -> DirectoryFailure {
    let retry_after_ms = match code {
        Code::RateLimited
        | Code::Capacity
        | Code::DirectoryUnavailable
        | Code::OperationPending => Some(1000),
        _ => None,
    };
    DirectoryFailure { code, retry_after_ms }
}

#[must_use]
pub const fn http_status(code: Code) -> u16 {
    match code {
        Code::AuthenticationRequired => 401,
        Code::InvalidUsername
        | Code::InvalidProfile
        | Code::InvalidAvatar
        | Code::UnsupportedVersion => 400,
        Code::SignatureInvalid => 403,
        Code::NotFound => 404,
        Code::RateLimited => 429,
        Code::Capacity | Code::DirectoryUnavailable | Code::ClockUnsafe => 503,
        Code::UsernameTaken
        | Code::UsernameHeld
        | Code::UsernameReserved
        | Code::OperationPending
        | Code::StaleEpoch
        | Code::Replay
        | Code::OwnershipMismatch
        | Code::KeyChanged
        | Code::NameChanged
        | Code::StaleProfile
        | Code::ProfileRollback
        | Code::ProfileEquivocation
        | Code::ProfileDowngrade
        | Code::MigrationRequired
        | Code::AccountDeleted => 409,
    }
}

#[must_use]
pub const fn lookup_code(code: Code) -> Code {
    match code {
        Code::NotFound
        | Code::AccountDeleted
        | Code::UsernameHeld
        | Code::UsernameReserved
        | Code::UsernameTaken => Code::NotFound,
        other => other,
    }
}

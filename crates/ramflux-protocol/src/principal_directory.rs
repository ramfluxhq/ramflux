// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed directory outcomes shared by authenticated gateways and SDK clients.
use serde::{Deserialize, Serialize};
/// Stable machine-readable identity directory and registration failures.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDirectoryReason {
    AuthenticationRequired,
    RateLimited,
    Capacity,
    PrincipalIdAmbiguous,
    PrincipalIdTaken,
    DeviceIdTaken,
    InvalidRegistration,
    RegistrationReplay,
    RegistrationUnavailable,
}
/// Known and unknown directory results have the same outer shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrincipalLookupResponse<T> {
    pub manifest: Option<T>,
    pub reason_code: Option<IdentityDirectoryReason>,
}
/// A registration error remains typed across the router/gateway boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityRegistrationFailure {
    pub error: IdentityRegistrationFailureBody,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityRegistrationFailureBody {
    pub reason_code: IdentityDirectoryReason,
}

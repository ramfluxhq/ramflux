// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lease renewal remains an actionable authority refusal for C consumers.
use super::*;

#[test]
fn native_group_lease_unavailable_is_permission_denied_in_c_abi() {
    let error = SdkError::Crypto(ramflux_crypto::CryptoError::GroupLeaseUnavailable);
    let mapped = map_sdk_error(&error);
    assert_eq!(mapped.code, RamfluxErrorCode::PermissionDenied);
    assert!(mapped.message.contains("refresh branch authority"));
}

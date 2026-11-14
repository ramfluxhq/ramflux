// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pin the public additive ABI registry. Pairing call/buffer behavior has separate tests.
use super::{RAMFLUX_ERR_PAIRING_REFUSED, RAMFLUX_ERR_PAIRING_STALE, RamfluxErrorCode as Code};

#[test]
fn pairing_abi_error_codes_are_additive() {
    let existing = [
        (Code::Ok, 0, "Ok"),
        (Code::InvalidArgument, 1, "InvalidArgument"),
        (Code::InvalidCanonicalJson, 2, "InvalidCanonicalJson"),
        (Code::UnsupportedVersion, 3, "UnsupportedVersion"),
        (Code::CapabilityRejected, 4, "CapabilityRejected"),
        (Code::AuthFailed, 5, "AuthFailed"),
        (Code::DeviceRevoked, 6, "DeviceRevoked"),
        (Code::CryptoFailed, 7, "CryptoFailed"),
        (Code::StorageFailed, 8, "StorageFailed"),
        (Code::TransportUnavailable, 9, "TransportUnavailable"),
        (Code::Timeout, 10, "Timeout"),
        (Code::ReplayRejected, 11, "ReplayRejected"),
        (Code::PermissionDenied, 12, "PermissionDenied"),
        (Code::McpGrantRejected, 13, "McpGrantRejected"),
        (Code::ObjectTransferFailed, 14, "ObjectTransferFailed"),
        (Code::RateLimited, 15, "RateLimited"),
        (Code::Internal, 16, "Internal"),
        (Code::PanicAborted, 17, "PanicAborted"),
        (Code::AccountBusy, 18, "AccountBusy"),
        (Code::ObjectErased, 19, "ObjectErased"),
        (Code::ObjectIdentityConflict, 20, "ObjectIdentityConflict"),
        (Code::ObjectOwnershipUnverified, 21, "ObjectOwnershipUnverified"),
        (Code::CustodyForkFenced, 22, "CustodyForkFenced"),
        (Code::SchemaResetRequired, 23, "SchemaResetRequired"),
    ];
    for (code, number, name) in existing {
        assert_eq!(code as i32, number, "changed existing {name}");
        assert_eq!(code.name(), name);
        assert_ne!(
            code as i32, RAMFLUX_ERR_PAIRING_REFUSED,
            "pairing code aliases existing {name}"
        );
        assert_ne!(code as i32, RAMFLUX_ERR_PAIRING_STALE, "pairing code aliases existing {name}");
    }
    for (status, number) in [
        (super::v2::RamfluxV2Status::Pending, 24),
        (super::v2::RamfluxV2Status::Cancelled, 25),
        (super::v2::RamfluxV2Status::Closed, 26),
        (super::v2::RamfluxV2Status::ResyncRequired, 27),
    ] {
        assert_eq!(status as i32, number, "test: changed existing v2 transport status");
        assert_ne!(
            status as i32, RAMFLUX_ERR_PAIRING_REFUSED,
            "test: pairing refusal aliases a v2 transport status"
        );
        assert_ne!(
            status as i32, RAMFLUX_ERR_PAIRING_STALE,
            "test: pairing stale callback aliases a v2 transport status"
        );
    }
    for (code, number, name) in
        [(Code::PairingRefused, 28, "PairingRefused"), (Code::PairingStale, 29, "PairingStale")]
    {
        assert_eq!(code as i32, number);
        assert_eq!(code.name(), name);
    }
    assert_eq!(RAMFLUX_ERR_PAIRING_REFUSED, 28);
    assert_eq!(RAMFLUX_ERR_PAIRING_STALE, 29);
}

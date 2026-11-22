// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify the SDK-bundled ABI 5 library. The release seed stays outside the repository.
use super::super::invalid;
use super::gate::card_err;
use crate::SdkError;
use ramflux_card::{AcceptancePolicy, SignedPackage};

pub(super) fn bundled() -> Result<SignedPackage, SdkError> {
    let bytecode = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/include/card/library.qjb"));
    let descriptor = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/include/card/library.descriptor.json"
    ));
    let signature =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/include/card/library.sig"));
    let public = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/include/card/library.pub"));
    let policy_bytes =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/include/card/policy.json"));
    let signature: [u8; 64] =
        signature.as_slice().try_into().map_err(|_| invalid("card package signature"))?;
    let public: [u8; 32] = public.as_slice().try_into().map_err(|_| invalid("card package key"))?;
    let policy: AcceptancePolicy =
        serde_json::from_slice(policy_bytes).map_err(|_| invalid("card package policy"))?;
    SignedPackage::verify(bytecode, descriptor, &signature, &public, &policy).map_err(card_err)
}

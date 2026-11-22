// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independently configured centre identity; no reply can establish or replace this pin.
use crate::SdkError;
use ramflux_protocol::username_directory::{DirectoryCode as Code, NativeDirectoryPin};

/// # Errors
/// Refuses missing/partial pins, malformed HTTPS origins, weak keys and invalid generations.
pub fn configured_center() -> Result<NativeDirectoryPin, SdkError> {
    let required = |suffix| std::env::var(format!("RAMFLUX_USERNAME_CENTER_{suffix}"))
        .ok().filter(|value| !value.is_empty() && value.trim() == value)
        .ok_or(SdkError::UsernameDirectoryRefused(Code::DirectoryUnavailable));
    let generation = std::env::var("RAMFLUX_USERNAME_TRUST_GENERATION")
        .ok().and_then(|v| v.parse::<u64>().ok())
        .ok_or(SdkError::UsernameDirectoryRefused(Code::DirectoryUnavailable))?;
    let pin = NativeDirectoryPin { url: required("URL")?, id: required("ID")?, public_key: required("PUBLIC_KEY")?, generation };
    pin.validate().map_err(|_| Code::DirectoryUnavailable)?;
    let key = ramflux_crypto::verifying_key_from_base64url(&pin.public_key).map_err(|_| Code::SignatureInvalid)?;
    if key.is_weak() { return Err(Code::SignatureInvalid.into()); }
    Ok(pin)
}

/// Local presentation normalization only; remote decoders always require exact wire spelling.
/// # Errors
/// Refuses oversized input, multiple presentation prefixes and invalid/reserved shapes.
pub fn normalize_name(value: &str) -> Result<String, SdkError> {
    let value = value.trim();
    let value = value.strip_prefix('@').unwrap_or(value);
    ramflux_protocol::username_directory::normalize_username(value).map_err(|_| Code::InvalidUsername.into())
}

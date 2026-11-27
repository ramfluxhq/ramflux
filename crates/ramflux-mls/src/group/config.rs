// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group configuration, leaf capabilities and KeyPackage lifetime.

use openmls::prelude::{
    Capabilities, CredentialType, Extension, Extensions, GroupContext, Lifetime,
    MlsGroupCreateConfig, MlsGroupJoinConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    RequiredCapabilitiesExtension, SenderRatchetConfiguration,
};

use crate::credential::GroupKind;
use crate::{
    CREDENTIAL_TYPE_DEVICE, CREDENTIAL_TYPE_PSEUDONYM, KEY_PACKAGE_LIFETIME_SECS, MAX_PAST_EPOCHS,
    MLS_SUITE, MlsError, PADDING_SIZE,
};

/// Sender ratchet tolerance: five out-of-order messages, a forward distance of 1 000.
const RATCHET_OUT_OF_ORDER: u32 = 5;
const RATCHET_FORWARD_DISTANCE: u32 = 1_000;

/// Capabilities of every own leaf: suite 0x0001 only, both rf credential types. Basic is added
/// only under `itest-mls-debug` (interop), never in production.
#[must_use]
pub fn capabilities() -> Capabilities {
    let mut credentials = vec![
        CredentialType::Other(CREDENTIAL_TYPE_DEVICE),
        CredentialType::Other(CREDENTIAL_TYPE_PSEUDONYM),
    ];
    if cfg!(feature = "itest-mls-debug") {
        credentials.push(CredentialType::Basic);
    }
    Capabilities::builder().ciphersuites(vec![MLS_SUITE]).credentials(credentials).build()
}

/// `required_capabilities` of a group: exactly one rf credential type, the kind's.
#[must_use]
pub fn required_capabilities(kind: GroupKind) -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(&[], &[], &[CredentialType::Other(kind.credential_type())])
}

fn group_context_extensions(kind: GroupKind) -> Result<Extensions<GroupContext>, MlsError> {
    Extensions::single(Extension::RequiredCapabilities(required_capabilities(kind)))
        .map_err(MlsError::mls)
}

/// Lifetime of a KeyPackage and of a group creator's leaf: 30 days.
#[must_use]
pub fn key_package_lifetime() -> Lifetime {
    Lifetime::new(KEY_PACKAGE_LIFETIME_SECS)
}

/// Join configuration (also stored with every group): pure ciphertext, padding 32, three past
/// epochs, ratchet tree inside the Welcome.
#[must_use]
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(PADDING_SIZE)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            RATCHET_OUT_OF_ORDER,
            RATCHET_FORWARD_DISTANCE,
        ))
        .build()
}

/// Creation configuration of a group of `kind`.
///
/// # Errors
/// The extension list could not be built.
pub fn create_config(kind: GroupKind) -> Result<MlsGroupCreateConfig, MlsError> {
    Ok(MlsGroupCreateConfig::builder()
        .ciphersuite(MLS_SUITE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(PADDING_SIZE)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            RATCHET_OUT_OF_ORDER,
            RATCHET_FORWARD_DISTANCE,
        ))
        .lifetime(key_package_lifetime())
        .capabilities(capabilities())
        .with_group_context_extensions(group_context_extensions(kind)?)
        .build())
}

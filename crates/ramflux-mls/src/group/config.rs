// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group configuration, leaf capabilities and `KeyPackage` lifetime.

use openmls::prelude::{
    Capabilities, CredentialType, Extension, Extensions, GroupContext, Lifetime,
    MlsGroupCreateConfig, MlsGroupJoinConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    RequiredCapabilitiesExtension, SenderRatchetConfiguration,
};

use super::conversation::RfConversation;
use crate::credential::GroupKind;
use crate::{
    CREDENTIAL_TYPE_DEVICE, CREDENTIAL_TYPE_PSEUDONYM, KEY_PACKAGE_LIFETIME_SECS, MAX_PAST_EPOCHS,
    MLS_SUITE, MlsError, PADDING_SIZE,
};

/// Sender ratchet tolerance of a group: five out-of-order messages.
const RATCHET_OUT_OF_ORDER_GROUP: u32 = 5;
/// Sender ratchet tolerance of `dm` and `self`: every facade call seals one message per target
/// device, so a receiver skips the generations sealed for other targets (the leaf bound is 2 x 50
/// = 100 targets, plus headroom).
const RATCHET_OUT_OF_ORDER_DEVICE: u32 = 128;
const RATCHET_FORWARD_DISTANCE: u32 = 1_000;

fn ratchet(kind: GroupKind) -> SenderRatchetConfiguration {
    let tolerance = if kind.is_device_kind() {
        RATCHET_OUT_OF_ORDER_DEVICE
    } else {
        RATCHET_OUT_OF_ORDER_GROUP
    };
    SenderRatchetConfiguration::new(tolerance, RATCHET_FORWARD_DISTANCE)
}

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
    Capabilities::builder()
        .ciphersuites(vec![MLS_SUITE])
        .extensions(vec![RfConversation::extension_type()])
        .credentials(credentials)
        .build()
}

/// `required_capabilities` of a group: exactly one rf credential type, the kind's; `dm` and
/// `self` also require the `rf_conversation` extension type.
#[must_use]
pub fn required_capabilities(kind: GroupKind) -> RequiredCapabilitiesExtension {
    let extensions: &[openmls::prelude::ExtensionType] =
        if kind.is_device_kind() { &[RfConversation::extension_type()] } else { &[] };
    RequiredCapabilitiesExtension::new(
        extensions,
        &[],
        &[CredentialType::Other(kind.credential_type())],
    )
}

/// The group context extensions of a new group. A `dm` or `self` group carries its immutable
/// `rf_conversation` binding; a group carries none.
fn group_context_extensions(
    kind: GroupKind,
    binding: Option<&RfConversation>,
) -> Result<Extensions<GroupContext>, MlsError> {
    let required = Extension::RequiredCapabilities(required_capabilities(kind));
    match (kind.is_device_kind(), binding) {
        (true, Some(binding)) => {
            if binding.role.kind() != kind {
                return Err(MlsError::PolicyRejected(
                    "rf_conversation role does not match the group kind".to_owned(),
                ));
            }
            Extensions::from_vec(vec![required, binding.extension()?]).map_err(MlsError::mls)
        }
        (true, None) => Err(MlsError::PolicyRejected(
            "a dm or self group requires an rf_conversation binding".to_owned(),
        )),
        (false, None) => Extensions::single(required).map_err(MlsError::mls),
        (false, Some(_)) => {
            Err(MlsError::PolicyRejected("a group carries no rf_conversation binding".to_owned()))
        }
    }
}

/// Lifetime of a `KeyPackage` and of a group creator's leaf: 30 days.
#[must_use]
pub fn key_package_lifetime() -> Lifetime {
    Lifetime::new(KEY_PACKAGE_LIFETIME_SECS)
}

/// Join configuration (also stored with every group): pure ciphertext, padding 32, three past
/// epochs, ratchet tree inside the Welcome. The sender ratchet tolerance depends on the kind
/// (`dm`/`self` 128, group 5).
#[must_use]
pub fn join_config(kind: GroupKind) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(PADDING_SIZE)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(ratchet(kind))
        .build()
}

/// Creation configuration of a group of `kind`. `binding` is required for `dm` and `self` and
/// refused for a group.
///
/// # Errors
/// The extension list could not be built or the binding does not fit the kind.
pub fn create_config(
    kind: GroupKind,
    binding: Option<&RfConversation>,
) -> Result<MlsGroupCreateConfig, MlsError> {
    Ok(MlsGroupCreateConfig::builder()
        .ciphersuite(MLS_SUITE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(PADDING_SIZE)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(ratchet(kind))
        .lifetime(key_package_lifetime())
        .capabilities(capabilities())
        .with_group_context_extensions(group_context_extensions(kind, binding)?)
        .build())
}

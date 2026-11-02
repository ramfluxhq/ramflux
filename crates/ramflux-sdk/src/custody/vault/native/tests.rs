// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native caller error contracts, with failures injected before Security side effects.
use super::*;
use crate::custody::{NativePrimaryVault, PrimaryVault};
use std::cell::Cell;

thread_local! {
    pub(super) static FORCED_STATUS: Cell<Option<i32>> = const { Cell::new(None) };
    pub(super) static COPY_REQUEST: Cell<Option<(bool, bool)>> = const { Cell::new(None) };
    pub(super) static INSERT_PRESENCE: Cell<Option<bool>> = const { Cell::new(None) };
    pub(super) static BACKEND: Cell<Option<Backend>> = const { Cell::new(None) };
}

struct Failure;
impl Failure {
    fn install() -> Self {
        // errSecInteractionNotAllowed: models a locked or headless Keychain.
        FORCED_STATUS.set(Some(-25308));
        COPY_REQUEST.set(None);
        INSERT_PRESENCE.set(None);
        Self
    }
}
impl Drop for Failure {
    fn drop(&mut self) {
        FORCED_STATUS.set(None);
        COPY_REQUEST.set(None);
        INSERT_PRESENCE.set(None);
        BACKEND.set(None);
    }
}

#[test]
fn native_creation_and_recovery_store_failures_keep_custody_vault_unavailable() {
    let _failure = Failure::install();
    let key = ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&Zeroizing::new([1; 32]));
    assert!(matches!(NativePrimaryVault.preflight(), Err(SdkError::CustodyVaultUnavailable)));
    for reference in ["creation-primary", "recovered-primary"] {
        assert!(matches!(
            NativePrimaryVault.store_new(reference, &key),
            Err(SdkError::CustodyVaultUnavailable)
        ));
    }
    // Exercise the insert's own status mapping, independently of the existence check.
    assert!(matches!(
        KeychainItems::PROTECTED.insert("primary", &[1; 32], false),
        Err(SdkError::CustodyVaultUnavailable)
    ));
}

#[test]
fn native_card_and_consent_load_failures_keep_custody_vault_unavailable() {
    let _failure = Failure::install();
    for reference in ["contact-card-primary", "contact-consent-primary"] {
        assert!(matches!(
            NativePrimaryVault.load_primary(reference),
            Err(SdkError::CustodyVaultUnavailable)
        ));
    }
}

#[test]
fn native_session_branch_failures_keep_custody_vault_unavailable() {
    let _failure = Failure::install();
    let device = ramflux_protocol::custody::DeviceRef {
        account_anchor: ramflux_protocol::encode_base64url([1; 32]),
        device_id: "device".into(),
        device_epoch: 1,
    };
    assert!(matches!(
        NativePrimaryVault.load_branch("branch", "human", &device),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert!(matches!(
        NativePrimaryVault.store_branch("branch", &Zeroizing::new([1; 64])),
        Err(SdkError::CustodyVaultUnavailable)
    ));
}

#[test]
fn native_creation_and_recovery_cleanup_failures_keep_custody_vault_unavailable() {
    let _failure = Failure::install();
    for reference in ["incomplete-creation", "retired-recovery"] {
        assert!(matches!(
            NativePrimaryVault.delete(reference),
            Err(SdkError::CustodyVaultUnavailable)
        ));
    }
}

#[test]
fn native_migration_boundary_alone_maps_provider_failure_to_presence_refusal() {
    let _failure = Failure::install();
    assert!(matches!(
        NativePrimaryVault.home_authorization_preflight(),
        Err(SdkError::HomeMigrationRefused(
            ramflux_protocol::home_migration::Refusal::CustodyUserPresenceUnavailable
        ))
    ));
    assert!(matches!(
        super::super::presence::approved_primary(&KeychainItems::PROTECTED, "primary", "key"),
        Err(SdkError::HomeMigrationRefused(
            ramflux_protocol::home_migration::Refusal::CustodyUserPresenceUnavailable
        ))
    ));
}

#[test]
fn native_provisioning_secret_failures_keep_generic_errors_without_requesting_presence() {
    let _failure = Failure::install();
    BACKEND.set(Some(Backend::DataProtection));
    assert!(matches!(
        NativePrimaryVault
            .store_provisioning_secret("pending-native-participant", b"fixture-secret"),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert_eq!(INSERT_PRESENCE.get(), Some(false));
    assert!(matches!(
        NativePrimaryVault.load_provisioning_secret("pending-native-participant"),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert_eq!(COPY_REQUEST.get(), Some((true, false)));
}

#[test]
fn native_provisioning_secret_duplicate_and_missing_entries_keep_generic_errors() {
    let _failure = Failure::install();
    BACKEND.set(Some(Backend::DataProtection));
    FORCED_STATUS.set(Some(security_framework_sys::base::errSecDuplicateItem));
    assert!(matches!(
        NativePrimaryVault
            .store_provisioning_secret("pending-native-participant", b"fixture-secret"),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    FORCED_STATUS.set(Some(errSecItemNotFound));
    assert!(matches!(
        NativePrimaryVault.load_provisioning_secret("pending-native-participant"),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert_eq!(COPY_REQUEST.get(), Some((true, false)));
}

#[test]
fn native_missing_primary_returns_custody_vault_unavailable_without_ui() -> Result<(), SdkError> {
    let mut random = [0; 32];
    getrandom::fill(&mut random).map_err(|_| SdkError::CustodyVaultUnavailable)?;
    let reference = format!("missing-primary-test-{}", ramflux_protocol::encode_base64url(random));
    assert!(matches!(
        NativePrimaryVault.load_primary(&reference),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    Ok(())
}

#[test]
fn native_backend_falls_back_only_on_missing_entitlement() {
    let probed = Cell::new(false);
    let login = || {
        probed.set(true);
        0
    };
    assert!(matches!(select(0, login), Ok(Backend::DataProtection)));
    assert!(!probed.get(), "login keychain probed for an entitled process");
    assert!(matches!(select(MISSING_ENTITLEMENT, || 0), Ok(Backend::LoginKeychain)));
    // A locked or headless login keychain fails closed; there is no file fallback.
    assert!(matches!(
        select(MISSING_ENTITLEMENT, || -25308),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert!(matches!(select(-25308, || 0), Err(SdkError::CustodyVaultUnavailable)));
}

#[test]
fn native_preflight_writes_a_probe_so_a_missing_entitlement_is_not_masked() {
    let _failure = Failure::install();
    // Lookups report "not found" without the entitlement; only the insert probe exposes it.
    FORCED_STATUS.set(Some(MISSING_ENTITLEMENT));
    assert!(matches!(NativePrimaryVault.preflight(), Err(SdkError::CustodyVaultUnavailable)));
    assert_eq!(INSERT_PRESENCE.get(), None, "probe must not use the presence insert path");
    assert_eq!(NativePrimaryVault.vault_class(), crate::custody::VAULT_CLASS_PROTECTED);
}

#[test]
fn native_login_keychain_class_refuses_presence_items_and_migration() {
    let _failure = Failure::install();
    BACKEND.set(Some(Backend::LoginKeychain));
    assert_eq!(NativePrimaryVault.vault_class(), crate::custody::VAULT_CLASS_LOGIN_KEYCHAIN);
    assert!(matches!(
        KeychainItems::LOGIN.insert("presence:v1:primary", &[1; 32], true),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert!(matches!(
        NativePrimaryVault.home_authorization_preflight(),
        Err(SdkError::HomeMigrationRefused(
            ramflux_protocol::home_migration::Refusal::CustodyUserPresenceUnavailable
        ))
    ));
}

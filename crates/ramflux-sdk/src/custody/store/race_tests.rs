// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Late legacy completion must survive every custody reservation/publication checkpoint.
use super::race_hooks::{Stage, install};
use super::*;
use crate::{
    RamfluxClient,
    custody::tests::{Root, TestVault, input, words},
};
use ramflux_storage::{
    AccountDb, AccountDbKey, FileVaultSecretSource, VaultSecretSource, WrappedAccountDbKey,
    wrap_with_vault_secret,
};
use std::{cell::RefCell, rc::Rc};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Clone)]
struct Snapshot {
    row: ramflux_storage::LocalAccountRecord,
    wrapped: WrappedAccountDbKey,
    manifest: Vec<u8>,
}

fn finish_prechecked_legacy_create(
    root: &Path,
    id: &str,
) -> std::result::Result<Snapshot, SdkError> {
    // Model a legacy SDK writer already past its bus prechecks. The public legacy SDK API
    // remains replace-capable for compatibility; new bus creation now uses reserve_account.
    let mut client = RamfluxClient::new();
    client.open_account_index(root)?;
    let identity = client.create_identity_root("legacy-principal", [0x81; 32]);
    let commitment = crate::identity_root_public_key_commitment(
        &ramflux_protocol::encode_base64url(identity.signing_key.verifying_key().to_bytes()),
    )?;
    let row = client.create_account(id, &commitment)?;
    let index = client.account_index()?;
    let vault_secret = FileVaultSecretSource::new(root).vault_secret(id)?;
    let kek =
        crate::client::account::account_db_key_encryption_key(&vault_secret, b"legacy-secret");
    let key = AccountDbKey::generate()?;
    let (nonce, wrapped_key) = wrap_with_vault_secret(&kek, key.bytes())?;
    let wrapped = WrappedAccountDbKey {
        key_wrapping_provider: "platform-local-vault".into(),
        key_wrapping_ref: format!("platform-local-vault:{id}"),
        nonce,
        wrapped_key,
    };
    index.store_wrapped_db_key(id, &wrapped)?;
    // This is the completion of the prechecked legacy write, not a fresh unlock through
    // the custody marker. The ordinary unlock is checked after custody removes its marker.
    let db = AccountDb::open(index, id, &key)?;
    drop(db);
    let request = crate::LocalBusAccountCreateRequest {
        label: None,
        kind: None,
        node_id: None,
        local_account_id: id.into(),
        principal_id: "legacy-principal".into(),
        principal_commitment: commitment,
        device_id: "legacy-device".into(),
        target_delivery_id: "legacy-delivery".into(),
        account_secret: "legacy-secret".into(),
        root_seed: [0x81; 32],
        device_seed: [0x82; 32],
        client_mode: crate::LocalBusClientMode::AttendedCli,
        gateway: crate::gateway::GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().map_err(|_| invalid())?,
            gateway_addr: "127.0.0.1:1".parse().map_err(|_| invalid())?,
            server_name: "absent".into(),
            ca_cert: root.join("missing.pem"),
            principal_id: String::new(),
            device_id: String::new(),
            target_delivery_id: String::new(),
            prekey_http_url: None,
        },
    };
    let manifest = crate::bus::protocol::LocalBusPersistedAccount::from_create_request(&request);
    crate::bus::daemon::write_local_bus_account_manifest(root, &manifest)?;
    let path = crate::bus::daemon::local_bus_account_manifest_path(root, id);
    Ok(Snapshot { row, wrapped, manifest: fs::read(path)? })
}
fn legacy_wins_at(stage: Stage) -> Result {
    let root = Root::new()?;
    let id = "raced-account";
    let capability = crate::bus::custody_setup::test_creation_capability();
    let mut ceremony = super::super::CreationCeremony::begin(&capability, &root.0, input(id), 100)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    let snapshot = Rc::new(RefCell::new(None));
    let captured = Rc::clone(&snapshot);
    let _hook = install(move |at, root, id| {
        if at == stage {
            *captured.borrow_mut() = Some(finish_prechecked_legacy_create(root, id)?);
        }
        Ok(())
    });
    assert!(matches!(
        ceremony.confirm(&words(&phrase, positions)?, &TestVault::default(), 100),
        Err(SdkError::CustodyAccountConflict)
    ));
    assert!(!root.0.join("custody_accounts").join(id).exists());
    let before = snapshot.borrow().clone().ok_or("checkpoint did not run")?;
    let index = ramflux_storage::AccountIndex::open(&root.0)?;
    assert_eq!(index.account(id)?, before.row);
    assert_eq!(index.load_wrapped_db_key(id)?, Some(before.wrapped));
    assert_eq!(index.known_account_ids()?, vec![id.to_owned()]);
    assert_eq!(
        fs::read(crate::bus::daemon::local_bus_account_manifest_path(&root.0, id))?,
        before.manifest
    );
    let mut client = RamfluxClient::new();
    client.open_account_index(&root.0)?;
    client.unlock_account(id, b"legacy-secret")?;
    client.verify_active_account_secret(id, b"legacy-secret")?;
    Ok(())
}
#[test]
fn custody_legacy_create_after_reservation_preserves_wrapped_key_and_unlock() -> Result {
    legacy_wins_at(Stage::AfterReservation)
}
#[test]
fn custody_legacy_create_after_manifest_check_preserves_wrapped_key_and_unlock() -> Result {
    legacy_wins_at(Stage::AfterManifestCheck)
}
#[test]
fn custody_legacy_create_before_authority_publication_preserves_wrapped_key_and_unlock() -> Result {
    legacy_wins_at(Stage::BeforeAuthorityPublish)
}

#[test]
fn custody_reservation_cannot_replace_a_legacy_wrapped_key_before_manifest_publication() -> Result {
    let root = Root::new()?;
    let id = "legacy-awaiting-manifest";
    let capability = crate::bus::custody_setup::test_creation_capability();
    let mut ceremony = super::super::CreationCeremony::begin(&capability, &root.0, input(id), 100)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    let before = finish_prechecked_legacy_create(&root.0, id)?;
    let path = crate::bus::daemon::local_bus_account_manifest_path(&root.0, id);
    let manifest = crate::bus::daemon::read_local_bus_account_manifest(&path)?;
    // Pause legacy completion after its index/database writes but before manifest publication.
    // Custody must reach reserve_account; the earlier manifest check cannot hide replacement.
    fs::remove_file(&path)?;
    assert!(matches!(
        ceremony.confirm(&words(&phrase, positions)?, &TestVault::default(), 100),
        Err(SdkError::CustodyAccountConflict)
    ));
    assert!(!root.0.join("custody_accounts").join(id).exists());
    let index = ramflux_storage::AccountIndex::open(&root.0)?;
    assert_eq!(index.account(id)?, before.row);
    assert_eq!(index.load_wrapped_db_key(id)?, Some(before.wrapped));
    assert_eq!(index.known_account_ids()?, vec![id.to_owned()]);
    crate::bus::daemon::write_local_bus_account_manifest(&root.0, &manifest)?;
    assert_eq!(fs::read(&path)?, before.manifest);
    let mut client = RamfluxClient::new();
    client.open_account_index(&root.0)?;
    client.unlock_account(id, b"legacy-secret")?;
    client.verify_active_account_secret(id, b"legacy-secret")?;
    Ok(())
}

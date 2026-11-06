// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{tests::TestResult, *};
use crate::custody::tests::{Root, TestVault, create};

#[test]
pub(super) fn generated_task_native_custody_manifest_round_trips_without_installing_keys()
-> TestResult {
    let root = Root::new()?;
    let vault = TestVault::default();
    let now = crate::custody::network_now()?;
    let account = create(&root.0, "peer", &vault, now)?;
    let (reference, credentials) = account.credentials(&vault, "primary", now)?;
    let signed = ramflux_crypto::X25519KeyPair::random()?;
    let bundle = ramflux_crypto::create_prekey_bundle(
        &credentials.signing,
        &credentials.agreement,
        "native-signed",
        &signed,
        None,
        None,
    )?;
    let identity =
        ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(account.verified(), "primary")?;
    let manifest = crate::prekey::SdkDeviceManifestResponse::from_native(
        ramflux_protocol::custody::CustodyManifest {
            publication: ramflux_protocol::custody::Publication {
                record: account.record().clone(),
                compacted_ids: None,
            },
            custodian_publication: None,
            devices: vec![ramflux_protocol::custody::CustodyManifestDevice {
                device_ref: reference,
                target_delivery_id: identity.storage_key().into(),
                prekey_bundle: serde_json::to_value(bundle)?,
            }],
        },
    )?;
    let directory = tempfile::tempdir()?;
    let mut client = RamfluxClient::new();
    client.create_identity_root("human", [22; 32]);
    client.create_device_branch("human", "device", 1, [23; 32]);
    client.open_account_index(directory.path())?;
    client.create_account("human", "human")?;
    client.unlock_account("human", b"generated-manifest-test")?;
    // The candidate decoder requires an already pinned root; fixture setup owns
    // this authenticated directory admission before the read-only adapter runs.
    client.persist_fetched_identity_directory(&manifest)?;
    let before = client.account_db()?.client_record("identity", &manifest.principal_id)?;
    let bytes = client.encode_generated_task_manifest(&manifest)?;
    assert_eq!(client.decode_generated_task_manifest(&bytes, &manifest.principal_id)?, manifest);
    let generated = g::NativeDeviceManifest::decode(bytes.as_slice())?;
    assert!(generated.custody.is_some());
    assert!(generated.signed_device_set.is_none());
    assert!(generated.devices.iter().all(|device| device.branch_proof.is_none()));
    let mut history = super::history_tests::fixture(&client)?;
    history.packets[0].manifests = vec![generated.clone()];
    assert_eq!(
        client.decode_generated_task_history_export(
            &client.encode_generated_task_history_export(&history)?
        )?,
        history
    );
    assert_eq!(client.account_db()?.client_record("identity", &manifest.principal_id)?, before);
    let mut changed = generated;
    changed.custody.as_mut().ok_or("custody")?.canonical.push(b' ');
    assert!(
        matches!(client.decode_generated_task_manifest(&changed.encode_to_vec(), &manifest.principal_id),
        Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, message }) if message == "noncanonical native task manifest document")
    );
    Ok(())
}

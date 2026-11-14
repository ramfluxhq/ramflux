// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local exporter/importer proof after actual enrollment. Wire upload/fetch is separate.
use super::TestResult;
use crate::{RamfluxClient, custody::PrimaryVault, prekey::SdkDeviceManifestResponse};
use ramflux_protocol::custody::{CustodyManifest, CustodyManifestDevice};
const DM: &str = "existing-dm-before-pairing";
const GROUP: &str = "existing-group-before-pairing";
const GROUP_MESSAGE: &str = "existing-group-message-before-pairing";
const BODY: &[u8] = b"history authored before recipient enrollment";

pub(crate) fn seed(source: &RamfluxClient, vault: &dyn PrimaryVault) -> TestResult {
    let identity = source.owned_device_identity()?;
    let mut session = source.init_dm_initiator_session(
        ramflux_crypto::random_32()?,
        ramflux_crypto::random_32()?,
        ramflux_crypto::random_32()?,
        ramflux_crypto::random_32()?,
    )?;
    let encrypted = session.encrypt(BODY, b"existing-dm-thread")?;
    source.persist_dm_session("existing-dm-thread", DM, "send", &session)?;
    source.send_direct_message(
        "existing-dm-thread",
        DM,
        identity.device_id(),
        &ramflux_protocol::canonical_json_bytes(&encrypted)?,
    )?;
    source.account_db()?.store_message_content("existing-dm-thread", DM, BODY)?;
    let account = source.born_v3_account.as_ref().ok_or("test: source native account")?;
    let primary = account.group_primary(vault)?;
    source.shared_group_create_with_primary(
        GROUP,
        "existing-group-thread",
        None,
        identity.storage_key(),
        Some(&primary),
    )?;
    let ciphertext = source.encrypt_group_message(GROUP, identity.device_id(), BODY)?;
    source.send_direct_message(GROUP, GROUP_MESSAGE, identity.device_id(), &ciphertext)?;
    Ok(())
}

pub(crate) fn verify(source: &RamfluxClient, target: &RamfluxClient) -> TestResult {
    let source_id = source.owned_device_identity()?;
    let target_id = target.owned_device_identity()?;
    assert_ne!(source_id, target_id, "test: paired history shares a device identity");
    assert!(
        target.account_db()?.message_content(DM)?.is_none(),
        "test: target already had source history"
    );
    let manifest = manifest(source, target)?;
    source.persist_fetched_identity_directory(&manifest)?;
    target.persist_fetched_identity_directory(&manifest)?;
    let bundle = source.own_device_history_bundle(
        source_id.root_commitment(),
        source_id.device_id(),
        target_id.device_id(),
        "snapshot_sync",
    )?;
    assert!(
        source.load_dm_session("existing-dm-thread", "send").is_ok(),
        "test: source outbound-ratchet exclusion oracle was vacuous"
    );
    assert!(bundle.dm_sessions.is_empty(), "test: history exported outbound DM ratchets");
    assert!(!bundle.groups.is_empty(), "test: group snapshot coverage was vacuous");
    let before = zeroize::Zeroizing::new(target.load_x3dh_private_state(&target_id)?.identity_seed);
    let mut envelope = crate::client::own_device_sync::tests::envelope(
        source_id.device_id(),
        target_id.device_id(),
    );
    envelope.principal_commitment = source_id.root_commitment().into();
    envelope.created_at = crate::time::now_unix_timestamp();
    envelope.expires_at = envelope.created_at + 3600;
    envelope.history_ref.key_slot.conversation_id =
        crate::own_device_sync::own_device_sync_slot_conversation_id(
            &envelope.snapshot_id,
            &envelope.history_ref.object_id,
            target_id.device_id(),
        );
    let branch = source.device_branch.as_ref().ok_or("test: original source signer")?;
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        branch,
        &crate::own_device_sync::own_device_sync_signing_body(&envelope),
    )?;
    target.validate_own_sync_header(target_id.root_commitment(), &envelope)?;
    target.verify_own_sync_devices(&envelope, &manifest)?;
    let plaintext = zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(&bundle)?);
    let (imported, next) = target.apply_own_history_plaintext(&envelope, &plaintext)?;
    assert!(next.is_none(), "test: bounded history fixture unexpectedly paged");
    assert!(
        imported.imported_messages >= 2,
        "test: paired target did not import both history kinds"
    );
    assert_eq!(
        target.account_db()?.message_content(DM)?.as_deref(),
        Some(BODY),
        "test: paired device lost existing DM plaintext"
    );
    assert_eq!(
        target.decrypt_group_message(GROUP, GROUP_MESSAGE)?,
        BODY,
        "test: imported receive-only group material cannot read existing history"
    );
    assert_eq!(
        target.load_x3dh_private_state(&target_id)?.identity_seed,
        *before,
        "test: history import replaced B's own private prekey identity"
    );
    assert!(
        target.load_dm_session("existing-dm-thread", "send").is_err(),
        "test: importing history copied A's outbound DM ratchet"
    );
    fresh_sender(source, target, &source_id, &target_id)?;
    Ok(())
}

fn manifest(
    source: &RamfluxClient,
    target: &RamfluxClient,
) -> TestResult<SdkDeviceManifestResponse> {
    let account = source.born_v3_account.as_ref().ok_or("test: installed native source")?;
    let mut devices = Vec::new();
    for client in [source, target] {
        let identity = client.owned_device_identity()?;
        let bundle = client.load_x3dh_private_state(&identity)?.bundle;
        let native = client.born_v3_account.as_ref().ok_or("test: installed native participant")?;
        let local = native.local_device_id()?;
        let device = native
            .record()
            .body
            .devices
            .iter()
            .find(|device| device.device_id == local)
            .ok_or("test: own branch in installed roster")?;
        devices.push(CustodyManifestDevice {
            device_ref: ramflux_protocol::custody::DeviceRef {
                account_anchor: identity.root_commitment().into(),
                device_id: local.into(),
                device_epoch: device.device_epoch,
            },
            target_delivery_id: identity.storage_key().into(),
            prekey_bundle: serde_json::to_value(bundle)?,
            message_layer: None,
        });
    }
    Ok(SdkDeviceManifestResponse::from_native(CustodyManifest {
        publication: account.publication(),
        custodian_publication: None,
        devices,
    })?)
}

fn fresh_sender(
    source: &RamfluxClient,
    target: &RamfluxClient,
    a: &ramflux_crypto::RootQualifiedDeviceRef,
    b: &ramflux_crypto::RootQualifiedDeviceRef,
) -> TestResult {
    let first = target.encrypt_group_message(
        GROUP,
        b.device_id(),
        b"first message from the newly paired branch",
    )?;
    let own: crate::group::SdkGroupEncryptedEnvelope = serde_json::from_slice(&first)?;
    let old = source
        .account_db()?
        .all_direct_messages()?
        .into_iter()
        .find(|message| message.message_id == GROUP_MESSAGE)
        .ok_or("test: original group ciphertext")?;
    let old: crate::group::SdkGroupEncryptedEnvelope = serde_json::from_slice(&old.encrypted_body)?;
    assert_eq!(old.sender_id, a.device_id(), "test: source history changed sender");
    assert_eq!(own.sender_id, b.device_id(), "test: new device sent under A's group identity");
    assert_ne!(
        own.ciphertext.session_id, old.ciphertext.session_id,
        "test: new device cloned A's sender chain"
    );
    assert_eq!(
        own.ciphertext.counter, 0,
        "test: first B group message continued an imported sender counter"
    );
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed native history, private keyed projection and the ordinary SDK read model.
use super::*;
use ramflux_storage::{FileVaultSecretSource, VaultSecretSource as _};
use std::sync::{Arc, atomic::AtomicBool};

#[test]
fn direct_private_install_preserves_signed_edit_original_order_and_product_revision() -> TestResult
{
    let source_root = Root::new()?;
    let (source, item) = super::source::installed_edit(&source_root)?;
    let original = g::original_header::decode_identity(&item.exact_original_identity)?;
    let id = ramflux_protocol::encode_base64url(&original.id);
    let source_db = source.account_db()?;
    let history = source_db.read_full_direct_history(&id)?.ok_or("source native record")?;
    let projection = source_db.direct_message_by_id(&id)?.ok_or("source projection")?;
    let target_root = Root::new()?;
    let target = empty_import_receiver(&target_root)?;
    let target_db = target.account_db()?;
    let context = source_db
        .client_record("conversation", &original.conversation_id)?
        .ok_or("source native context")?;
    // Seed the admitted context using the existing fixture. Its portable owner and
    // current contact authorization remain distinct from this content projection.
    target_db.persist_client_record("conversation", &original.conversation_id, &context)?;
    let path = target_root.0.join("private-native.db");
    let snapshot = target_db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    let source_device = source.owned_device_identity()?;
    let contributor = ramflux_protocol::custody::DeviceRef {
        account_anchor: source.own_account_anchor()?,
        device_id: source_device.device_id().to_owned(),
        device_epoch: source.device_branch.as_ref().ok_or("source branch")?.device_epoch,
    };

    // Expose this private file to an authorized local reader fixture, without
    // claiming generation fencing, native publication or full-transfer acceptance.
    let reader_root = Root::new()?;
    let mut reader = RamfluxClient::new();
    reader.create_identity_root("receiver", [53; 32]);
    reader.create_device_branch("receiver", "reader", 1, [55; 32]);
    let local_root = reader_root.0.join("reader");
    reader.open_account_index(&local_root)?;
    reader.create_account("receiver", &reader.own_account_anchor()?)?;
    let destination =
        local_root.join(reader.account_index()?.account("receiver")?.db_relative_path);
    assert!(!destination.try_exists()?, "reader fixture must not overwrite an existing generation");
    std::fs::copy(&path, &destination)?;
    let vault =
        zeroize::Zeroizing::new(FileVaultSecretSource::new(&local_root).vault_secret("receiver")?);
    let wrapping = zeroize::Zeroizing::new(crate::client::account::account_db_key_encryption_key(
        &vault,
        b"history-import-test",
    ));
    let (nonce, wrapped_key) =
        ramflux_storage::wrap_with_vault_secret(&wrapping, snapshot.key.bytes())?;
    reader.account_index()?.store_wrapped_db_key(
        "receiver",
        &ramflux_storage::WrappedAccountDbKey {
            key_wrapping_provider: "platform-local-vault".into(),
            key_wrapping_ref: FileVaultSecretSource::owner_ref("receiver"),
            nonce,
            wrapped_key,
        },
    )?;
    reader.unlock_account("receiver", b"history-import-test")?;
    assert!(
        reader.account_db()?.project_full_direct_history_for_test(
            contributor,
            history,
            projection,
            None,
        )?,
        "verified signed Edit did not enter the private-file managed projection"
    );
    super::source::assert_product_body(&reader, &original)?;
    let page = reader.generated_message_view_page(&original.conversation_id, None, 10)?;
    let [view] = page.messages.as_slice() else {
        return Err("native view must contain one imported row".into());
    };
    assert!(view.edited, "product view lost the applied native revision");
    assert_eq!(view.revision, 7, "product view adopted a local cursor as native revision");
    assert_eq!(
        view.text.as_deref(),
        Some("current source body"),
        "product view exposed retired content instead of the winning Edit"
    );
    Ok(())
}

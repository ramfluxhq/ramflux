// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independently signed equivalent headers and genuine immutable-header disagreements.
use super::*;
use ramflux_storage::{BackupDatabase, FileVaultSecretSource, VaultSecretSource};

fn merge_into(
    local: &RamfluxClient,
    root: &Root,
    incoming: &RamfluxClient,
) -> TestResult<ramflux_storage::BackupMergeReport> {
    let archive = root.0.join("incoming.db");
    let snapshot = incoming.account_db()?.write_backup_snapshot(&archive)?;
    let vault = FileVaultSecretSource::new(root.0.join("receiver")).vault_secret("receiver")?;
    let kek = crate::client::account::account_db_key_encryption_key(&vault, b"history-import-test");
    let wrapped = local.account_index()?.load_wrapped_db_key("receiver")?.ok_or("wrapped key")?;
    let key = ramflux_storage::unwrap_with_vault_secret(&kek, &wrapped)?;
    Ok(BackupDatabase::open(&local.account_db()?.path, &key)?.merge_backup(
        &archive,
        &snapshot.key,
        || Ok(()),
    )?)
}

fn reopen(root: &Root) -> TestResult<RamfluxClient> {
    let mut client = RamfluxClient::new();
    client.create_identity_root("receiver", [53; 32]);
    client.create_device_branch("receiver", "receiver", 1, [54; 32]);
    client.open_account_index(root.0.join("receiver"))?;
    client.unlock_account("receiver", b"history-import-test")?;
    Ok(client)
}

#[test]
fn restore_header_agreement_verifies_origins_and_fences_conflicting_dependents() -> TestResult {
    let origin_root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&origin_root, "restore-header-origin", now)?;
    for conflict in [false, true] {
        for reverse in [false, true] {
            let first = item(&author, &author, now)?;
            let second = item(&author, &author, now + u64::from(conflict))?;
            let original = g::original_header::decode_identity(&first.exact_original_identity)?;
            let target = ramflux_protocol::encode_base64url(&original.id);
            let local_root = Root::new()?;
            let incoming_root = Root::new()?;
            let local = import_receiver(&local_root, &original)?;
            let incoming = import_receiver(&incoming_root, &original)?;
            let (ours, theirs) = if reverse { (&second, &first) } else { (&first, &second) };
            assert!(apply_claim(&local, ours)?);
            let incoming_revision = revise(&author, theirs, 9, now + 2)?;
            assert!(apply_claim(&incoming, &incoming_revision)?);
            incoming.account_db()?.persist_client_record(
                "test",
                "unrelated",
                &json!({"survives":true}),
            )?;
            let header_key = format!("routed/original-header/{target}");
            let before: Value =
                local.account_db()?.load_actor_state(&header_key)?.ok_or("local header")?;
            let register_key = format!("routed/edit-revision/{target}");
            let before_revision: Value =
                local.account_db()?.load_actor_state(&register_key)?.ok_or("local register")?;
            let report = merge_into(&local, &local_root, &incoming)?;
            assert_eq!(report.refused_items.len(), usize::from(conflict));
            if conflict {
                assert_eq!(report.refused_items[0].code, EvidenceError::OriginCommitmentMismatch);
                assert_eq!(
                    local.account_db()?.load_actor_state::<Value>(&register_key)?,
                    Some(before_revision)
                );
            } else {
                assert_eq!(
                    local.account_db()?.message_content(&target)?,
                    Some(incoming_revision.exact_inner)
                );
                assert_eq!(
                    local
                        .account_db()?
                        .actor_state_keys(&format!("routed/original-header-copy/{target}/"))?
                        .len(),
                    1
                );
            }
            drop(local);
            let reopened = reopen(&local_root)?;
            assert_eq!(
                reopened.account_db()?.load_actor_state::<Value>(&header_key)?,
                Some(before)
            );
            assert_eq!(
                reopened.account_db()?.client_record("test", "unrelated")?,
                Some(json!({"survives":true}))
            );
        }
    }
    Ok(())
}

#[test]
fn restore_header_invalid_local_evidence_is_an_integrity_failure() -> TestResult {
    let root = Root::new()?;
    let author_root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&author_root, "restore-invalid-local", now)?;
    let claim = item(&author, &author, now)?;
    let original = g::original_header::decode_identity(&claim.exact_original_identity)?;
    let local = import_receiver(&root, &original)?;
    assert!(apply_claim(&local, &claim)?);
    let target = ramflux_protocol::encode_base64url(&original.id);
    let header_key = format!("routed/original-header/{target}");
    let mut header: Value = local.account_db()?.load_actor_state(&header_key)?.ok_or("header")?;
    header["evidence"]["canonical_sender_envelope"] = json!([1, 2, 3]);
    local.account_db()?.persist_message_actor_state(&target, &header_key, &header)?;
    let incoming_root = Root::new()?;
    let incoming = import_receiver(&incoming_root, &original)?;
    assert!(apply_claim(&incoming, &claim)?);
    let error =
        merge_into(&local, &root, &incoming).err().ok_or("invalid local evidence accepted")?;
    assert!(error.to_string().contains("invalid local original-header evidence"));
    Ok(())
}

#[test]
fn restore_header_missing_incoming_original_refuses_edit_and_owned_cache() -> TestResult {
    let origin_root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&origin_root, "restore-missing-header", now)?;
    let claim = item(&author, &author, now)?;
    let original = g::original_header::decode_identity(&claim.exact_original_identity)?;
    let target = ramflux_protocol::encode_base64url(&original.id);
    let local_root = Root::new()?;
    let incoming_root = Root::new()?;
    let local = import_receiver(&local_root, &original)?;
    let incoming = import_receiver(&incoming_root, &original)?;
    assert!(apply_claim(&local, &claim)?);
    assert!(apply_claim(&incoming, &revise(&author, &claim, 9, now + 1)?)?);
    let before = local.account_db()?.message_content(&target)?;
    let db = incoming.account_db()?;
    db.remove_actor_state(&format!("routed/original-header/{target}"))?;
    let cache = format!("own-copy/prepared/{target}/conflicting-dependent");
    db.persist_message_actor_state(&target, &cache, &json!({"private":"incoming cache"}))?;
    let report = merge_into(&local, &local_root, &incoming)?;
    assert_eq!(report.refused_items.len(), 1);
    assert_eq!(report.refused_items[0].code, EvidenceError::OriginCommitmentMismatch);
    assert_eq!(local.account_db()?.message_content(&target)?, before);
    assert!(!local.account_db()?.actor_state_exists(&cache)?);
    Ok(())
}

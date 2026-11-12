// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable post-commit reclamation of exactly the replaced account generation.
use crate::SdkError;
use ramflux_storage::{AccountIndex, LocalAccountRecord};
use std::{io::Write, path::Path};
const MARKER: &str = ".backup-replaced.json";
pub(super) fn remember(
    generation: &Path,
    previous: Option<&LocalAccountRecord>,
) -> Result<(), SdkError> {
    let Some(previous) = previous else { return Ok(()) };
    let mut file = crate::platform::fs::create_new_owner_only(&generation.join(MARKER))?;
    file.write_all(&serde_json::to_vec(&previous.db_relative_path)?)?;
    file.sync_all()?;
    std::fs::File::open(generation)?.sync_all()?;
    Ok(())
}
pub(super) fn complete(
    generation: &Path,
    root: &Path,
    index: &AccountIndex,
    id: &str,
) -> Result<bool, SdkError> {
    let mut selection = index.account_generation_selection(id)?;
    // A legacy index manifest contains private recovery material. Keep its bytes
    // erasing and classify its origin without materializing unknown fields in Value.
    let metadata = selection.manifest_json.take().map(zeroize::Zeroizing::new);
    let selected = root.join(&selection.account.db_relative_path);
    let ready =
        full_install_ready(root, id, &selection.account, metadata.as_deref().map(Vec::as_slice));
    if selected.parent() != Some(generation) || !ready? {
        return Ok(false);
    }

    let marker = generation.join(MARKER);
    let meta = match std::fs::symlink_metadata(&marker) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() || meta.len() > 4096 {
        return Err(super::service::refused("unreadable"));
    }
    let relative: String = serde_json::from_slice(&std::fs::read(&marker)?)?;
    let account = root.join("accounts").join(id);
    let old = root.join(&relative);
    if Path::new(&relative).components().any(|c| !matches!(c, std::path::Component::Normal(_)))
        || !old.starts_with(&account)
        || old == selected
    {
        return Err(super::service::refused("root_conflict"));
    }
    let parent = old.parent().ok_or_else(|| super::service::refused("unreadable"))?;
    // Never follow a directory symlink, even under the same-user local-bus trust model.
    if parent != account
        && (parent.parent() != Some(account.as_path())
            || !parent.file_name().is_some_and(|n| n.to_string_lossy().starts_with("generation_")))
    {
        return Err(super::service::refused("root_conflict"));
    }
    if std::fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(super::service::refused("root_conflict"));
    }
    let _readers = match std::fs::symlink_metadata(parent) {
        Ok(_) => {
            let Some(guard) = index.try_acquire_generation_reclamation(&relative)? else {
                return Ok(false);
            };
            Some(guard)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if parent == account {
        if old.file_name() != Some(std::ffi::OsStr::new(ramflux_storage::ACCOUNT_DB_FILE)) {
            return Err(super::service::refused("root_conflict"));
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = parent.join(format!("{}{suffix}", ramflux_storage::ACCOUNT_DB_FILE));
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    } else {
        match std::fs::remove_dir_all(parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    std::fs::File::open(&account)?.sync_all()?;
    std::fs::remove_file(marker)?;
    std::fs::File::open(generation)?.sync_all()?;
    Ok(true)
}

#[derive(serde::Deserialize)]
struct Origin {
    #[serde(default)]
    origin: Option<String>,
    #[serde(default, deserialize_with = "present_full")]
    full_transfer: bool,
}
fn present_full<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<bool, D::Error> {
    <serde::de::IgnoredAny as serde::Deserialize>::deserialize(decoder)?;
    Ok(true)
}

fn full_install_ready(
    root: &Path,
    id: &str,
    selected: &ramflux_storage::LocalAccountRecord,
    metadata: Option<&[u8]>,
) -> Result<bool, SdkError> {
    use crate::custody::pairing::{full_generation::FullGenerationManifest, install_store};
    let installed = install_store::read_installed(root, id)?;
    let pending = install_store::list_pending(root, id)?;
    let names_selected = |row: &install_store::Install| {
        row.full_transfer.as_ref().is_some_and(|full| {
            full.db_relative_path == selected.db_relative_path
                && full.object_relative_path == selected.object_dir_relative_path
        })
    };
    // Classification grants no permission: full-profile deletion requires the
    // complete closed manifest and exact installed receipt below.
    let full_manifest = metadata
        .map(ramflux_protocol::parse_i_json::<Origin>)
        .transpose()?
        .is_some_and(|value| value.origin.is_some() || value.full_transfer);
    if !full_manifest
        && !installed.as_ref().is_some_and(names_selected)
        && !pending.iter().any(names_selected)
    {
        return Ok(true);
    }
    let Some(installed) = installed.filter(|row| row.state == "installed" && names_selected(row))
    else {
        return Ok(false);
    };
    let Some(bytes) = metadata else {
        return Ok(false);
    };
    let Ok(manifest) = FullGenerationManifest::decode(bytes) else {
        return Ok(false);
    };
    Ok(selected.local_account_id == installed.account_id
        && selected.principal_commitment == installed.account_anchor
        && manifest == FullGenerationManifest::for_install(&installed)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::pairing::{full_generation::FullGenerationManifest, install_store};
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn pairing_full_reclamation_requires_exact_g3_and_drained_old_readers() -> TestResult {
        let root = crate::bus::runtime_tests::root("pairing-full-reclamation");
        let index = AccountIndex::open(&root)?;
        let mut install = install_store::full_tests::fixture();
        let full = install.full_transfer.as_mut().ok_or("full install")?;
        full.db_relative_path = "accounts/acct/generation_next/account.db".into();
        full.object_relative_path = "accounts/acct/generation_next/objects".into();
        full.expected_prior_generation.db_relative_path = "accounts/acct/account.db".into();
        full.expected_prior_generation.object_relative_path = "accounts/acct/objects".into();
        index.create_account("acct", &install.account_anchor)?;
        let key = ramflux_storage::AccountDbKey::derive("acct", b"reader-drain");
        let db = ramflux_storage::AccountDb::open(&index, "acct", &key)?;
        let reader = db.open_reader()?;
        let previous = index.account("acct")?;
        let generation = root.join("accounts/acct/generation_next");
        std::fs::create_dir_all(generation.join("objects"))?;
        std::fs::write(
            generation.join("account.db"),
            b"prepared database placeholder: metadata/reclamation fixture only",
        )?;
        remember(&generation, Some(&previous))?;
        super::super::recovery::mark_install(&generation)?;
        let wrapped = ramflux_storage::WrappedAccountDbKey {
            key_wrapping_provider: "vault".into(),
            key_wrapping_ref: "b-local".into(),
            nonce: [1; 12],
            wrapped_key: vec![2; 48],
        };
        let manifest = FullGenerationManifest::for_install(&install)?.encode()?;
        let full = install.full_transfer.as_ref().ok_or("full")?;
        index.install_backup_generation(&ramflux_storage::BackupIndexInstall {
            account_id: "acct",
            principal_commitment: &install.account_anchor,
            db_relative_path: &full.db_relative_path,
            object_relative_path: &full.object_relative_path,
            manifest_json: &manifest,
            wrapped_key: &wrapped,
        })?;
        drop(db);
        drop(reader);
        // Isolate G3 from the reader guard: with every old reader drained, G2
        // alone and an unrelated installed receipt must STILL preserve the old DB.
        assert!(!complete(&generation, &root, &index, "acct")?, "G2 alone allowed reclamation");
        let locks = super::super::generation_lock::GenerationLocks::default();
        super::super::recovery::recover_generations(&root, &index, &locks)?;
        assert!(
            generation.join(super::super::recovery::INSTALL_MARKER).exists(),
            "recovery removed pending full marker before G3"
        );
        let old = root.join(&previous.db_relative_path);
        assert!(old.exists());
        let mut wrong = install.clone();
        wrong.full_transfer.as_mut().ok_or("full")?.initial_union_root =
            ramflux_protocol::encode_base64url([99; 32]);
        install_store::write_installed(&root, &wrong)?;
        assert!(
            !complete(&generation, &root, &index, "acct")?,
            "wrong generation receipt allowed reclamation"
        );
        let reader = ramflux_storage::BackupDatabase::open_live_account(&old, &key)?;
        install_store::write_installed(&root, &install)?;
        assert!(
            !complete(&generation, &root, &index, "acct")?,
            "old independent reader was ignored"
        );
        assert!(old.exists());
        drop(reader);
        assert!(complete(&generation, &root, &index, "acct")?);
        assert!(!old.exists());
        assert!(generation.join("account.db").exists());
        assert!(!generation.join(MARKER).exists());
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

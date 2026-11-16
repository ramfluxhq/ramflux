// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creation and restore must publish through the atomic initial-authority path.
use super::{
    checkpoints::{self, Stage},
    *,
};
use crate::custody::{
    CreationCeremony, PrimaryVault,
    tests::{Root, TestVault, create, input, words},
};
use ramflux_protocol::custody::CustodyAuthority;
use ramflux_storage::{AccountIndex, WrappedAccountDbKey};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{cell::RefCell, rc::Rc};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn prepared(root: &Path, id: &str) -> Result<(CreationCeremony, [zeroize::Zeroizing<String>; 3])> {
    let mut ceremony = CreationCeremony::begin(root, input(id), 100)?;
    let phrase = ceremony.show_once()?;
    let answers = words(&phrase, ceremony.hidden_challenge()?)?;
    Ok((ceremony, answers))
}
fn temporaries(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    fs::read_dir(dir)?
        .filter_map(|entry| match entry {
            Ok(entry) if entry.file_name().to_string_lossy().starts_with(".authority-") => {
                Some(Ok(entry.path()))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}
fn observe_publication(dir: &Path, stage: Stage) -> std::result::Result<(), SdkError> {
    let path = dir.join("authority.json");
    if stage == Stage::Published {
        assert_eq!(temporaries(dir)?.len(), 0, "rename must consume the publication temporary");
        let _: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    } else {
        assert_eq!(temporaries(dir)?.len(), 1, "publication temporary must exist before rename");
        assert!(!path.exists(), "authority is visible before the atomic rename");
    }
    Ok(())
}
fn confirm_publication() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let (ceremony, answers) = prepared(&root.0, "created")?;
    let dir = directory(&root.0, "created")?;
    let observed = Rc::new(RefCell::new(Vec::new()));
    let stages = Rc::clone(&observed);
    let observed_dir = dir.clone();
    let _hook = checkpoints::install(move |stage| {
        observe_publication(&observed_dir, stage)?;
        stages.borrow_mut().push(stage);
        Ok(())
    });
    let account = ceremony.confirm(&answers, &vault, 100)?;
    assert_eq!(
        *observed.borrow(),
        [Stage::TemporaryCreated, Stage::TemporarySynced, Stage::Publish, Stage::Published]
    );
    assert_eq!(
        fs::read(dir.join("authority.json"))?,
        ramflux_protocol::canonical_json_bytes(&account.stored)?
    );
    let loaded = super::super::load_account(&root.0, "created", 100)?;
    assert_eq!(loaded.record(), account.record());
    assert_eq!(vault.entry_count()?, 2, "published credentials were deleted");
    assert_eq!(
        vault.load_primary(&loaded.stored.primary_vault_ref)?.public_key(),
        account.record().body.master_certificate.body.self_signing_public_key
    );
    loaded.credentials(&vault, "primary", 100)?;
    assert_eq!(temporaries(&dir)?, Vec::<PathBuf>::new());
    Ok(())
}
#[test]
fn review_genesis_persist_publishes_through_the_no_replace_helper() -> Result {
    confirm_publication()
}
#[test]
fn publication_permission_denied_names_the_check_and_removes_the_sealed_account() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let (ceremony, answers) = prepared(&root.0, "publish-denied")?;
    let _sealed = super::super::race_hooks::install(|stage, root, id| {
        if stage == super::super::race_hooks::Stage::BeforeAuthorityPublish {
            assert!(
                AccountIndex::open(root)?.load_wrapped_db_key(id)?.is_some(),
                "publication runs after the data key is stored"
            );
        }
        Ok(())
    });
    let _deny = checkpoints::install(|stage| {
        if stage == Stage::Publish {
            Err(SdkError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "hard_link denied",
            )))
        } else {
            Ok(())
        }
    });
    let error = ceremony
        .confirm_with_passphrase(&answers, &vault, 100, b"discarded passphrase")
        .expect_err("permission denied while publishing authority");
    assert!(matches!(error, SdkError::CustodyPublicationFailed), "{error}");
    let rendered = error.to_string();
    assert!(!rendered.contains("publish-denied"), "publication error includes the account id");
    assert!(!rendered.contains('/'), "publication error includes a path");
    let body = crate::bus::io::local_bus_error_body(&error);
    assert_eq!(body.code, "CustodyPublicationFailed");
    assert_eq!(body.reason_code.as_deref(), Some("authority_publication"));
    assert!(body.cause.is_none(), "publication failure must not carry an OS path");
    assert!(!body.message.contains("publish-denied"), "bus message includes the account id");
    assert_eq!(vault.entry_count()?, 0, "unpublished vault entries remained");
    assert!(!directory(&root.0, "publish-denied")?.exists(), "locked custody directory remained");
    assert!(!root.0.join("accounts/publish-denied").exists(), "account database remained");
    assert!(matches!(
        AccountIndex::open(&root.0)?.account("publish-denied"),
        Err(ramflux_storage::StorageError::AccountNotFound(_))
    ));
    assert!(
        super::super::list_accounts(&root.0, 100)?.is_empty(),
        "account list kept a locked row"
    );
    Ok(())
}
#[test]
fn custody_final_publication_failure_deletes_both_new_vault_entries() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let _deny = checkpoints::install(|stage| {
        if stage == Stage::Publish {
            Err(SdkError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "hard_link denied",
            )))
        } else {
            Ok(())
        }
    });
    let error = create(&root.0, "final-failure", &vault, 100).expect_err("publication denied");
    let sdk = error.downcast_ref::<SdkError>().expect("test: sdk error");
    assert!(matches!(sdk, SdkError::CustodyPublicationFailed), "{sdk}");
    assert_eq!(vault.entry_count()?, 0, "unpublished vault entries remained");
    assert!(
        !super::super::account_exists(&root.0, "final-failure")?,
        "publication failure left a locked account"
    );
    assert!(super::super::load_account(&root.0, "final-failure", 100).is_err());
    assert!(!root.0.join("local_bus_accounts/final-failure.json").exists());
    Ok(())
}
fn source_authority() -> Result<(Root, CustodyAuthority)> {
    let source = Root::new()?;
    let vault = TestVault::default();
    let (ceremony, answers) = prepared(&source.0, "source")?;
    let account = ceremony.confirm(&answers, &vault, 100)?;
    Ok((
        source,
        CustodyAuthority { publication: account.publication(), custodian_publication: None },
    ))
}
#[test]
fn custody_restore_publishes_through_the_no_replace_helper_with_marker_first() -> Result {
    let (_source, authority) = source_authority()?;
    for interrupt in [false, true] {
        let root = Root::new()?;
        let vault = TestVault::default();
        let dir = directory(&root.0, "restored")?;
        let reservation = Rc::new(RefCell::new(false));
        let saw_marker = Rc::clone(&reservation);
        let _reservation = super::super::race_hooks::install(move |stage, root, id| {
            if stage == super::super::race_hooks::Stage::BeforeReservation {
                assert!(directory(root, id)?.is_dir(), "index reservation preceded the marker");
                assert!(matches!(
                    AccountIndex::open(root)?.account(id),
                    Err(ramflux_storage::StorageError::AccountNotFound(_))
                ));
                *saw_marker.borrow_mut() = true;
            }
            Ok(())
        });
        let observed = Rc::new(RefCell::new(Vec::new()));
        let stages = Rc::clone(&observed);
        let observed_dir = dir.clone();
        let _hook = checkpoints::install(move |stage| {
            observe_publication(&observed_dir, stage)?;
            stages.borrow_mut().push(stage);
            if interrupt && stage == Stage::TemporarySynced {
                return Err(crate::custody::invalid());
            }
            Ok(())
        });
        let restored = super::super::recovery::pending_restore(
            &root.0,
            "restored",
            &authority,
            &vault,
            b"restore data secret",
            100,
        );
        assert!(*reservation.borrow(), "restore bypassed the marker-first reservation");
        if interrupt {
            assert!(matches!(restored, Err(SdkError::CustodySetupInvalid)));
            assert_eq!(*observed.borrow(), [Stage::TemporaryCreated, Stage::TemporarySynced]);
            assert!(!dir.exists(), "a failed restore must not leave a locked account");
            assert_eq!(vault.entry_count()?, 0);
            assert_eq!(super::super::failed_setup(&root.0, "restored")?, None);
        } else {
            let restored = restored?;
            assert_eq!(
                *observed.borrow(),
                [Stage::TemporaryCreated, Stage::TemporarySynced, Stage::Publish, Stage::Published]
            );
            assert_eq!(
                fs::read(dir.join("authority.json"))?,
                ramflux_protocol::canonical_json_bytes(&restored.stored)?
            );
            #[cfg(unix)]
            assert_eq!(
                fs::metadata(dir.join("authority.json"))?.permissions().mode() & 0o777,
                0o600
            );
            let loaded = super::super::load_account(&root.0, "restored", 100)?;
            assert_eq!(loaded.publication(), authority.publication);
            assert!(loaded.branch_pending());
            assert_eq!(vault.entry_count()?, 1);
            crate::client::account::verify_stored_data_secret(
                &root.0,
                "restored",
                b"restore data secret",
            )?;
            assert_eq!(temporaries(&dir)?, Vec::<PathBuf>::new());
        }
    }
    Ok(())
}
fn deny_hard_link(_from: &Path, _to: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from_raw_os_error(1))
}

#[test]
fn hard_link_eperm_at_the_syscall_still_publishes_by_rename() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let (ceremony, answers) = prepared(&root.0, "link-eperm")?;
    let dir = directory(&root.0, "link-eperm")?;
    let calls = Rc::new(std::cell::Cell::new(0_u8));
    let seen = Rc::clone(&calls);
    let observed = dir.clone();
    let _link = crate::platform::fs::install_hard_link(deny_hard_link);
    let _hook = checkpoints::install(move |stage| {
        if stage != Stage::Publish {
            return Ok(());
        }
        let temps = temporaries(&observed)?;
        assert_eq!(temps.len(), 1, "the publication temporary must exist at the link boundary");
        let destination = observed.join("authority.json");
        let error = crate::platform::fs::hard_link(&temps[0], &destination)
            .expect_err("hard link must fail");
        assert_eq!(error.raw_os_error(), Some(1), "the link syscall must return EPERM");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!destination.exists(), "a refused hard link must not publish authority");
        seen.set(seen.get() + 1);
        Ok(())
    });
    let account = ceremony.confirm(&answers, &vault, 100)?;
    assert_eq!(calls.get(), 1, "publication must reach the hard-link syscall once");
    assert_eq!(
        fs::read(dir.join("authority.json"))?,
        ramflux_protocol::canonical_json_bytes(&account.stored)?
    );
    assert_eq!(temporaries(&dir)?, Vec::<PathBuf>::new(), "rename must consume the temporary");
    Ok(())
}

#[test]
fn restore_branch_store_failure_leaves_no_account_or_directory() -> Result {
    let (_source, authority) = source_authority()?;
    let root = Root::new()?;
    let vault = TestVault::default();
    vault.fail_branch.store(true, std::sync::atomic::Ordering::SeqCst);
    let error = super::super::recovery::pending_restore(
        &root.0,
        "restored",
        &authority,
        &vault,
        b"restore data secret",
        100,
    )
    .expect_err("branch store refused");
    assert!(matches!(error, SdkError::CustodyVaultUnavailable), "{error}");
    assert_eq!(AccountIndex::open(&root.0)?.known_account_ids()?.len(), 0);
    for parent in ["custody_accounts", "accounts"] {
        let path = root.0.join(parent);
        let leftover = if path.is_dir() { fs::read_dir(&path)?.count() } else { 0 };
        assert_eq!(leftover, 0, "{parent}");
    }
    assert_eq!(vault.entry_count()?, 0);
    Ok(())
}

#[test]
fn custody_restore_reservation_preserves_existing_index_row_and_wrapped_key() -> Result {
    let (_source, authority) = source_authority()?;
    let root = Root::new()?;
    let index = AccountIndex::open(&root.0)?;
    let before = index.reserve_account("collision", "existing-anchor")?;
    let wrapped = WrappedAccountDbKey {
        key_wrapping_provider: "test".into(),
        key_wrapping_ref: "existing".into(),
        nonce: [4; 12],
        wrapped_key: vec![5; 48],
    };
    index.store_wrapped_db_key("collision", &wrapped)?;
    let vault = TestVault::default();
    assert!(matches!(
        super::super::recovery::pending_restore(
            &root.0,
            "collision",
            &authority,
            &vault,
            b"new secret",
            100
        ),
        Err(SdkError::CustodyAccountConflict)
    ));
    assert_eq!(index.account("collision")?, before);
    assert_eq!(index.load_wrapped_db_key("collision")?, Some(wrapped));
    assert!(!directory(&root.0, "collision")?.exists());
    assert_eq!(vault.entry_count()?, 0);
    Ok(())
}

#[test]
fn reconcile_reaps_stale_authority_temp_before_link() -> Result {
    let root = Root::new()?;
    let lease = crate::bus::data_root_lock::DataRootLock::acquire(&root.0)?;
    let dir = reserve_account(&root.0, "interrupted", "anchor")?;
    let stale = dir.join(".authority-crashed.tmp");
    fs::write(&stale, b"partial authority")?;
    fs::write(dir.join("unrelated"), b"keep")?;
    super::super::reconcile_incomplete_markers(&root.0, &lease)?;
    assert!(!stale.exists());
    assert_eq!(fs::read(dir.join("unrelated"))?, b"keep");
    assert!(!dir.join("authority.json").exists());
    assert!(AccountIndex::open(&root.0)?.account("interrupted").is_ok());
    Ok(())
}
#[test]
fn reconcile_keeps_live_authority_and_credentials_after_link() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let (ceremony, answers) = prepared(&root.0, "published")?;
    let account = ceremony.confirm(&answers, &vault, 100)?;
    let dir = directory(&root.0, "published")?;
    let bytes = fs::read(dir.join("authority.json"))?;
    fs::hard_link(dir.join("authority.json"), dir.join(".authority-crashed.tmp"))?;
    fs::write(dir.join("unrelated"), b"keep")?;
    let lease = crate::bus::data_root_lock::DataRootLock::acquire(&root.0)?;
    super::super::reconcile_incomplete_markers(&root.0, &lease)?;
    assert!(!dir.join(".authority-crashed.tmp").exists());
    assert_eq!(fs::read(dir.join("authority.json"))?, bytes);
    assert_eq!(fs::read(dir.join("unrelated"))?, b"keep");
    assert_eq!(vault.entry_count()?, 2);
    account.credentials(&vault, "primary", 100)?;
    Ok(())
}

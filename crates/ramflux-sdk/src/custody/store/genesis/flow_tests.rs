// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creation and restore must publish through the atomic initial-authority path.
use super::{
    checkpoints::{self, Stage},
    *,
};
use crate::custody::{
    CreationCeremony, PrimaryVault,
    tests::{Root, TestVault, input, words},
};
use ramflux_protocol::custody::CustodyAuthority;
use ramflux_storage::{AccountIndex, WrappedAccountDbKey};
use std::{cell::RefCell, os::unix::fs::PermissionsExt, rc::Rc};
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
    assert_eq!(temporaries(dir)?.len(), 1, "publication temporary must exist at every checkpoint");
    if stage == Stage::Linked {
        let _: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    } else {
        assert!(!path.exists(), "authority is visible before the atomic link");
    }
    Ok(())
}
fn confirm_publication(unlink_failure: bool) -> Result {
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
        if unlink_failure && stage == Stage::Linked {
            // Force a real unlink failure after publication without changing the published inode.
            let temporary = temporaries(&observed_dir)?.remove(0);
            fs::remove_file(&temporary)?;
            fs::create_dir(&temporary)?;
        }
        Ok(())
    });
    let account = ceremony.confirm(&answers, &vault, 100)?;
    assert_eq!(
        *observed.borrow(),
        [Stage::TemporaryCreated, Stage::TemporarySynced, Stage::Linked]
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
    assert_eq!(temporaries(&dir)?.len(), usize::from(unlink_failure));
    Ok(())
}
#[test]
fn review_genesis_persist_publishes_through_the_no_replace_helper() -> Result {
    confirm_publication(false)
}
#[test]
fn custody_genesis_unlink_failure_preserves_published_credentials() -> Result {
    confirm_publication(true)
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
            assert!(!dir.join("authority.json").exists());
            assert_eq!(vault.entry_count()?, 0);
            assert_eq!(
                super::super::failed_setup(&root.0, "restored")?,
                Some("setup_failed_before_authority")
            );
        } else {
            let restored = restored?;
            assert_eq!(
                *observed.borrow(),
                [Stage::TemporaryCreated, Stage::TemporarySynced, Stage::Linked]
            );
            assert_eq!(
                fs::read(dir.join("authority.json"))?,
                ramflux_protocol::canonical_json_bytes(&restored.stored)?
            );
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
        }
        assert_eq!(temporaries(&dir)?, Vec::<PathBuf>::new());
    }
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

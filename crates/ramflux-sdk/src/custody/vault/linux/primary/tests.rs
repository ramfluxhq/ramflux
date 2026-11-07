// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::super::{
    cleanup::observer,
    durability::recording::{Op, RecordingOps},
    test_proc::{in_child, run_in_child},
};
use super::*;
use std::{os::unix::fs::PermissionsExt, path::Path};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const BODY: &str = "custody::vault::linux::primary::tests::";

// Every test below takes the realm lock in its own process (`run_in_child`): a fork by another
// test thread must never be able to inherit a held flock description (P03 fork-window race).
#[test]
fn linux_vault_owned_buffers_clear_on_all_exits() -> TestResult {
    run_in_child(&format!("{BODY}owned_buffers_body"))
}
#[test]
fn linux_vault_primary_delete_reconciles_absence_durably() -> TestResult {
    run_in_child(&format!("{BODY}delete_reconcile_body"))
}
/// Every internal source maps to its own bounded reason; each row is isolated.
#[test]
fn linux_vault_errors_map_to_bounded_reasons() {
    use super::super::init::LinuxVaultInitError as I;
    use files::Error as F;
    use rustix::io::Errno;
    fn reason_of(error: &SdkError) -> Option<CustodyVaultReason> {
        match error {
            SdkError::CustodyVault(reason) => Some(*reason),
            _ => None,
        }
    }
    fn init(error: I) -> Option<CustodyVaultReason> {
        reason_of(&init_error(error))
    }
    fn file(error: F) -> Option<CustodyVaultReason> {
        reason_of(&files_error(error))
    }
    use CustodyVaultReason as R;
    assert_eq!(init(I::Missing), Some(R::Missing), "init Missing");
    assert_eq!(file(F::Missing), Some(R::Missing), "files Missing");
    assert_eq!(init(I::Pending), Some(R::InitPending), "init Pending");
    assert_eq!(init(I::Corrupt), Some(R::Corrupt), "init Corrupt");
    assert_eq!(init(I::Length), Some(R::Corrupt), "init Length");
    assert_eq!(init(I::Realm), Some(R::Corrupt), "init Realm");
    assert_eq!(file(F::Generation), Some(R::Corrupt), "files Generation");
    assert_eq!(file(F::Record(codec::Error::Authentication)), Some(R::Corrupt), "files Record");
    assert_eq!(init(I::Metadata), Some(R::Permission), "init Metadata");
    assert_eq!(file(F::Path), Some(R::Permission), "files Path");
    assert_eq!(file(F::Metadata), Some(R::Permission), "files Metadata");
    assert_eq!(init(I::from(Errno::ACCESS)), Some(R::Permission), "init EACCES");
    assert_eq!(init(I::from(Errno::PERM)), Some(R::Permission), "init EPERM");
    assert_eq!(file(F::from(Errno::ACCESS)), Some(R::Permission), "files EACCES");
    assert_eq!(file(F::from(Errno::PERM)), Some(R::Permission), "files EPERM");
    assert_eq!(init(I::Provider), Some(R::Locked), "init Provider");
    assert_eq!(init(I::Timeout), Some(R::Locked), "init Timeout");
    assert_eq!(init(I::Busy), Some(R::Busy), "init Busy");
    assert_eq!(file(F::Busy), Some(R::Busy), "files Busy");
    assert_eq!(init(I::Mode), Some(R::ModeMismatch), "init Mode");
    // Unchanged unit variant and the existing randomness error.
    assert!(matches!(init_error(I::Io), SdkError::CustodyVaultUnavailable), "init Io");
    assert!(
        matches!(init_error(I::Cancelled), SdkError::CustodyVaultUnavailable),
        "init Cancelled"
    );
    assert!(matches!(files_error(F::Io), SdkError::CustodyVaultUnavailable), "files Io");
    assert!(matches!(files_error(F::Exists), SdkError::CustodyVaultUnavailable), "files Exists");
    assert!(matches!(files_error(F::Full), SdkError::CustodyVaultUnavailable), "files Full");
    assert!(matches!(init_error(I::Random), SdkError::CustodyRandomUnavailable), "init Random");
}
#[test]
fn linux_vault_primary_open_builds_stores_in_a_slot_owning_worker() -> TestResult {
    run_in_child(&format!("{BODY}open_worker_body"))
}

fn provider_in(
    root: &Path,
    reference: &str,
) -> Result<LinuxPrimaryVault, Box<dyn std::error::Error>> {
    let mut provider = LinuxPrimaryVault {
        realms: std::array::from_fn(|_| None),
        reference: reference.into(),
        class: "test",
        role: LinuxVaultRole::AttendedPrimary,
    };
    for i in 0..3 {
        let mut key = Secret::new("p06-owned-kek");
        key.bytes_mut().fill(9);
        provider.realms[i] = Some(Realm {
            store: files::Store::open(root, "account", u8::try_from(i + 1)?, [1; 16], [2; 16])?,
            key,
        });
    }
    Ok(provider)
}
fn private_root() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(root)
}

#[test]
fn delete_reconcile_body() -> TestResult {
    if !in_child() {
        return Ok(());
    }
    let root = private_root()?;
    let reference = ramflux_protocol::encode_base64url([7; 32]);
    let branch = format!("branch:{reference}");
    let provider = provider_in(root.path(), &reference)?;
    provider.store_branch(&branch, &Zeroizing::new([4; 64]))?;
    let entry = root.path().join("account/2").join(&branch);
    assert!(entry.exists());
    // Normal delete: unlink, then the parent fsync.
    let ops = RecordingOps::new(None);
    provider.realms[1].as_ref().ok_or("device realm")?.delete_with(&branch, 2, &ops)?;
    assert_eq!(*ops.log.borrow(), [Op::Unlink, Op::DirSync]);
    // Unlink succeeds but the parent fsync fails: the failure is reported, the entry is gone.
    provider.store_branch(&branch, &Zeroizing::new([4; 64]))?;
    let failing = RecordingOps::new(Some(Op::DirSync));
    assert!(matches!(
        provider.realms[1].as_ref().ok_or("device realm")?.delete_with(&branch, 2, &failing),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert_eq!(*failing.log.borrow(), [Op::Unlink, Op::DirSync]);
    assert!(!entry.exists(), "the unlink itself happened");
    // Retry: absence is reconciled with a real parent fsync before success is reported.
    let retry = RecordingOps::new(None);
    provider.realms[1].as_ref().ok_or("device realm")?.delete_with(&branch, 2, &retry)?;
    assert_eq!(*retry.log.borrow(), [Op::DirSync], "absence is made durable, not assumed");
    // A failing reconcile fsync is an error, never a silent success.
    let failing_retry = RecordingOps::new(Some(Op::DirSync));
    assert!(matches!(
        provider.realms[1].as_ref().ok_or("device realm")?.delete_with(&branch, 2, &failing_retry),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    Ok(())
}

#[test]
fn open_worker_body() -> TestResult {
    if !in_child() {
        return Ok(());
    }
    let root = private_root()?;
    let mut material = init::Material {
        vault_id: [1; 16],
        key_ids: [[2; 16]; 3],
        keys: std::array::from_fn(|_| None),
    };
    for key in &mut material.keys {
        *key = Some(Secret::new("p06-owned-kek"));
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let realms = runtime.block_on(build_realms(root.path().into(), "account".into(), material))?;
    assert!(realms.iter().all(Option::is_some));
    let worker = test_seam::open_thread(root.path()).ok_or("stores were not built by a worker")?;
    assert_ne!(worker, std::thread::current().id(), "stores must not be built on the async caller");
    // The cap applies to the worker: with every slot held the open is refused.
    let held: Vec<_> = (0..4).map(|_| init::Slot::acquire()).collect::<Result<Vec<_>, _>>()?;
    let refused = tempfile::tempdir()?;
    let again = init::Material {
        vault_id: [1; 16],
        key_ids: [[2; 16]; 3],
        keys: std::array::from_fn(|_| Some(Secret::new("p06-owned-kek"))),
    };
    assert!(matches!(
        runtime.block_on(build_realms(refused.path().into(), "account".into(), again)),
        Err(SdkError::CustodyVault(CustodyVaultReason::Busy))
    ));
    drop(held);
    Ok(())
}

#[test]
fn owned_buffers_body() -> TestResult {
    if !in_child() {
        return Ok(());
    }
    let root = private_root()?;
    let reference = ramflux_protocol::encode_base64url([7; 32]);
    let branch = format!("branch:{reference}");
    let device =
        DeviceRef { account_anchor: "anchor".into(), device_id: "desktop".into(), device_epoch: 1 };
    let mut provider = LinuxPrimaryVault {
        realms: std::array::from_fn(|_| None),
        reference: reference.clone(),
        class: "test",
        role: LinuxVaultRole::AttendedPrimary,
    };
    let _session = observer::begin(&["p06-primary-seed", "p06-branch-seed", "p06-owned-kek"]);
    for i in 0..3 {
        let mut key = Secret::new("p06-owned-kek");
        key.bytes_mut().fill(9);
        provider.realms[i] = Some(Realm {
            store: files::Store::open(
                root.path(),
                "account",
                u8::try_from(i + 1)?,
                [1; 16],
                [2; 16],
            )?,
            key,
        });
    }
    let key = SelfSigningKey::from_vault_seed(&Zeroizing::new([3; 32]));
    provider.store_new(&reference, &key)?;
    assert_eq!(provider.load_primary(&reference)?.public_key(), key.public_key());
    provider.store_branch(&branch, &Zeroizing::new([4; 64]))?;
    drop(provider.load_branch(&branch, "principal", &device)?);
    let mut bad_device = device;
    bad_device.device_epoch = 0;
    assert!(matches!(
        provider.load_branch(&branch, "principal", &bad_device),
        Err(SdkError::CustodySetupInvalid)
    ));
    assert!(matches!(provider.store_new(&reference, &key), Err(SdkError::CustodyVaultUnavailable)));
    // Authentication failure after actual readback allocation.
    provider.realms[0].as_mut().ok_or("primary realm")?.key.bytes_mut().fill(8);
    assert!(matches!(
        provider.load_primary(&reference),
        Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt))
    ));
    let pending = format!("agent-provisioning:{reference}");
    provider.store_provisioning_secret(&pending, b"data-secret")?;
    provider.role = LinuxVaultRole::DataOnly;
    assert!(matches!(
        provider.load_provisioning_secret(&pending),
        Err(SdkError::CustodyVault(CustodyVaultReason::PrimaryUnavailable))
    ));
    // Synchronous adapters have no suspension point; releasing the handle clears retained KEKs.
    drop(provider);
    let observations = observer::take();
    for label in ["p06-primary-seed", "p06-branch-seed", "p06-owned-kek"] {
        assert!(observations.iter().any(|o| o.label == label), "missing {label}");
    }
    for observation in observations {
        assert!(observation.bytes.iter().all(|b| *b == 0), "P06 uncleared {}", observation.label);
    }
    Ok(())
}

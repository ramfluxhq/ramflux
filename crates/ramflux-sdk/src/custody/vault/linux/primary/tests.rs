// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::super::cleanup::observer;
use super::*;

#[test]
fn linux_vault_owned_buffers_clear_on_all_exits() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
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
    observer::begin();
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
    assert!(matches!(provider.load_primary(&reference), Err(SdkError::CustodyVaultUnavailable)));
    let pending = format!("agent-provisioning:{reference}");
    provider.store_provisioning_secret(&pending, b"data-secret")?;
    provider.role = LinuxVaultRole::DataOnly;
    assert!(matches!(
        provider.load_provisioning_secret(&pending),
        Err(SdkError::CustodyVaultUnavailable)
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

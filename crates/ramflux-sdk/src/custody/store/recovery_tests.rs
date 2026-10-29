// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recovery persistence retains only fresh vault credentials and public signed intent.
use super::*;
use crate::custody::tests::{Root, TestVault};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn known_account(root: &Path, vault: &TestVault) -> TestResult<(BornAccount, Zeroizing<String>)> {
    let input = crate::custody::tests::input("recoverable");
    let phrase = RecoveryPhrase::from_entropy(&[0; 32])?;
    let master = MasterKey::from_phrase(&phrase)?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
    let branch =
        ramflux_crypto::create_device_branch(&input.principal_id, &input.device_id, 1, [3; 32]);
    let now = crate::custody::network_now()?;
    let record = ramflux_crypto::custody::create_genesis(
        &master,
        &primary,
        &branch,
        &ramflux_crypto::X25519KeyPair::from_seed([4; 32]),
        ramflux_crypto::custody::GenesisInput {
            principal_kind: input.principal_kind,
            display_name: input.display_name.clone(),
            issued_at: now,
            master_cert_id: ramflux_protocol::encode_base64url([5; 32]),
            branch_cert_id: ramflux_protocol::encode_base64url([6; 32]),
            external_human_primary: None,
        },
    )?;
    drop(master);
    let mut seeds = Zeroizing::new([0; 64]);
    seeds[..32].fill(3);
    seeds[32..].fill(4);
    let account = super::super::persist(
        root,
        &input,
        super::super::GenesisMaterial {
            record,
            primary: &primary,
            branch: &seeds,
            now,
            data_secret: Some(b"independent data secret"),
            commit_gate: None,
        },
        vault,
    )?;
    Ok((account, phrase.display_words()))
}
fn master_seed() -> TestResult<Zeroizing<Vec<u8>>> {
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ramflux-crypto/tests/fixtures/custody_v3.json"
    )))?;
    let encoded = vector["master_seed_hex"].as_str().ok_or("master vector")?;
    Ok(Zeroizing::new(
        encoded
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair)?, 16).map_err(Into::into))
            .collect::<TestResult<Vec<_>>>()?,
    ))
}
fn assert_no_secret(root: &Path, secret: &[u8]) -> TestResult {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            assert_no_secret(&entry.path(), secret)?;
        } else {
            let bytes = fs::read(entry.path())?;
            assert!(
                !bytes.windows(secret.len()).any(|part| part == secret),
                "master or phrase persisted"
            );
        }
    }
    Ok(())
}

#[test]
fn phrase_recovery_never_persists_master_and_reconciles_a_crash_before_authority_selection()
-> TestResult {
    let root = Root::new()?;
    let vault = TestVault::default();
    let (prior, phrase) = known_account(&root.0, &vault)?;
    let old = fs::read(directory(&root.0, "recoverable")?.join("authority.json"))?;
    let old_primary = prior.stored.primary_vault_ref.clone();
    let old_branch = prior.stored.branch_vault_ref.clone();
    let now = crate::custody::network_now()?;
    let recovery = RecoveryCeremony::begin(&root.0, "recoverable", now)?;
    let anchor = recovery.account_anchor().to_owned();
    let replacement = recovery.confirm(&phrase, &anchor, &vault, now)?;
    assert_eq!(replacement.state(), CreationState::NetworkingPending);
    assert_ne!(replacement.local_device_id()?, prior.local_device_id()?);
    assert!(replacement.require_networking().is_err());
    assert!(replacement.stored.pins.require_current(prior.verified()).is_err());
    assert!(
        replacement
            .verified()
            .authorize(
                &prior.record().body.master_certificate.body.primary_device_ref,
                "register",
                now
            )
            .is_err()
    );
    // The durable journal must select the certified intent even if selection was interrupted.
    fs::write(directory(&root.0, "recoverable")?.join("authority.json"), old)?;
    let mut resumed = load_data_account(&root.0, "recoverable", now)?;
    assert_eq!(resumed.record(), replacement.record());
    assert_eq!(resumed.state(), CreationState::NetworkingPending);
    let seed = master_seed()?;
    assert_no_secret(&root.0, &seed)?;
    assert_no_secret(&root.0, phrase.as_bytes())?;
    assert!(!vault.contains_material(&seed)?);
    assert!(!vault.contains_material(phrase.as_bytes())?);
    // Unit persistence transition only; TLS/durable server ACK is exercised separately.
    resumed.mark_live(&root.0)?;
    finish_recovery(&root.0, "recoverable", &vault, now)?;
    assert!(vault.load_primary(&old_primary).is_err());
    assert!(
        vault
            .load_branch(
                &old_branch,
                &prior.record().body.principal_id,
                &prior.record().body.master_certificate.body.primary_device_ref
            )
            .is_err()
    );
    assert!(journal(&root.0, "recoverable")?.is_none());
    assert_no_secret(&root.0, &seed)?;
    Ok(())
}

#[test]
fn wrong_phrase_or_cancelled_recovery_cannot_change_authority_or_leave_vault_entries() -> TestResult
{
    let root = Root::new()?;
    let vault = TestVault::default();
    let (_, phrase) = known_account(&root.0, &vault)?;
    let path = directory(&root.0, "recoverable")?.join("authority.json");
    let before = fs::read(&path)?;
    let entries = vault.entry_count()?;
    let now = crate::custody::network_now()?;
    let pending = RecoveryCeremony::begin(&root.0, "recoverable", now)?;
    let anchor = pending.account_anchor().to_owned();
    let wrong = RecoveryPhrase::from_entropy(&[1; 32])?.display_words();
    assert!(matches!(
        pending.confirm(&wrong, &anchor, &vault, now),
        Err(SdkError::CustodyConfirmationFailed)
    ));
    assert_eq!(fs::read(&path)?, before);
    assert_eq!(vault.entry_count()?, entries);
    assert!(!directory(&root.0, "recoverable")?.join(".authority.lock").exists());
    let mut pending = RecoveryCeremony::begin(&root.0, "recoverable", now)?;
    let gate = std::sync::Arc::new(crate::custody::CommitGate::new(pending.deadline()));
    gate.cancel();
    pending.guard_commit(gate);
    assert!(pending.confirm(&phrase, &anchor, &vault, now).is_err());
    assert_eq!(fs::read(path)?, before);
    assert_eq!(vault.entry_count()?, entries);
    assert!(journal(&root.0, "recoverable")?.is_none());
    Ok(())
}

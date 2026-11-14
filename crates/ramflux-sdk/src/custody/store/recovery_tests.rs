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
fn declaration_publication(
    root: &Path,
    account: &BornAccount,
    vault: &TestVault,
    issued_at: u64,
) -> TestResult<ramflux_protocol::custody::Publication> {
    let device_id = account.local_device_id()?.to_owned();
    let (_, branch) = account.credentials(vault, &device_id, issued_at)?;
    // This public raw-key API acquires its own signing barrier; do not nest a lease.
    let primary = vault.load_primary(account.primary_vault_ref())?;
    let publication = account.candidate_message_layer_publication(
        root,
        &branch,
        &primary,
        ramflux_protocol::custody::MESSAGE_LAYER_FLOOR,
        crate::custody::DeclarationValidity { issued_at, expires_at: issued_at + 120 },
    )?;
    crate::custody::accept_publication(
        root,
        account.local_account_id(),
        &ramflux_protocol::custody::CustodyAuthority {
            publication: publication.clone(),
            custodian_publication: None,
        },
        issued_at,
    )?;
    Ok(publication)
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
    let (mut prior, phrase) = known_account(&root.0, &vault)?;
    let now = crate::custody::network_now()?;
    prior.bind_capacity_node(&root.0, "recovery-node", "recovery-key", now)?;
    prior.set_networking_reason(
        &root.0,
        Some(crate::AccountNetworkingReason::NodeBusy {
            retry_after_ms: 300_000,
            capacity: Some(ramflux_protocol::custody::CapacityHint {
                scope: ramflux_protocol::custody::CapacityScope::PrefixDaily,
                resets_at_unix: now + 3600,
            }),
        }),
    )?;
    let old = fs::read(directory(&root.0, "recoverable")?.join("authority.json"))?;
    let old_primary = prior.stored.primary_vault_ref.clone();
    let old_branch = prior.stored.branch_vault_ref.clone();
    let now = crate::custody::network_now()?;
    let recovery = RecoveryCeremony::begin(&root.0, "recoverable", now)?;
    let anchor = recovery.account_anchor().to_owned();
    let replacement = recovery.confirm(&phrase, &anchor, &vault, now)?;
    assert_eq!(replacement.state(), CreationState::NetworkingPending);
    replacement.check_capacity_deadline(now)?;
    assert!(replacement.networking_reason().is_none());
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
    resumed.check_capacity_deadline(now)?;
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

#[test]
fn custody_recovery_journal_allows_connection_metadata_but_rejects_credential_changes() -> TestResult
{
    let root = Root::new()?;
    let vault = TestVault::default();
    let (_, phrase) = known_account(&root.0, &vault)?;
    let now = crate::custody::network_now()?;
    let recovery = RecoveryCeremony::begin(&root.0, "recoverable", now)?;
    let anchor = recovery.account_anchor().to_owned();
    let mut account = recovery.confirm(&phrase, &anchor, &vault, now)?;
    let record = account.record().clone();
    account.bind_capacity_node(&root.0, "recovery-node", "recovery-key", now)?;
    let mut account = load_data_account(&root.0, "recoverable", now)?;
    assert_eq!(account.record(), &record);
    account.set_networking_reason(
        &root.0,
        Some(crate::AccountNetworkingReason::NodeBusy {
            retry_after_ms: 300_000,
            capacity: Some(ramflux_protocol::custody::CapacityHint {
                scope: ramflux_protocol::custody::CapacityScope::PrefixDaily,
                resets_at_unix: now + 3600,
            }),
        }),
    )?;
    let mut account = load_data_account(&root.0, "recoverable", now)?;
    assert_eq!(account.record(), &record);
    assert!(account.check_capacity_deadline(now).is_err());
    account.bind_capacity_node(&root.0, "replacement-node", "replacement-key", now)?;
    load_data_account(&root.0, "recoverable", now)?.check_capacity_deadline(now)?;
    let path = directory(&root.0, "recoverable")?.join("authority.json");
    let original = fs::read(&path)?;
    for field in ["primary_vault_ref", "branch_vault_ref", "local_device_id", "vault_class"] {
        let mut forged: serde_json::Value = serde_json::from_slice(&original)?;
        forged[field] = "changed-outside-the-recovery-intent".into();
        fs::write(&path, ramflux_protocol::canonical_json_bytes(&forged)?)?;
        assert!(
            matches!(
                load_data_account(&root.0, "recoverable", now),
                Err(SdkError::CustodySetupInvalid)
            ),
            "recovery accepted an unexpected {field}"
        );
        fs::write(&path, &original)?;
    }
    let mut account = load_data_account(&root.0, "recoverable", now)?;
    account.mark_live(&root.0)?;
    finish_recovery(&root.0, "recoverable", &vault, now)?;
    assert!(journal(&root.0, "recoverable")?.is_none());
    Ok(())
}

#[test]
fn declaration_bearing_backup_restore_refuses_history_and_accepts_forward_refresh() -> TestResult {
    let source = Root::new()?;
    let source_vault = TestVault::default();
    let (source_account, _) = known_account(&source.0, &source_vault)?;
    let original = source_account.publication();
    let issued_at = crate::custody::network_now()? + 1;
    let backed_up = declaration_publication(&source.0, &source_account, &source_vault, issued_at)?;
    assert_eq!(
        backed_up.record.body.devices[0]
            .message_layer
            .as_ref()
            .ok_or("backup declaration")?
            .declaration
            .declaration_sequence,
        1
    );

    // Import the declaration-bearing backup through the same pending-restore path used by
    // account.restore.install, not by replaying a peer observation.
    let restored_root = Root::new()?;
    let restored_vault = TestVault::default();
    let authority = ramflux_protocol::custody::CustodyAuthority {
        publication: backed_up.clone(),
        custodian_publication: None,
    };
    let restored = pending_restore(
        &restored_root.0,
        "restored",
        &authority,
        &restored_vault,
        b"restore data secret",
        issued_at,
    )?;
    let device_key = ramflux_protocol::qualified_device_id(
        &backed_up.record.body.account_anchor,
        &backed_up.record.body.devices[0].device_id,
    )?;
    assert_eq!(restored.stored.message_layer_sequences.get(&device_key), Some(&1));
    assert_eq!(restored.record(), &backed_up.record);

    let authority_path = directory(&restored_root.0, "restored")?.join("authority.json");
    let before_rollback = fs::read(&authority_path)?;
    assert!(
        crate::custody::accept_publication(
            &restored_root.0,
            "restored",
            &ramflux_protocol::custody::CustodyAuthority {
                publication: original,
                custodian_publication: None,
            },
            issued_at + 1,
        )
        .is_err()
    );
    assert_eq!(fs::read(&authority_path)?, before_rollback);

    let primary = source_vault.primary_for_public_key(
        &backed_up.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = backed_up.record.body.clone();
    body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&backed_up.record)?);
    let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
    body.device_set_epoch = ramflux_protocol::custody::encode_epoch(
        range,
        revision.checked_add(1).ok_or("native revision overflow")?,
    )?;
    body.issued_at = issued_at + 2;
    let refreshed = ramflux_protocol::custody::Publication {
        record: primary.sign_record(body)?,
        compacted_ids: None,
    };
    assert_eq!(
        crate::custody::accept_publication(
            &restored_root.0,
            "restored",
            &ramflux_protocol::custody::CustodyAuthority {
                publication: refreshed.clone(),
                custodian_publication: None,
            },
            issued_at + 2,
        )?,
        ramflux_crypto::custody::PinOutcome::Advanced
    );
    let refreshed_account = load_data_account(&restored_root.0, "restored", issued_at + 2)?;
    assert_eq!(refreshed_account.record(), &refreshed.record);
    assert_eq!(refreshed_account.stored.message_layer_sequences.get(&device_key), Some(&1));
    assert!(refreshed_account.stored.pins.require_current(refreshed_account.verified()).is_ok());
    Ok(())
}

#[test]
fn declaration_sequence_high_water_survives_phrase_recovery() -> TestResult {
    let root = Root::new()?;
    let vault = TestVault::default();
    let (account, phrase) = known_account(&root.0, &vault)?;
    let issued_at = crate::custody::network_now()? + 1;
    declaration_publication(&root.0, &account, &vault, issued_at)?;
    let key = ramflux_protocol::qualified_device_id(
        &account.record().body.account_anchor,
        account.local_device_id()?,
    )?;
    let prior = load_data_account(&root.0, "recoverable", issued_at)?;
    assert_eq!(prior.stored.message_layer_sequences.get(&key), Some(&1));

    let recovery = RecoveryCeremony::begin(&root.0, "recoverable", issued_at)?;
    let anchor = recovery.account_anchor().to_owned();
    let recovered = recovery.confirm(&phrase, &anchor, &vault, issued_at)?;
    assert_eq!(recovered.stored.message_layer_sequences.get(&key), Some(&1));
    let reopened = load_data_account(&root.0, "recoverable", issued_at)?;
    assert_eq!(reopened.stored.message_layer_sequences.get(&key), Some(&1));
    Ok(())
}

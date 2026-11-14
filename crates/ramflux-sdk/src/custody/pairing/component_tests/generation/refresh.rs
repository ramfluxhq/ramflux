// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary native profile refresh keeps an already installed full data generation.
use super::{
    ClockHold, CustodyAuthority, Rig, TestResult, admits_exact_g3, bootstrap_full_rig,
    canonical_json_bytes, custody, finish_owned_stream, install_live_generation,
    publication_with_cleanup,
};
use crate::custody::pairing::{
    LocalPairingParticipant, PairingAuthorityQuery, publication::NodeHeadPersist,
};

#[tokio::test(start_paused = true)]
async fn pairing_full_profile_refresh_preserves_selected_generation_and_source_secondary()
-> TestResult {
    Box::pin(run_refresh(false)).await
}
#[tokio::test(start_paused = true)]
async fn pairing_authority_refresh_preserves_role_refs_after_reopen() -> TestResult {
    crate::bus::credentials::contract_tests::deadline(Box::pin(run_refresh(true))).await
}
async fn run_refresh(reopen: bool) -> TestResult {
    let hold = ClockHold::new();
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    rig.primary.sync_relay().await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let mut published = Box::pin(publication_with_cleanup(&mut rig, &operation, true)).await?;
    let cleanup = published.source_cleanup.take().ok_or("source cleanup receipt")?;
    install_live_generation(&rig, &operation, published)?;
    let old =
        custody::load_account(&rig.participant_b.root, &rig.participant_b.account_id, rig.now)?;
    let selected_before = ramflux_storage::AccountIndex::open(&rig.participant_b.root)?
        .account_generation_selection(&rig.participant_b.account_id)?;
    let adoption_before = rig
        .participant_b
        .db
        .lock()
        .map_err(|_| "B before refresh")?
        .as_ref()
        .ok_or("B before writer")?
        .pairing_adoption()?
        .ok_or("B before receipt")?;
    let authority = publish_profile(&rig, &old).map_err(|e| format!("profile publish: {e}"))?;
    rig.now += 1;
    crate::time::FixedClock::advance_to(i64::try_from(rig.now)?);
    // Native query, not the request or a relay success flag, supplies refresh authority.
    let observed = rig.node.current_authority(&authority.publication.record.body.account_anchor)?;
    assert_eq!(canonical_json_bytes(&observed)?, canonical_json_bytes(&authority)?);
    require_observed_head_fences_old_install(&rig, &observed)?;
    refresh_participant(&rig.participant_b, &observed, rig.now)
        .map_err(|e| format!("B full refresh: {e}"))?;
    rig.participant_a.take_client(&mut rig.source.client)?;
    refresh_participant(&rig.participant_a, &observed, rig.now)
        .map_err(|e| format!("A secondary refresh: {e}"))?;
    finish_deferred_source_cleanup(&rig, &cleanup, &operation)?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    let selected_after = ramflux_storage::AccountIndex::open(&rig.participant_b.root)?
        .account_generation_selection(&rig.participant_b.account_id)?;
    assert_eq!(
        selected_before.account, selected_after.account,
        "native refresh replaced selected full paths"
    );
    assert_eq!(
        selected_before.manifest_json, selected_after.manifest_json,
        "native refresh replaced selected full manifest"
    );
    require_refreshed_owners(&rig, &old, &adoption_before, &authority)
        .map_err(|e| format!("refreshed owners/admission: {e}"))?;
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    if reopen {
        reopen_refreshed_frontends(&mut rig, &authority, &old)
            .map_err(|error| format!("test: refresh reopen: {error}"))?;
    }
    hold.finish().await?;
    Ok(())
}

fn require_observed_head_fences_old_install(rig: &Rig, authority: &CustodyAuthority) -> TestResult {
    let mut frontend = crate::RamfluxClient::new();
    rig.participant_b.return_client(&mut frontend)?;
    custody::accept_publication(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
        authority,
        rig.now,
    )?;
    assert!(
        !crate::custody::pairing::ordinary_session_admitted(
            &frontend,
            &rig.participant_b.account_id
        )?,
        "test: an observed newer native head admitted stale full-generation authority"
    );
    rig.participant_b.take_client(&mut frontend)?;
    Ok(())
}

fn publish_profile(
    rig: &Rig,
    account: &custody::BornAccount,
) -> Result<CustodyAuthority, Box<dyn std::error::Error>> {
    let primary = account.group_primary(rig.participant_b.vault.as_ref())?;
    let mut body = account.record().body.clone();
    let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
    body.device_set_epoch = ramflux_protocol::custody::encode_epoch(range, revision + 1)?;
    body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(account.record())?);
    body.issued_at = rig.now + 1;
    body.profile.display_name = "Refreshed primary".into();
    let publication = ramflux_protocol::custody::Publication {
        record: primary.sign_record(body)?,
        compacted_ids: None,
    };
    drop(primary); // Public native I/O must not retain the signing lease.
    rig.node.persist_head(&publication, rig.now + 1)?;
    Ok(CustodyAuthority { publication, custodian_publication: None })
}

fn refresh_participant(
    participant: &LocalPairingParticipant,
    authority: &CustodyAuthority,
    now: u64,
) -> TestResult {
    let slot = participant.db.lock().map_err(|_| "refresh owner")?;
    let db = slot.as_ref().ok_or("refresh writer")?;
    crate::custody::pairing::refresh_authority(
        &participant.root,
        db,
        participant.vault.as_ref(),
        &participant.account_id,
        authority,
        now,
    )?;
    Ok(())
}

fn require_refreshed_owners(
    rig: &Rig,
    old: &custody::BornAccount,
    adoption_before: &ramflux_storage::AdoptionRow,
    authority: &CustodyAuthority,
) -> TestResult {
    let slot = rig.participant_b.db.lock().map_err(|_| "B refreshed")?;
    let db = slot.as_ref().ok_or("B refreshed writer")?;
    let adopted = db.pairing_adoption()?.ok_or("B refreshed receipt")?;
    assert_eq!(adopted.full_generation_nonce, adoption_before.full_generation_nonce);
    assert_eq!(adopted.full_initial_union_root, adoption_before.full_initial_union_root);
    let installed = super::super::super::install_store::read_installed(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
    )?
    .ok_or("B refreshed marker")?;
    assert_eq!(installed.version, 2);
    assert!(installed.full_transfer.is_none());
    admits_exact_g3(rig, db, &installed)?;
    let primary =
        custody::load_account(&rig.participant_b.root, &rig.participant_b.account_id, rig.now)?;
    assert_eq!(primary.primary_vault_ref(), old.primary_vault_ref());
    let key = primary.group_primary(rig.participant_b.vault.as_ref())?;
    assert_eq!(
        key.public_key(),
        authority.publication.record.body.master_certificate.body.self_signing_public_key
    );
    drop(key);
    assert!(
        old.group_primary(rig.participant_b.vault.as_ref()).is_err(),
        "stale cached native head signed"
    );
    let source =
        custody::load_account(&rig.participant_a.root, &rig.participant_a.account_id, rig.now)?;
    assert_eq!(source.primary_vault_ref(), "");
    assert!(matches!(
        source.group_primary(rig.participant_a.vault.as_ref()),
        Err(crate::SdkError::PairingCode("PrimaryRequired"))
    ));
    Ok(())
}

fn finish_deferred_source_cleanup(
    rig: &Rig,
    cleanup: &crate::custody::pairing::FullSourcePublished,
    operation: &str,
) -> TestResult {
    let slot = rig.participant_a.db.lock().map_err(|_| "source refreshed cleanup")?;
    let db = slot.as_ref().ok_or("source refreshed writer")?;
    let before = db.pairing_adoption()?.ok_or("source refreshed receipt")?;
    let unavailable = super::source_tail::DeleteUnavailable(rig.participant_a.vault.as_ref());
    assert_eq!(
        cleanup.retire_source(&crate::custody::pairing::Installation {
            root: &rig.participant_a.root,
            db,
            vault: &unavailable,
            now: rig.now,
        })?,
        crate::custody::pairing::FullSourceRetirementOutcome::CleanupPending
    );
    let local = crate::custody::pairing::Installation {
        root: &rig.participant_a.root,
        db,
        vault: rig.participant_a.vault.as_ref(),
        now: rig.now,
    };
    // Unlock/hourly/status work needs only the durable positive cleanup owner.
    assert_eq!(
        crate::custody::pairing::retry_full_source_cleanup(&local, operation)?,
        crate::custody::pairing::FullSourceRetirementOutcome::Complete
    );
    assert_eq!(
        crate::custody::pairing::retry_full_source_cleanup(&local, operation)?,
        crate::custody::pairing::FullSourceRetirementOutcome::Complete
    );
    assert_eq!(
        db.pairing_adoption()?.ok_or("source post-cleanup receipt")?,
        before,
        "old key cleanup rewrote a later native head"
    );
    assert_eq!(
        super::super::super::install_store::list_pending(
            &rig.participant_a.root,
            &rig.participant_a.account_id
        )?
        .len(),
        0
    );
    Ok(())
}

fn reopen_refreshed_frontends(
    rig: &mut Rig,
    authority: &CustodyAuthority,
    old: &custody::BornAccount,
) -> TestResult {
    use crate::custody::pairing::ordinary_session_admitted;
    let source =
        custody::load_account(&rig.participant_a.root, &rig.participant_a.account_id, rig.now)?;
    let primary =
        custody::load_account(&rig.participant_b.root, &rig.participant_b.account_id, rig.now)?;
    let owners = [
        (
            &rig.participant_a,
            b"fresh-source-data".as_slice(),
            source.branch_vault_ref().to_owned(),
            source.primary_vault_ref().to_owned(),
            "source-vault",
        ),
        (
            &rig.participant_b,
            b"component-recipient-passphrase".as_slice(),
            primary.branch_vault_ref().to_owned(),
            primary.primary_vault_ref().to_owned(),
            "branch-vault",
        ),
    ];
    rig.source.client = crate::RamfluxClient::new();
    for (participant, password, branch_ref, primary_ref, directory) in owners {
        assert!(
            participant.db.lock().map_err(|_| "test: closed participant")?.is_none(),
            "test: pairing close retained an ordinary database across the process-equivalent reopen"
        );
        let before = ramflux_storage::AccountIndex::open(&participant.root)?
            .account_generation_selection(&participant.account_id)?;
        let wrapped = ramflux_storage::AccountIndex::open(&participant.root)?
            .load_wrapped_db_key(&participant.account_id)?
            .ok_or("test: own wrapped data key")?;
        let mut wrong = crate::RamfluxClient::new();
        wrong.open_account_index(&participant.root)?;
        assert!(
            wrong.unlock_account(&participant.account_id, b"wrong-original-password").is_err(),
            "test: refreshed native authority bypassed the original data password"
        );
        drop(wrong);
        let mut frontend = crate::RamfluxClient::new();
        frontend.open_account_index(&participant.root)?;
        frontend.unlock_account(&participant.account_id, password).map_err(|error| {
            format!("test: {} original password reopen: {error}", participant.account_id)
        })?;
        assert!(
            ordinary_session_admitted(&frontend, &participant.account_id)?,
            "test: refresh/reopen lost the exact installed-generation admission receipt"
        );
        let vault = super::super::super::recipient::tests::DiskVault::open(
            participant.root.join(directory),
        )?;
        let current = custody::load_account(&participant.root, &participant.account_id, rig.now)?;
        require_role_after_reopen(&current, &vault, authority, &branch_ref, &primary_ref, rig.now)
            .map_err(|error| format!("test: {} reopened role: {error}", participant.account_id))?;
        require_stale_head_refused(&frontend, participant, &vault, &current, old, rig.now)
            .map_err(|error| {
                format!("test: {} stale head refusal: {error}", participant.account_id)
            })?;
        let after =
            frontend.account_index()?.account_generation_selection(&participant.account_id)?;
        assert_eq!(
            before.account, after.account,
            "test: native refresh/reopen replaced the account's selected full data paths"
        );
        assert_eq!(
            before.manifest_json, after.manifest_json,
            "test: native refresh/reopen rewrote its selected full data manifest"
        );
        assert_eq!(
            frontend
                .account_index()?
                .load_wrapped_db_key(&participant.account_id)?
                .ok_or("test: retained data wrapping")?
                .key_wrapping_ref,
            wrapped.key_wrapping_ref,
            "test: native refresh/reopen substituted this device's original data wrapping owner"
        );
    }
    Ok(())
}

fn require_stale_head_refused(
    frontend: &crate::RamfluxClient,
    participant: &LocalPairingParticipant,
    vault: &dyn crate::custody::PrimaryVault,
    current: &custody::BornAccount,
    old: &custody::BornAccount,
    now: u64,
) -> TestResult {
    let before = crate::custody::pairing::install_store::list_pending(
        &participant.root,
        &participant.account_id,
    )?;
    let stale = CustodyAuthority { publication: old.publication(), custodian_publication: None };
    assert!(
        crate::custody::pairing::refresh_authority(
            &participant.root,
            frontend.account_db()?,
            vault,
            &participant.account_id,
            &stale,
            now
        )
        .is_err(),
        "test: reopened authority pins accepted the old pre-refresh native head"
    );
    assert_eq!(
        crate::custody::pairing::install_store::list_pending(
            &participant.root,
            &participant.account_id
        )?,
        before,
        "test: stale-node refusal created an installation fence for the current device"
    );
    assert!(
        crate::custody::pairing::ordinary_session_admitted(frontend, &participant.account_id)?,
        "test: stale-node refusal removed current ordinary admission"
    );
    let retained = custody::load_account(&participant.root, &participant.account_id, now)?;
    assert_eq!(
        retained.record(),
        current.record(),
        "test: rejected stale refresh still rewrote native authority"
    );
    assert_eq!(
        retained.branch_vault_ref(),
        current.branch_vault_ref(),
        "test: rejected stale refresh still rewrote the local branch owner"
    );
    assert_eq!(
        retained.primary_vault_ref(),
        current.primary_vault_ref(),
        "test: rejected stale refresh still rewrote the local management role"
    );
    Ok(())
}

fn require_role_after_reopen(
    current: &custody::BornAccount,
    vault: &dyn crate::custody::PrimaryVault,
    authority: &CustodyAuthority,
    expected_branch: &str,
    expected_primary: &str,
    now: u64,
) -> TestResult {
    assert_eq!(
        current.record(),
        &authority.publication.record,
        "test: refresh/reopen changed independently observed native authority"
    );
    assert_eq!(
        current.branch_vault_ref(),
        expected_branch,
        "test: refresh/reopen changed this device's original branch vault reference"
    );
    assert_eq!(
        current.primary_vault_ref(),
        expected_primary,
        "test: refresh/reopen changed the installed primary/secondary role reference"
    );
    drop(current.credentials(vault, current.local_device_id()?, now)?);
    if expected_primary.is_empty() {
        assert!(
            matches!(
                current.group_primary(vault),
                Err(crate::SdkError::PairingCode("PrimaryRequired"))
            ),
            "test: demoted source regained management authority after reopen"
        );
    } else {
        let key = current.group_primary(vault)?;
        assert_eq!(
            key.public_key(),
            authority.publication.record.body.master_certificate.body.self_signing_public_key,
            "test: recipient reopened another management key"
        );
        drop(key);
    }
    Ok(())
}

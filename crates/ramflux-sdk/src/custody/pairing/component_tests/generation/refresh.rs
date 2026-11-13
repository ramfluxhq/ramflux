// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary native profile refresh keeps an already installed full data generation.
use super::{
    ClockHold, CustodyAuthority, Rig, TestResult, admits_exact_g3, bootstrap_full_rig,
    canonical_json_bytes, custody, finish_owned_stream, install_live_generation, publication,
};
use crate::custody::pairing::{
    LocalPairingParticipant, PairingAuthorityQuery, publication::NodeHeadPersist,
};

#[tokio::test(start_paused = true)]
async fn pairing_full_profile_refresh_preserves_selected_generation_and_source_secondary()
-> TestResult {
    let hold = ClockHold::new();
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    rig.primary.sync_relay().await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let published = Box::pin(publication(&mut rig, &operation)).await?;
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
    refresh_participant(&rig.participant_b, &observed, rig.now)
        .map_err(|e| format!("B full refresh: {e}"))?;
    rig.participant_a.take_client(&mut rig.source.client)?;
    refresh_participant(&rig.participant_a, &observed, rig.now)
        .map_err(|e| format!("A secondary refresh: {e}"))?;
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
    hold.finish().await?;
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

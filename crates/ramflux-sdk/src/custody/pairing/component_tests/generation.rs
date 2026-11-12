// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native publication + SDK G1/G2/G3. Frontend/private-input/tail acceptance is separate.
use super::{
    ClockHold, Rig, TestResult, bootstrap_full_rig, finish_owned_stream,
    ordinary_session_admitted_for_participant,
};
use crate::custody::{
    self,
    pairing::{
        Install, Installation, NodeHeadPersist, full_generation::owner::FullGenerationPreparation,
    },
};
use ramflux_crypto::custody::{
    CooperativeTransferInput, MasterKey, RecoveryPhrase, SelfSigningKey,
    cooperative_transfer_preserving_devices,
};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{CustodyAuthority, Publication, object_hash},
    encode_base64url,
};
use ramflux_storage::{FullPinnedReceiverBase, HeadRow};

struct Published {
    authority: CustodyAuthority,
    install: Install,
    head: HeadRow,
}
#[tokio::test(start_paused = true)]
async fn pairing_full_generation_installer_requires_real_j6_keys_and_all_owner_g3() -> TestResult {
    let hold = ClockHold::new();
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    rig.primary.sync_relay().await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let published = publication(&rig, &operation)?;
    refuses_before_j6_or_with_wrong_primary(&rig, &published, false)?;
    let pinned = pin_published_target(&rig, &published)?;
    refuses_before_j6_or_with_wrong_primary(&rig, &published, true)?;
    let mut copy = pinned.copy()?; // No ordinary DB/stage loan crosses bulk G1 work.
    let preparation = {
        let slot = rig.participant_b.db.lock().map_err(|_| "B original owner")?;
        let db = slot.as_ref().ok_or("B writer")?;
        let stage = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        copy.project_retained_chain(&stage, rig.now)?;
        FullGenerationPreparation::pin(
            &Installation {
                root: &rig.participant_b.root,
                db,
                vault: rig.participant_b.vault.as_ref(),
                now: rig.now,
            },
            &stage,
            copy,
            published.install,
            &published.authority,
        )?
    };
    let prepared = preparation.prepare()?;
    let install = prepared.install().clone();
    let committed = {
        let slot = rig.participant_b.db.lock().map_err(|_| "B original owner")?;
        let db = slot.as_ref().ok_or("B writer")?;
        let stage = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        prepared.select(
            &Installation {
                root: &rig.participant_b.root,
                db,
                vault: rig.participant_b.vault.as_ref(),
                now: rig.now,
            },
            &stage,
            &published.authority,
        )?
    };
    let selected = finish_installed(&rig, committed, &install, &published.authority)?;
    let old = rig.participant_b.db.lock().map_err(|_| "B handback")?.replace(selected);
    drop(old);
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    hold.finish().await?;
    Ok(())
}
fn publication(rig: &Rig, operation: &str) -> Result<Published, Box<dyn std::error::Error>> {
    let (record, live) = {
        let slot = rig.participant_b.db.lock().map_err(|_| "B proposal owner")?;
        let db = slot.as_ref().ok_or("B proposal writer")?;
        let stage = db.open_full_transfer_stage(
            operation,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        (
            stage.resume_record()?,
            db.pairing_live_rows()?
                .into_iter()
                .find(|row| row.operation_id == operation)
                .ok_or("B live")?,
        )
    };
    let authority =
        rig.participant_b.query.current_authority(&record.grant.destination_ref.account_anchor)?;
    let current = ramflux_crypto::custody::verify_publication(&authority, rig.now)?;
    let branch_ref = live.branch_vault_ref.clone().ok_or("own B branch")?;
    let (publication, primary_ref) = candidate(rig, &record, &current, &branch_ref)?;
    let hash = object_hash(&publication.record)?;
    let head = HeadRow {
        account_id: rig.participant_b.account_id.clone(),
        operation_id: operation.into(),
        invitation_id: Some(live.invitation_id),
        generation: live.generation,
        kind: "transfer".into(),
        base_record_hash: record.base_record_hash,
        base_epoch: current.envelope().body.device_set_epoch,
        publisher_ref: canonical_json_bytes(&record.grant.source_ref)?,
        candidate: canonical_json_bytes(&publication)?,
        candidate_hash: hash.clone(),
        state: "prepared".into(),
        ack: None,
        recipient_ref: Some(canonical_json_bytes(&record.grant.destination_ref)?),
        revoked_ref: None,
        created_at: rig.now,
    };
    prepare_head(rig, &head)?;
    // Actual native core persistence happens after releasing the original B loan.
    assert_eq!(rig.node.persist_head(&publication, rig.now)?, hash);
    let authority =
        rig.participant_b.query.current_authority(&record.grant.destination_ref.account_anchor)?;
    let install = Install {
        schema: "ramflux.pairing.Install.v2".into(),
        version: 2,
        account_id: rig.participant_b.account_id.clone(),
        account_anchor: record.grant.destination_ref.account_anchor.clone(),
        operation_id: operation.into(),
        recipient_ref: record.grant.destination_ref,
        recipient_mode: "new".into(),
        install_purpose: "transfer_destination".into(),
        record_hash: Some(hash),
        prior_record_hash: None,
        branch_vault_ref: branch_ref,
        data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(
            &rig.participant_b.account_id,
        ),
        primary_vault_ref: Some(primary_ref),
        state: "vault_durable".into(),
        cleanup_ref: None,
        cleanup_owner_ref: None,
        full_transfer: None,
    };
    Ok(Published { authority, install, head })
}
fn prepare_head(rig: &Rig, head: &HeadRow) -> TestResult {
    let slot = rig.participant_b.db.lock().map_err(|_| "B candidate owner")?;
    let db = slot.as_ref().ok_or("B candidate writer")?;
    let mut live = db
        .pairing_live_rows()?
        .into_iter()
        .find(|row| row.operation_id == head.operation_id)
        .ok_or("candidate live")?;
    live.phase = "proposal_pending".into();
    live.proposal_hash = Some(head.candidate_hash.clone());
    db.put_pairing_live(&live)?;
    db.commit_pairing_head(head)?;
    Ok(())
}
fn pin_published_target(
    rig: &Rig,
    published: &Published,
) -> Result<FullPinnedReceiverBase, Box<dyn std::error::Error>> {
    let slot = rig.participant_b.db.lock().map_err(|_| "B published owner")?;
    let db = slot.as_ref().ok_or("B published writer")?;
    let mut head = published.head.clone();
    head.state = "acknowledged".into();
    head.ack = Some(canonical_json_bytes(
        &serde_json::json!({"record_hash":head.candidate_hash,"device_set_epoch":published.authority.publication.record.body.device_set_epoch}),
    )?);
    db.commit_pairing_head(&head)?;
    let stage = db.open_full_transfer_stage(
        &published.install.operation_id,
        ramflux_crypto::custody::pairing::PairingRole::Responder,
        rig.now,
    )?;
    Ok(stage.pin_receiver_base(&stage.resume_record()?.base_manifest_hash)?)
}

fn refuses_before_j6_or_with_wrong_primary(
    rig: &Rig,
    published: &Published,
    wrong_primary: bool,
) -> TestResult {
    let pinned = {
        let slot = rig.participant_b.db.lock().map_err(|_| "B negative owner")?;
        let db = slot.as_ref().ok_or("B negative writer")?;
        let stage = db.open_full_transfer_stage(
            &published.install.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        stage.pin_receiver_base(&stage.resume_record()?.base_manifest_hash)?
    };
    let mut copy = pinned.copy()?;
    let slot = rig.participant_b.db.lock().map_err(|_| "B negative owner")?;
    let db = slot.as_ref().ok_or("B negative writer")?;
    let stage = db.open_full_transfer_stage(
        &published.install.operation_id,
        ramflux_crypto::custody::pairing::PairingRole::Responder,
        rig.now,
    )?;
    copy.project_retained_chain(&stage, rig.now)?;
    let mut install = published.install.clone();
    if wrong_primary {
        let reference = encode_base64url(ramflux_crypto::random_32()?);
        rig.participant_b.vault.store_new(&reference, &SelfSigningKey::generate()?)?;
        install.primary_vault_ref = Some(reference);
    }
    let before = ramflux_storage::AccountIndex::open(&rig.participant_b.root)?
        .account(&rig.participant_b.account_id)?;
    let result = FullGenerationPreparation::pin(
        &Installation {
            root: &rig.participant_b.root,
            db,
            vault: rig.participant_b.vault.as_ref(),
            now: rig.now,
        },
        &stage,
        copy,
        install,
        &published.authority,
    );
    assert!(result.is_err(), "G1 accepted missing local J6 or foreign B primary");
    assert_eq!(
        ramflux_storage::AccountIndex::open(&rig.participant_b.root)?
            .account(&rig.participant_b.account_id)?,
        before,
        "refused G1 changed selected B"
    );
    Ok(())
}

fn candidate(
    rig: &Rig,
    record: &ramflux_crypto::custody::pairing::FullResumeRecord,
    current: &ramflux_crypto::custody::VerifiedRecord,
    branch_ref: &str,
) -> Result<(Publication, String), Box<dyn std::error::Error>> {
    let phrase = RecoveryPhrase::parse(rig.source.phrase.as_ref().ok_or("fixture local phrase")?)?;
    let master = MasterKey::from_phrase(&phrase)?;
    let primary = SelfSigningKey::generate()?;
    let primary_ref = encode_base64url(ramflux_crypto::random_32()?);
    rig.participant_b.vault.store_new(&primary_ref, &primary)?;
    let branch = rig.participant_b.vault.load_branch(
        branch_ref,
        &current.envelope().body.principal_id,
        &record.grant.destination_ref,
    )?;
    let mut certificate = current
        .envelope()
        .body
        .devices
        .first()
        .and_then(|device| device.branch_certificate.as_ref())
        .ok_or("branch template")?
        .body
        .clone();
    certificate.device_id = record.grant.destination_ref.device_id.clone();
    certificate.device_epoch = record.grant.destination_ref.device_epoch;
    certificate.branch_signing_public_key =
        encode_base64url(branch.signing.signing_key.verifying_key().to_bytes());
    certificate.agreement_identity_public_key = encode_base64url(branch.agreement.public);
    certificate.cert_id = encode_base64url(ramflux_crypto::random_32()?);
    let candidate = cooperative_transfer_preserving_devices(
        &master,
        &primary,
        current,
        CooperativeTransferInput {
            destination: record.grant.destination_ref.clone(),
            fresh_destination: Some(certificate),
            highest_observed_range: 0,
            issued_at: rig.now,
            master_cert_id: encode_base64url(ramflux_crypto::random_32()?),
        },
    )?;
    let publication = Publication { record: candidate, compacted_ids: None };
    Ok((publication, primary_ref))
}

fn finish_installed(
    rig: &Rig,
    committed: super::super::full_generation::owner::FullGenerationCommitted,
    install: &Install,
    authority: &CustodyAuthority,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    assert!(
        !ordinary_session_admitted_for_participant(&rig.participant_b)?,
        "G2 opened admission before G3"
    );
    let selected = committed.open_selected()?;
    committed.finish(
        &Installation {
            root: &rig.participant_b.root,
            db: &selected,
            vault: rig.participant_b.vault.as_ref(),
            now: rig.now,
        },
        authority,
    )?;
    let installed = super::super::install_store::read_installed(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
    )?
    .ok_or("G3 installed")?;
    assert_eq!(installed.full_transfer, install.full_transfer);
    assert_eq!(installed.record_hash, install.record_hash);
    let pending_count = super::super::install_store::list_pending(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
    )?
    .len();
    assert_eq!(pending_count, 0, "G3 retained its pending install file");
    let adoption = selected.pairing_adoption()?.ok_or("selected adoption")?;
    super::super::full_generation::require_selected_full_generation(
        &rig.participant_b.root,
        &installed,
        &adoption,
    )?;
    let account = custody::load_data_account(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
        rig.now,
    )?;
    assert!(custody::matches_generation_install(&account, &installed)?);
    let stage = selected.open_full_transfer_stage(
        &installed.operation_id,
        ramflux_crypto::custody::pairing::PairingRole::Responder,
        rig.now,
    )?;
    let retained = stage.verify_retained_receiver_application(rig.now)?;
    let full = installed.full_transfer.as_ref().ok_or("full G3")?;
    assert_eq!(encode_base64url(retained.generation_nonce), full.generation_nonce);
    assert_eq!(encode_base64url(retained.chunks_root), full.initial_union_root);
    drop(stage);
    admits_exact_g3(rig, &selected, &installed)?;
    assert_eq!(
        account.record().body.master_certificate.body.primary_device_ref,
        installed.recipient_ref
    );
    Ok(selected)
}

fn admits_exact_g3(rig: &Rig, db: &ramflux_storage::AccountDb, installed: &Install) -> TestResult {
    let account = custody::load_account(&rig.participant_b.root, &installed.account_id, rig.now)?;
    let config = custody::CustodyNetworkConfig {
        pairing_admission: Some(std::sync::Arc::new(db.pairing_admission_reader())),
        account_root: rig.participant_b.root.clone(),
        account_id: installed.account_id.clone(),
        device_id: account.local_device_id()?.into(),
        gateway_address: "127.0.0.1:1".parse()?,
        server_name: "localhost".into(),
        ca_certificate: rig.participant_b.root.join("unused.pem"),
        node_id: "fixture".into(),
        node_public_key: encode_base64url([1; 32]),
        audience: "fixture".into(),
        binding_mode: ramflux_protocol::custody::BindingMode::DirectExporter,
        allow_no_channel_binding: false,
        timeout: std::time::Duration::from_secs(5),
    };
    let check = || {
        super::super::admission::require_network_admission(
            &config,
            &account,
            rig.participant_b.vault.as_ref(),
            rig.now,
        )
    };
    check()?;
    let adoption = db.pairing_adoption()?.ok_or("G3 adoption")?;
    let mut corrupt = adoption.clone();
    corrupt.full_generation_nonce = Some(encode_base64url([241; 32]));
    assert!(db.put_pairing_adoption(&corrupt).is_err(), "immutable G3 generation nonce changed");
    corrupt = adoption.clone();
    corrupt.data_vault_ref = "foreign-data-owner".into();
    db.put_pairing_adoption(&corrupt)?;
    assert!(check().is_err(), "ordinary network accepted wrong actual DB owner");
    db.put_pairing_adoption(&adoption)?;
    super::super::install_store::write_pending(&rig.participant_b.root, installed)?;
    assert!(check().is_err(), "ordinary network accepted pending G3");
    super::super::install_store::remove_pending(
        &rig.participant_b.root,
        &installed.account_id,
        &installed.operation_id,
    )?;
    check()?;
    Ok(())
}

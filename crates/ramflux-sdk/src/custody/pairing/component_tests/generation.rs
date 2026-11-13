// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native publication + SDK G1/G2/G3. Frontend/private-input/tail acceptance is separate.
use super::{
    ClockHold, Rig, TestResult, bootstrap_full_rig, finish_owned_stream,
    ordinary_session_admitted_for_participant,
};
use crate::custody::{
    self,
    pairing::{Install, Installation, full_generation::owner::FullGenerationPreparation},
};
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::{canonical_json_bytes, custody::CustodyAuthority, encode_base64url};
use ramflux_storage::{FullPinnedReceiverBase, HeadRow};
mod recipient_cancel;
mod source_cancel;
mod source_tail;

struct Prepared {
    publication: ramflux_protocol::custody::Publication,
    install: Install,
    head: HeadRow,
    source_submission: crate::custody::pairing::FullSourceSubmission,
}

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
    let published = Box::pin(publication(&mut rig, &operation)).await?;
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
async fn prepare_candidate(
    rig: &mut Rig,
    operation: &str,
) -> Result<Prepared, Box<dyn std::error::Error>> {
    let request = {
        let slot = rig.participant_b.db.lock().map_err(|_| "B prepare owner")?;
        let db = slot.as_ref().ok_or("B prepare writer")?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or("B prepare live")?;
        let stage = db.open_full_transfer_stage(
            operation,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        ramflux_protocol::custody::pairing::local_dto::Prepare {
            schema: "ramflux.pairing.Prepare.v2".into(),
            version: 2,
            operation_id: operation.into(),
            generation: live.generation,
            transcript_hash: encode_base64url(stage.resume_record()?.th),
        }
    };
    let reservation = super::super::local_credential::load_reservation(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
    )?
    .ok_or("B prepare reservation")?;
    assert!(
        rig.participant_a
            .prepare_full_transfer_candidate(&request, reservation.frontend_generation)
            .is_err(),
        "A accepted B phrase preparation"
    );
    let mut wrong = request.clone();
    wrong.generation += 1;
    assert!(
        rig.participant_b
            .prepare_full_transfer_candidate(&wrong, reservation.frontend_generation)
            .is_err(),
        "stale frontend accepted phrase preparation"
    );
    // B must supply fresh attended phrase approval; data resume need not retain
    // the original local confirmation flags. This is not a process-restart fixture.
    rig.secondary.replace_full_confirmations_for_test((false, false))?;
    let prepared = rig.secondary.prepare_full_transfer(&request).await?;
    assert!(
        matches!(prepared.outcome,ramflux_protocol::custody::pairing::local_dto::Outcome::FullStatus {value} if value.stage==ramflux_protocol::custody::pairing::local_dto::FullStatusStage::Candidate)
    );
    let (publication, install) = rig.secondary.full_prepared_candidate_for_test()?;
    let head = rig
        .participant_b
        .db
        .lock()
        .map_err(|_| "B prepared owner")?
        .as_ref()
        .ok_or("B prepared writer")?
        .pairing_head()?
        .ok_or("B durable prepared head")?;
    assert_eq!(head.candidate, canonical_json_bytes(&publication)?);
    assert_eq!(head.state, "prepared");
    prove_source_preservation(rig, &publication, &install).await?;
    rig.participant_a.take_client(&mut rig.source.client)?;
    let source_submission = rig.primary.prepare_full_source_submission(publication.clone()).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    // Actual SDK submission owns only public bytes/ports and weak writer liveness.
    assert!(rig.participant_a.db.lock().map_err(|_| "off-loan source")?.is_none());
    Ok(Prepared { publication, install, head, source_submission })
}
async fn publication(
    rig: &mut Rig,
    operation: &str,
) -> Result<Published, Box<dyn std::error::Error>> {
    let Prepared { publication: _, install, head, source_submission } =
        prepare_candidate(rig, operation).await?;
    let before = rig.node.persist_calls.load(std::sync::atomic::Ordering::Acquire);
    rig.node.lose_next_reply.store(true, std::sync::atomic::Ordering::Release);
    assert!(source_submission.submit().is_err(), "lost native response became a local J6");
    rig.participant_a.take_client(&mut rig.source.client)?;
    assert_eq!(
        rig.participant_a
            .db
            .lock()
            .map_err(|_| "uncertain source")?
            .as_ref()
            .ok_or("source writer")?
            .pairing_head()?
            .ok_or("submitted intent")?
            .state,
        "submitted"
    );
    rig.participant_a.return_client(&mut rig.source.client)?;
    let published = source_submission.submit()?;
    assert_eq!(
        rig.node.persist_calls.load(std::sync::atomic::Ordering::Acquire),
        before + 1,
        "exact native observation retried persistence after response loss"
    );
    let authority = rig.participant_b.query.current_authority(&install.account_anchor)?;
    assert_eq!(canonical_json_bytes(published.authority())?, canonical_json_bytes(&authority)?);
    source_tail::acknowledge(rig, published)?;
    Ok(Published { authority, install, head })
}
async fn prove_source_preservation(
    rig: &mut Rig,
    publication: &ramflux_protocol::custody::Publication,
    install: &Install,
) -> TestResult {
    rig.participant_a.take_client(&mut rig.source.client)?;
    let original = rig.primary.replace_full_confirmations_for_test((false, false))?;
    let refused = rig.primary.preserve_full_candidate(publication.clone()).await.is_err();
    rig.primary.replace_full_confirmations_for_test(original)?;
    assert!(refused, "data metadata restored A preservation approval without local confirmation");
    assert!(
        rig.secondary.preserve_full_candidate(publication.clone()).await.is_err(),
        "B accessed original A preservation signer"
    );
    let primary = rig
        .participant_b
        .vault
        .load_primary(install.primary_vault_ref.as_deref().ok_or("B primary ref")?)?;
    let mut removed = publication.clone();
    let old = rig.participant_a.query.current_authority(&install.account_anchor)?;
    let old_primary = &old.publication.record.body.master_certificate.body.primary_device_ref;
    let mut body = removed.record.body.clone();
    body.devices.retain(|device| device.device_id != old_primary.device_id);
    removed.record = primary.sign_record(body)?;
    assert!(
        rig.primary.preserve_full_candidate(removed).await.is_err(),
        "A approved a validly signed candidate that removed its branch"
    );
    let foreign = foreign_destination_branch(publication, &primary)?;
    assert!(
        rig.primary.preserve_full_candidate(foreign).await.is_err(),
        "A approved a candidate with a substituted SAS-bound B key"
    );
    let signed = rig.primary.preserve_full_candidate(publication.clone()).await?;
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::custody::signing_bytes(&signed.body.schema, &signed.body)?,
        &signed.signature,
        &old.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    assert_eq!(
        signed.body.new_record_hash,
        ramflux_protocol::custody::object_hash(&publication.record)?
    );
    assert!(
        rig.primary.preserve_full_candidate(publication.clone()).await? == signed,
        "identical preservation was not durably idempotent"
    );
    rig.participant_a.return_client(&mut rig.source.client)?;
    Ok(())
}

fn foreign_destination_branch(
    publication: &ramflux_protocol::custody::Publication,
    primary: &SelfSigningKey,
) -> Result<ramflux_protocol::custody::Publication, Box<dyn std::error::Error>> {
    let mut foreign = publication.clone();
    let mut body = foreign.record.body.clone();
    let reference = body.master_certificate.body.primary_device_ref.clone();
    let device = body
        .devices
        .iter_mut()
        .find(|device| device.device_id == reference.device_id)
        .ok_or("B candidate device")?;
    let mut branch = device.branch_certificate.as_ref().ok_or("B candidate branch")?.body.clone();
    branch.branch_signing_public_key = SelfSigningKey::generate()?.public_key();
    let (signing, agreement) = ramflux_crypto::device_key_commitments(
        &branch.branch_signing_public_key,
        &branch.agreement_identity_public_key,
    )?;
    device.branch_certificate = Some(primary.certify_branch(branch)?);
    device.signing_key_commitment = signing;
    device.agreement_key_commitment = agreement;
    foreign.record = primary.sign_record(body)?;
    ramflux_crypto::custody::verify_publication(
        &CustodyAuthority { publication: foreign.clone(), custodian_publication: None },
        crate::custody::network_now()?,
    )?;
    Ok(foreign)
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
    assert!(selected.pairing_head()?.is_none(), "G3 retained the primary head-writer fence");
    assert!(
        selected
            .pairing_live_rows()?
            .into_iter()
            .any(|row| row.operation_id == installed.operation_id
                && row.full_stage_reference().is_ok_and(|reference| reference.is_some())),
        "G3 discarded the tail/reconciliation reference"
    );
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

struct FullPhraseFixture {
    phrase: Option<zeroize::Zeroizing<String>>,
    setup: super::super::recipient::tests::Phrase,
}
pub(super) fn phrase_provider(
    phrase: Option<&str>,
) -> std::sync::Arc<dyn super::super::LocalCredentialProvider> {
    std::sync::Arc::new(FullPhraseFixture {
        phrase: phrase.map(|value| zeroize::Zeroizing::new(value.into())),
        setup: super::super::recipient::tests::Phrase::setup(b"component-recipient-passphrase"),
    })
}
impl super::super::LocalCredentialProvider for FullPhraseFixture {
    fn provide(
        &self,
        request: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<super::super::CredentialOutcome, crate::SdkError> {
        if request.action != "phrase" {
            return self.setup.provide(request);
        }
        let phrase = self.phrase.as_ref().ok_or(crate::SdkError::PairingCode("WrongContext"))?;
        Ok(super::super::CredentialOutcome::Provided {
            passphrase: super::super::SecretUtf8::from_bytes(phrase.as_bytes())?,
            confirmation: None,
        })
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real B cancellation/restart retains the sole published primary and finishes exact G1/G2/G3.
use super::{
    ClockHold, FullGenerationPreparation, Install, Installation, Rig, TestResult,
    bootstrap_full_rig, finish_owned_stream, ordinary_session_admitted_for_participant,
    prepare_candidate,
};
use crate::custody::pairing::{LocalPairingParticipant, recipient::ordinary_session_admitted};
use ramflux_protocol::custody::{object_hash, pairing::local_dto::Cancel};
use std::sync::{Arc, Mutex};
#[tokio::test(start_paused = true)]
async fn pairing_cancel_after_candidate_release_preserves_possible_publication() -> TestResult {
    let hold = ClockHold::new();
    for published_before_cancel in [true, false] {
        Box::pin(cancel_and_restart(published_before_cancel)).await?;
    }
    hold.finish().await?;
    Ok(())
}
async fn cancel_and_restart(published_before_cancel: bool) -> TestResult {
    let (mut rig, operation, _) =
        Box::pin(bootstrap_full_rig()).await.map_err(|e| format!("B bootstrap: {e}"))?;
    rig.primary.sync_relay().await.map_err(|e| format!("B initial relay: {e}"))?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await.map_err(|e| format!("B durable stream: {e}"))?;
    let prepared =
        prepare_candidate(&mut rig, &operation).await.map_err(|e| format!("B prepare: {e}"))?;
    if published_before_cancel {
        prepared.source_submission.submit().map_err(|e| format!("A native publication: {e}"))?;
    }
    if published_before_cancel {
        rig.secondary
            .cancel(&Cancel {
                schema: "ramflux.pairing.Cancel.v2".into(),
                version: 2,
                operation_id: operation.clone(),
                generation: prepared.head.generation,
            })
            .await
            .map_err(|e| format!("B cancel: {e}"))?;
    } else {
        rig.secondary.background().await.map_err(|e| format!("B expire: {e}"))?;
        // No native evidence yet. The released candidate must remain restrictive,
        // and neither a stale base nor local pre-submit phase permits key deletion.
        let query = rig
            .participant_b
            .full_recipient_publication_query(&operation)
            .map_err(|e| format!("B retained query scope: {e}"))?;
        let mut frontend = crate::RamfluxClient::new();
        rig.participant_b.return_data_client(&mut frontend)?;
        let observation = query.observe()?;
        rig.participant_b.take_client(&mut frontend)?;
        {
            let slot = rig.participant_b.db.lock().map_err(|_| "B pending owner")?;
            let db = slot.as_ref().ok_or("B pending writer")?;
            assert!(matches!(
                observation.acknowledge(db),
                Err(crate::SdkError::PairingCode("PublicationPending"))
            ));
            assert_eq!(db.pairing_head()?.ok_or("B pending candidate")?, prepared.head);
        }
        assert!(!ordinary_session_admitted_for_participant(&rig.participant_b)?);
        prepared.source_submission.submit().map_err(|e| format!("A native publication: {e}"))?;
    }
    let reference = prepared.install.primary_vault_ref.as_deref().ok_or("B sole primary ref")?;
    let primary = rig
        .participant_b
        .vault
        .load_primary(reference)
        .map_err(|error| format!("B possible-publication primary key was lost: {error}"))?;
    assert_eq!(
        primary.public_key(),
        prepared.publication.record.body.master_certificate.body.self_signing_public_key
    );
    drop(primary);
    rig.secondary.lock().await.map_err(|e| format!("B close writer: {e}"))?; // Actual B data owner/keys/jobs close before process-equivalent reopen.
    assert!(rig.participant_b.db.lock().map_err(|_| "B closed")?.is_none());
    let mut frontend = crate::RamfluxClient::new();
    frontend
        .open_account_index(&rig.participant_b.root)
        .map_err(|e| format!("B reopen index: {e}"))?;
    frontend
        .unlock_account(&rig.participant_b.account_id, b"component-recipient-passphrase")
        .map_err(|e| format!("B reopen data credential: {e}"))?;
    let previous = &rig.participant_b;
    let reopened = Arc::new(LocalPairingParticipant {
        root: previous.root.clone(),
        account_id: previous.account_id.clone(),
        vault: Arc::new(super::super::super::recipient::tests::DiskVault::open(
            previous.root.join("branch-vault"),
        )?),
        provider: Arc::new(NoApproval),
        db: Mutex::new(None),
        persist: previous.persist.clone(),
        query: previous.query.clone(),
    });
    reopened.take_client(&mut frontend)?;
    rig.participant_b = reopened;
    let query = rig
        .participant_b
        .full_recipient_publication_query(&operation)
        .map_err(|e| format!("B retained query scope: {e}"))?;
    rig.participant_b.return_data_client(&mut frontend)?;
    let observation = query.observe()?;
    assert_eq!(
        object_hash(&observation.authority().publication.record)?,
        prepared.head.candidate_hash
    );
    install_reconciled(&mut rig, &operation, &mut frontend, prepared, &observation)
        .map_err(|e| format!("B exact installation: {e}"))?;
    rig.primary.lock().await?;
    Ok(())
}
fn install_reconciled(
    rig: &mut Rig,
    operation: &str,
    frontend: &mut crate::RamfluxClient,
    prepared: super::Prepared,
    observation: &crate::custody::pairing::FullRecipientNativeObservation,
) -> TestResult {
    let authority = observation.authority().clone();
    let current = ramflux_crypto::custody::verify_publication(&authority, rig.now)?;
    rig.participant_b.take_client(frontend)?;
    let pinned = {
        let slot = rig.participant_b.db.lock().map_err(|_| "B reconciled writer")?;
        let db = slot.as_ref().ok_or("B reconciled DB")?;
        observation.acknowledge(db)?;
        assert!(
            db.open_full_transfer_stage(
                operation,
                ramflux_crypto::custody::pairing::PairingRole::Responder,
                rig.now
            )
            .is_err(),
            "native reconciliation revived cancelled data state"
        );
        db.open_full_recipient_install_stage(operation, &current, rig.now)?.pin_receiver_base()?
    };
    rig.participant_b.return_data_client(frontend)?;
    let mut copy = pinned.copy()?;
    rig.participant_b.take_client(frontend)?;
    let preparation = {
        let slot = rig.participant_b.db.lock().map_err(|_| "B reconciled replay")?;
        let db = slot.as_ref().ok_or("B replay writer")?;
        let stage = db.open_full_recipient_install_stage(operation, &current, rig.now)?;
        stage.project(&mut copy)?;
        FullGenerationPreparation::pin_reconciliation(
            &Installation {
                root: &rig.participant_b.root,
                db,
                vault: rig.participant_b.vault.as_ref(),
                now: rig.now,
            },
            &stage,
            copy,
            prepared.install,
            &authority,
        )?
    };
    rig.participant_b.return_data_client(frontend)?;
    let generation = preparation.prepare()?;
    let install = generation.install().clone();
    rig.participant_b.take_client(frontend)?;
    let committed = {
        let slot = rig.participant_b.db.lock().map_err(|_| "B reconciled select")?;
        let db = slot.as_ref().ok_or("B select writer")?;
        let stage = db.open_full_recipient_install_stage(operation, &current, rig.now)?;
        generation.select_reconciliation(
            &Installation {
                root: &rig.participant_b.root,
                db,
                vault: rig.participant_b.vault.as_ref(),
                now: rig.now,
            },
            &stage,
            &authority,
        )?
    };
    let selected = committed.open_selected()?;
    committed.finish(
        &Installation {
            root: &rig.participant_b.root,
            db: &selected,
            vault: rig.participant_b.vault.as_ref(),
            now: rig.now,
        },
        &authority,
    )?;
    assert!(
        selected
            .open_full_transfer_stage(
                operation,
                ramflux_crypto::custody::pairing::PairingRole::Responder,
                rig.now
            )
            .is_err(),
        "installed projection erased durable data cancellation"
    );
    let retired = rig.participant_b.db.lock().map_err(|_| "B selected handback")?.replace(selected);
    drop(retired);
    verify_primary_reopen(rig, frontend, &install)?;
    Ok(())
}
fn verify_primary_reopen(
    rig: &mut Rig,
    frontend: &mut crate::RamfluxClient,
    install: &Install,
) -> TestResult {
    rig.participant_b.return_data_client(frontend)?;
    let mut reopened = crate::RamfluxClient::new();
    // Drop the selected writer before reopening through the ordinary authenticated data path.
    *frontend = crate::RamfluxClient::new();
    reopened.open_account_index(&rig.participant_b.root)?;
    reopened.unlock_account(&rig.participant_b.account_id, b"component-recipient-passphrase")?;
    assert!(ordinary_session_admitted(&reopened, &install.account_id)?);
    let account =
        crate::custody::load_account(&rig.participant_b.root, &install.account_id, rig.now)?;
    let key = account.group_primary(rig.participant_b.vault.as_ref())?;
    assert_eq!(
        key.public_key(),
        account.record().body.master_certificate.body.self_signing_public_key
    );
    assert_eq!(
        account.record().body.master_certificate.body.primary_device_ref,
        install.recipient_ref
    );
    drop(key);
    Ok(())
}

struct NoApproval;
impl crate::custody::pairing::LocalCredentialProvider for NoApproval {
    fn provide(
        &self,
        _: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<crate::custody::pairing::CredentialOutcome, crate::SdkError> {
        Err(crate::SdkError::PairingCode("VaultUnavailable"))
    }
}

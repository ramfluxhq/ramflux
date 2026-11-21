// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-side cancellation of an already escaped exact candidate, without claiming B resume.
use super::{ClockHold, TestResult, bootstrap_full_rig, finish_owned_stream, prepare_candidate};
use ramflux_protocol::custody::{object_hash, pairing::local_dto::Cancel};
use std::sync::atomic::Ordering;
#[tokio::test(start_paused = true)]
async fn pairing_full_source_cancel_fences_off_loan_submission_and_retains_uncertain_candidate()
-> TestResult {
    let hold = ClockHold::new();
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    rig.primary.sync_relay().await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let prepared = prepare_candidate(&mut rig, &operation).await?;
    rig.node.lose_next_reply.store(true, Ordering::Release);
    assert!(prepared.source_submission.submit().is_err());
    let count = rig.node.persist_calls.load(Ordering::Acquire);
    rig.participant_a.take_client(&mut rig.source.client)?;
    let before = rig
        .participant_a
        .db
        .lock()
        .map_err(|_| "source before cancel")?
        .as_ref()
        .ok_or("writer")?
        .pairing_head()?
        .ok_or("intent")?;
    assert_eq!(before.state, "submitted");
    rig.primary
        .cancel(&Cancel {
            schema: "ramflux.pairing.Cancel.v2".into(),
            version: 2,
            operation_id: operation.clone(),
            generation: before.generation,
        })
        .await?;
    let after = rig
        .participant_a
        .db
        .lock()
        .map_err(|_| "source after cancel")?
        .as_ref()
        .ok_or("writer")?
        .pairing_head()?
        .ok_or("retained intent")?;
    assert_eq!(before, after, "cancel erased an uncertain native candidate");
    rig.participant_a.return_client(&mut rig.source.client)?;
    assert!(
        prepared.source_submission.submit().is_err(),
        "cancelled ceremony revived an off-loan native submission"
    );
    assert_eq!(
        rig.node.persist_calls.load(Ordering::Acquire),
        count,
        "cancelled source reached native persistence"
    );
    let authority = rig.participant_b.query.current_authority(&prepared.install.account_anchor)?;
    assert_eq!(object_hash(&authority.publication.record)?, before.candidate_hash);
    let key = rig.participant_b.vault.load_primary(
        prepared.install.primary_vault_ref.as_deref().ok_or("B primary reference")?,
    )?;
    assert_eq!(
        key.public_key(),
        prepared.publication.record.body.master_certificate.body.self_signing_public_key,
        "source cancel removed B's possibly published primary"
    );
    drop(key);
    rig.primary.lock().await?;
    cold_source_retirement(&mut rig, &operation)?;
    rig.secondary.lock().await?;
    hold.finish().await?;
    Ok(())
}

fn cold_source_retirement(rig: &mut super::Rig, operation: &str) -> TestResult {
    use crate::custody::pairing::{
        FullSourceRetirementOutcome, Installation, LocalPairingParticipant,
    };
    use std::sync::{Arc, Mutex};
    assert!(rig.participant_a.db.lock().map_err(|_| "closed source")?.is_none());
    let mut frontend = crate::RamfluxClient::new();
    frontend.open_account_index(&rig.participant_a.root)?;
    frontend.unlock_account(&rig.participant_a.account_id, b"fresh-source-data")?;
    let previous = &rig.participant_a;
    let reopened = Arc::new(LocalPairingParticipant {
        root: previous.root.clone(),
        account_id: previous.account_id.clone(),
        vault: Arc::new(super::super::super::recipient::tests::DiskVault::open(
            previous.root.join("source-vault"),
        )?),
        provider: Arc::new(NoApproval),
        db: Mutex::new(None),
        persist: previous.persist.clone(),
        query: previous.query.clone(),
    });
    reopened.take_client(&mut frontend)?;
    let query = reopened.full_source_publication_query(operation)?;
    reopened.return_data_client(&mut frontend)?;
    let observed = query.observe()?; // No original actor, approval or database loan.
    reopened.take_client(&mut frontend)?;
    {
        let slot = reopened.db.lock().map_err(|_| "source exact reconciliation")?;
        let db = slot.as_ref().ok_or("source reconciled writer")?;
        observed.acknowledge(db)?;
        observed.acknowledge(db)?; // Idempotent J6 cannot recut a declined tail.
        assert!(
            db.open_full_transfer_stage(
                operation,
                ramflux_crypto::custody::pairing::PairingRole::Initiator,
                rig.now
            )
            .is_err(),
            "source reconciliation revived cancelled DATA"
        );
        assert_eq!(
            observed.retire_source(&Installation {
                root: &reopened.root,
                db,
                vault: reopened.vault.as_ref(),
                now: rig.now
            })?,
            FullSourceRetirementOutcome::Complete
        );
        assert!(db.pairing_head()?.is_none());
        assert!(
            db.open_full_transfer_stage(
                operation,
                ramflux_crypto::custody::pairing::PairingRole::Initiator,
                rig.now
            )
            .is_err(),
            "source G3 erased its data-terminal barrier"
        );
    }
    reopened.return_client(&mut frontend)?;
    let account = crate::custody::load_account(&reopened.root, &reopened.account_id, rig.now)?;
    assert_eq!(account.primary_vault_ref(), "");
    assert!(matches!(
        account.group_primary(reopened.vault.as_ref()),
        Err(crate::SdkError::PairingCode("PrimaryRequired"))
    ));
    drop(account.credentials(reopened.vault.as_ref(), account.local_device_id()?, rig.now)?);
    assert!(crate::custody::pairing::ordinary_session_admitted(&frontend, &reopened.account_id)?);
    rig.participant_a = reopened;
    rig.source.client = frontend;
    Ok(())
}
struct NoApproval;
impl crate::custody::pairing::LocalCredentialProvider for NoApproval {
    fn provide(
        &self,
        _: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<crate::custody::pairing::CredentialOutcome, crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A source lock on either side of native durability cannot fabricate or roll back authority.
use super::*;
use crate::custody::pairing::{Installation, LocalPairingParticipant};
use std::sync::{Arc, Mutex, atomic::Ordering};

#[tokio::test(start_paused = true)]
async fn cooperative_transfer_publication_crash_and_lock() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        for durable in [false, true] {
            Box::pin(run(durable)).await?;
        }
        Ok(())
    }))
    .await;
    hold.finish().await?;
    result
}
async fn run(durable: bool) -> TestResult {
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    rig.primary.sync_relay().await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let prepared = Box::pin(prepare_candidate(&mut rig, &operation)).await?;
    let before = rig.node.persist_calls.load(Ordering::Acquire);
    let source =
        custody::load_account(&rig.participant_a.root, &rig.participant_a.account_id, rig.now)?;
    let old_primary = source.primary_vault_ref().to_owned();
    if durable {
        rig.node.lose_next_reply.store(true, Ordering::Release);
        assert!(
            prepared.source_submission.submit().is_err(),
            "test: lost native response became a local acknowledgement"
        );
    }
    rig.primary.lock().await?;
    assert!(
        prepared.source_submission.submit().is_err(),
        "test: source lock left the original signer executable"
    );
    reopen_source(&mut rig)?;
    let query = rig.participant_a.full_source_publication_query(&operation)?;
    rig.participant_a.return_data_client(&mut rig.source.client)?;
    let observed = query.observe()?;
    let db = rig.source.client.account_db()?;
    if durable {
        finish_published(&rig, prepared, &operation, &observed, &old_primary)?;
    } else {
        assert!(
            matches!(
                observed.acknowledge(db),
                Err(crate::SdkError::PairingCode("PublicationPending"))
            ),
            "test: prepublication lock fabricated native durability"
        );
        assert!(
            rig.participant_a.vault.load_primary(&old_primary).is_ok(),
            "test: missing positive evidence deleted A's primary key"
        );
        assert!(
            !ordinary_session_admitted_for_participant(&rig.participant_b)?,
            "test: unsubmitted B candidate opened ordinary admission"
        );
        assert_eq!(
            db.pairing_head()?.ok_or("test: submitted intent removed")?.state,
            "submitted",
            "test: cold observation erased uncertainty"
        );
    }
    assert_eq!(
        rig.node.persist_calls.load(Ordering::Acquire),
        before + usize::from(durable),
        "test: cold source recovery retried native publication"
    );
    rig.secondary.lock().await?;
    Ok(())
}
fn finish_published(
    rig: &Rig,
    prepared: Prepared,
    operation: &str,
    observed: &crate::custody::pairing::FullSourceNativeObservation,
    old_primary: &str,
) -> TestResult {
    let db = rig.source.client.account_db()?;
    observed.acknowledge(db)?;
    observed.retire_source(&Installation {
        root: &rig.participant_a.root,
        db,
        vault: rig.participant_a.vault.as_ref(),
        now: rig.now,
    })?;
    assert!(
        rig.participant_a.vault.load_primary(old_primary).is_err(),
        "test: positive cold reconciliation retained old primary capability"
    );
    let authority = rig.node.current_authority(&prepared.install.account_anchor)?;
    assert_eq!(
        ramflux_protocol::custody::object_hash(&authority.publication.record)?,
        prepared.head.candidate_hash,
        "test: cold reconciliation installed a different native candidate"
    );
    install_live_generation(
        rig,
        &operation,
        Published {
            source_cleanup: None,
            authority,
            install: prepared.install,
            head: prepared.head,
        },
    )?;
    assert!(
        ordinary_session_admitted_for_participant(&rig.participant_b)?,
        "test: positively published B could not finish G3 after A locked"
    );
    assert!(
        crate::custody::pairing::ordinary_session_admitted(
            &rig.source.client,
            &rig.participant_a.account_id
        )?,
        "test: native reconciliation revoked the surviving A branch"
    );
    Ok(())
}
fn reopen_source(rig: &mut Rig) -> TestResult {
    rig.source.client = crate::RamfluxClient::new();
    let previous = &rig.participant_a;
    let participant = Arc::new(LocalPairingParticipant {
        root: previous.root.clone(),
        account_id: previous.account_id.clone(),
        vault: Arc::new(crate::custody::pairing::recipient::tests::DiskVault::open(
            previous.root.join("source-vault"),
        )?),
        provider: Arc::new(RefuseApproval),
        db: Mutex::new(None),
        persist: previous.persist.clone(),
        query: previous.query.clone(),
    });
    rig.source.client.open_account_index(&participant.root)?;
    rig.source.client.unlock_account(&participant.account_id, b"fresh-source-data")?;
    participant.take_client(&mut rig.source.client)?;
    rig.participant_a = participant;
    Ok(())
}
struct RefuseApproval;
impl crate::custody::pairing::LocalCredentialProvider for RefuseApproval {
    fn provide(
        &self,
        _: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<crate::custody::pairing::CredentialOutcome, crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
}

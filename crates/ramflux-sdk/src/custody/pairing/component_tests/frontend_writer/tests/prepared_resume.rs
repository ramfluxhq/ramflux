// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Prepared B recovery reuses the immutable candidate after an actual database reopen.
use super::*;
mod reconnect;
use ramflux_protocol::custody::{Publication, object_hash};
struct RefusePhrase(std::sync::atomic::AtomicUsize);
impl crate::custody::pairing::LocalCredentialProvider for RefusePhrase {
    fn provide(
        &self,
        _: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<crate::custody::pairing::CredentialOutcome, SdkError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(SdkError::PairingCode("WrongContext"))
    }
}
#[tokio::test(start_paused = true)]
async fn pairing_full_prepared_b_reopen_reuses_exact_candidate_without_phrase_or_new_key()
-> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let mut rig = Box::pin(Rig::open_profile(true)).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    let mut service = rig.primary.bind_frontend_writer(rig.source.client.account_db()?)?;
    Box::pin(bootstrap(&mut rig, &mut service)).await?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let operation = rig
        .source
        .client
        .account_db()?
        .pairing_live_rows()?
        .into_iter()
        .next()
        .ok_or("test: prepared operation missing")?
        .operation_id;
    Box::pin(deliver_candidate_and_ready(&mut rig, &operation)).await?;
    let head = {
        let slot = rig.participant_b.db.lock().map_err(|_| "test: B writer")?;
        slot.as_ref().ok_or("test: B unlocked")?.pairing_head()?.ok_or("test: B prepared head")?
    };
    let expected: Publication = ramflux_protocol::parse_i_json(&head.candidate)?;
    rig.secondary.lock().await?;
    let mut old = crate::RamfluxClient::new();
    rig.participant_b.return_client(&mut old)?;
    drop(old);
    let client = reopen_staged(&rig.participant_b, &operation)?;
    let provider = Arc::new(RefusePhrase(std::sync::atomic::AtomicUsize::new(0)));
    let participant = LocalPairingParticipant {
        root: rig.participant_b.root.clone(),
        account_id: rig.participant_b.account_id.clone(),
        vault: rig.participant_b.vault.clone(),
        provider: provider.clone(),
        db: Mutex::new(None),
        persist: rig.participant_b.persist.clone(),
        query: rig.participant_b.query.clone(),
    };
    let db = client.account_db()?;
    let native = rig.node.current_authority(&expected.record.body.account_anchor)?;
    let current =
        ramflux_crypto::custody::verify_publication(&native, crate::custody::network_now()?)?;
    let mut live = db
        .pairing_live_rows()?
        .into_iter()
        .find(|row| row.operation_id == operation)
        .ok_or("test: prepared live row missing after reopen")?;
    let retained = participant
        .restore_prepared_full_candidate_in(db, &live, &current, crate::custody::network_now()?)?
        .ok_or("test: exact retained candidate was lost")?;
    assert_eq!(retained.publication(), &expected, "test: restart generated another candidate");
    assert_eq!(
        object_hash(retained.publication())?,
        object_hash(&expected)?,
        "test: candidate bytes changed"
    );
    assert_eq!(
        db.pairing_head()?.ok_or("test: head missing")?.candidate,
        head.candidate,
        "test: candidate recovery mutated its durable owner"
    );
    live.generation += 1;
    assert!(
        participant
            .restore_prepared_full_candidate_in(db, &live, &current, crate::custody::network_now()?)
            .is_err(),
        "test: prepared candidate crossed generations"
    );
    assert_eq!(
        provider.0.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "test: prepared candidate recovery requested a phrase"
    );
    rig.primary.lock().await?;
    Ok(())
}

fn reopen_staged(
    participant: &LocalPairingParticipant,
    operation: &str,
) -> Result<crate::RamfluxClient, SdkError> {
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(&participant.root)?;
    let request = ramflux_protocol::custody::pairing::local_dto::StatusRequest {
        schema: "ramflux.pairing.StatusRequest.v2".into(),
        version: 2,
        operation_id: operation.into(),
        generation: 1,
    };
    let provider =
        crate::custody::pairing::recipient::tests::Phrase::setup(b"component-recipient-passphrase");
    client.active_account_db = Some(crate::bus::unlock_for_test(
        &participant.root,
        &participant.account_id,
        &request,
        &provider,
    )?);
    Ok(client)
}

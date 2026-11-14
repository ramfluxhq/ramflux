// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate-bound approval after lost SAS flags. Actual cold actor reconstruction is separate.
#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::custody::{BranchCredentials, PrimaryVault};
    use ramflux_protocol::custody::{
        DeviceRef,
        pairing::local_dto::{Confirm, Outcome, TransferAffirm},
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    struct MeteredVault {
        inner: Arc<dyn PrimaryVault>,
        primary_reads: AtomicUsize,
    }
    impl PrimaryVault for MeteredVault {
        fn vault_class(&self) -> &'static str {
            self.inner.vault_class()
        }
        fn preflight(&self) -> Result<(), crate::SdkError> {
            self.inner.preflight()
        }
        fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), crate::SdkError> {
            self.inner.store_new(reference, key)
        }
        fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, crate::SdkError> {
            self.primary_reads.fetch_add(1, Ordering::Relaxed);
            self.inner.load_primary(reference)
        }
        fn load_branch(
            &self,
            reference: &str,
            principal: &str,
            device: &DeviceRef,
        ) -> Result<BranchCredentials, crate::SdkError> {
            self.inner.load_branch(reference, principal, device)
        }
        fn delete(&self, reference: &str) -> Result<(), crate::SdkError> {
            self.inner.delete(reference)
        }
        fn store_branch(
            &self,
            reference: &str,
            seeds: &zeroize::Zeroizing<[u8; 64]>,
        ) -> Result<(), crate::SdkError> {
            self.inner.store_branch(reference, seeds)
        }
    }
    async fn setup()
    -> Result<(Rig, String, RecipientPrepared, Arc<MeteredVault>), Box<dyn std::error::Error>> {
        Box::pin(setup_with_original_approval(false)).await
    }
    async fn setup_with_original_approval(
        original: bool,
    ) -> Result<(Rig, String, RecipientPrepared, Arc<MeteredVault>), Box<dyn std::error::Error>>
    {
        let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
        rig.primary.sync_relay().await?;
        rig.participant_a.return_client(&mut rig.source.client)?;
        Box::pin(finish_owned_stream(&mut rig)).await?;
        let recipient = Box::pin(prepare_recipient_candidate(&mut rig, &operation)).await?;
        let old = &rig.participant_a;
        let vault =
            Arc::new(MeteredVault { inner: old.vault.clone(), primary_reads: AtomicUsize::new(0) });
        let owner = Arc::new(crate::custody::pairing::LocalPairingParticipant {
            root: old.root.clone(),
            account_id: old.account_id.clone(),
            vault: vault.clone(),
            provider: old.provider.clone(),
            db: Mutex::new(None),
            persist: old.persist.clone(),
            query: old.query.clone(),
        });
        rig.primary.set_participant(owner.clone());
        rig.participant_a = owner;
        if !original {
            rig.primary.replace_full_confirmations_for_test((false, false))?;
        }
        Ok((rig, operation, recipient, vault))
    }
    fn request(
        rig: &Rig,
        operation: &str,
        recipient: &RecipientPrepared,
    ) -> Result<TransferAffirm, Box<dyn std::error::Error>> {
        let db = rig.source.client.account_db()?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|r| r.operation_id == operation)
            .ok_or("test: source live row")?;
        let stage = db.open_full_transfer_stage(
            operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            rig.now,
        )?;
        Ok(TransferAffirm {
            schema: "ramflux.pairing.TransferAffirm.v2".into(),
            version: 2,
            operation_id: operation.into(),
            generation: live.generation,
            transcript_hash: encode_base64url(stage.resume_record()?.th),
            new_record_hash: ramflux_protocol::custody::object_hash(&recipient.publication.record)?,
            approved: true,
        })
    }
    async fn review_without_approval(
        rig: &mut Rig,
        recipient: &RecipientPrepared,
        request: &TransferAffirm,
        vault: &MeteredVault,
    ) -> TestResult {
        assert!(
            rig.primary.observe_full_source_candidate(recipient.publication.clone()).await.is_err(),
            "test: DATA-only source restored its old SAS signing approval"
        );
        let review =
            rig.primary.inspect_full_source_candidate(recipient.publication.clone()).await?;
        assert!(
            matches!(review.outcome,Outcome::Update {value} if value.emoji_indices.is_none()
                && value.proposal_hash.as_deref()==Some(request.new_record_hash.as_str())
                && value.peer_ref==Some(recipient.install.recipient_ref.clone())),
            "test: review omitted exact candidate/destination binding"
        );
        let confirm = Confirm {
            schema: "ramflux.pairing.Confirm.v2".into(),
            version: 2,
            operation_id: request.operation_id.clone(),
            generation: request.generation,
            transcript_hash: request.transcript_hash.clone(),
            r#match: true,
        };
        assert!(
            rig.primary.confirm(&confirm).await.is_err(),
            "test: initial Confirm signed a resumed source candidate"
        );
        let mut changed = request.clone();
        changed.new_record_hash = encode_base64url([91; 32]);
        assert!(
            rig.primary.affirm_full_transfer(&changed).await.is_err(),
            "test: affirmation ignored changed candidate hash"
        );
        assert_eq!(
            vault.primary_reads.load(Ordering::Relaxed),
            0,
            "test: rejected/data-only request loaded old management authority"
        );
        Ok(())
    }
    async fn consume_once(
        rig: &mut Rig,
        request: &TransferAffirm,
        vault: &MeteredVault,
    ) -> TestResult {
        let before = rig.node.query_calls.load(Ordering::Relaxed);
        rig.primary.affirm_full_transfer(request).await?;
        assert_eq!(
            rig.node.query_calls.load(Ordering::Relaxed),
            before + 1,
            "test: attended request reused pre-gesture native evidence"
        );
        assert!(
            rig.primary.affirmed_full_source_preservation().is_err(),
            "test: native work released a signature without local writer service"
        );
        assert_eq!(
            vault.primary_reads.load(Ordering::Relaxed),
            0,
            "test: native-query phase retained primary signing work"
        );
        assert!(
            rig.primary.service_full_transfer(rig.source.client.account_db()?)?,
            "test: original writer did not service queued affirmation"
        );
        assert_eq!(
            rig.node.query_calls.load(Ordering::Relaxed),
            before + 1,
            "test: local writer loan crossed native I/O"
        );
        assert_eq!(
            vault.primary_reads.load(Ordering::Relaxed),
            1,
            "test: exact attended candidate was not signed once"
        );
        let signed = canonical_json_bytes(rig.primary.affirmed_full_source_preservation()?)?;
        assert!(
            rig.primary.affirm_full_transfer(request).await.is_err(),
            "test: replayed source approval was consumed twice"
        );
        assert!(
            rig.primary.finish_full_source_affirmation(rig.source.client.account_db()?).is_err(),
            "test: empty local approval slot signed again"
        );
        assert_eq!(
            canonical_json_bytes(rig.primary.affirmed_full_source_preservation()?)?,
            signed,
            "test: repeated request replaced immutable preservation"
        );
        assert_eq!(
            rig.primary.replace_full_confirmations_for_test((false, false))?,
            (false, false),
            "test: source affirmation revived SAS flags"
        );
        Ok(())
    }
    async fn deliver_source_ready(
        rig: &mut Rig,
        request: &TransferAffirm,
        recipient: &RecipientPrepared,
    ) -> TestResult {
        rig.primary.affirm_full_transfer(request).await?;
        assert!(
            rig.primary.service_full_transfer(rig.source.client.account_db()?)?,
            "test: source signing service did not run"
        );
        rig.primary
            .poll_full_management_control()
            .await
            .map_err(|error| format!("test: A ready sender: {error}"))?;
        assert!(
            rig.secondary
                .poll_full_management_control()
                .await
                .map_err(|error| format!("test: B ready receiver: {error}"))?,
            "test: destination did not receive encrypted full preservation"
        );
        let signed = rig.primary.affirmed_full_source_preservation()?.clone();
        let source = custody::load_data_account(
            &rig.participant_a.root,
            &rig.participant_a.account_id,
            rig.now,
        )?
        .record()
        .clone();
        let slot = rig.participant_b.db.lock().map_err(|_| "test: B writer")?;
        let db = slot.as_ref().ok_or("test: B staged writer")?;
        let stage = db.open_full_transfer_stage(
            &request.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        assert!(
            stage
                .retained_destination_after_native_ack(
                    &source,
                    &recipient.publication.record,
                    rig.now
                )?
                .is_none(),
            "test: wire receipt skipped the destination's durable writer service"
        );
        let mut substituted = signed.clone();
        substituted.body.target_restrictions_root = encode_base64url([93; 32]);
        assert!(
            stage
                .retain_destination_full_preservation(
                    &source,
                    &recipient.publication.record,
                    &substituted,
                    rig.now
                )
                .is_err(),
            "test: B trusted source roots without its own durable reverse proof"
        );
        drop(stage);
        let before = rig.node.query_calls.load(Ordering::Relaxed);
        assert!(
            rig.secondary
                .service_full_transfer(db)
                .map_err(|error| format!("test: B ready persistence: {error}"))?,
            "test: B did not persist the exact ready control"
        );
        assert_eq!(
            rig.node.query_calls.load(Ordering::Relaxed),
            before,
            "test: B's short writer loan crossed native I/O"
        );
        let stage = db.open_full_transfer_stage(
            &request.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        let saved = stage
            .retained_destination_after_native_ack(&source, &recipient.publication.record, rig.now)?
            .ok_or("test: missing durable B preservation")?;
        assert_eq!(
            canonical_json_bytes(&saved)?,
            canonical_json_bytes(&signed)?,
            "test: B retained different source approval bytes"
        );
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_uninterrupted_sas_approval_only_signs_through_original_writer_service()
    -> TestResult {
        let hold = ClockHold::new();
        let outcome = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            let (mut rig, operation, recipient, vault) =
                Box::pin(setup_with_original_approval(true)).await?;
            let expected = request(&rig, &operation, &recipient)?;
            let mut delivered = false;
            for _ in 0..66 {
                rig.secondary
                    .poll_full_management_control()
                    .await
                    .map_err(|error| format!("test: B candidate control: {error}"))?;
                if rig
                    .primary
                    .poll_full_management_control()
                    .await
                    .map_err(|error| format!("test: A candidate review: {error}"))?
                {
                    delivered = true;
                    break;
                }
            }
            assert!(delivered, "test: original confirmed source did not receive candidate");
            assert_eq!(
                vault.primary_reads.load(Ordering::Relaxed),
                0,
                "test: native/relay phase loaded management key"
            );
            assert!(
                rig.primary.affirmed_full_source_preservation().is_err(),
                "test: original approval skipped writer service"
            );
            assert!(
                rig.primary.affirm_full_transfer(&expected).await.is_err(),
                "test: original SAS approval accepted a second candidate grant"
            );
            let before = rig.node.query_calls.load(Ordering::Relaxed);
            assert!(
                rig.primary.service_full_transfer(rig.source.client.account_db()?)?,
                "test: original writer did not consume its approved work"
            );
            assert_eq!(
                rig.node.query_calls.load(Ordering::Relaxed),
                before,
                "test: signing crossed native I/O under writer loan"
            );
            assert_eq!(
                vault.primary_reads.load(Ordering::Relaxed),
                1,
                "test: source did not sign exactly once"
            );
            assert_eq!(
                rig.primary.affirmed_full_source_preservation()?.body.new_record_hash,
                expected.new_record_hash,
                "test: original approval signed a different candidate"
            );
            rig.primary.lock().await?;
            rig.secondary.lock().await?;
            Ok(())
        }))
        .await;
        hold.finish().await?;
        outcome
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_candidate_control_reaches_source_review_without_approval() -> TestResult {
        let hold = ClockHold::new();
        let outcome = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            let (mut rig, operation, recipient, vault) = Box::pin(setup()).await?;
            let expected = request(&rig, &operation, &recipient)?;
            let mut delivered = false;
            for _ in 0..66 {
                rig.secondary.poll_full_management_control().await.map_err(|error|format!("test: B candidate control: {error}"))?;
                if rig.primary.poll_full_management_control().await.map_err(|error|format!("test: A candidate review: {error}"))? {
                    delivered = true;
                    break;
                }
            }
            assert!(delivered,"test: encrypted candidate controls did not reach original source");
            let status=Box::pin(rig.primary.status(&ramflux_protocol::custody::pairing::local_dto::StatusRequest {
                schema:"ramflux.pairing.StatusRequest.v2".into(),version:2,
                operation_id:operation,generation:expected.generation,
            })).await?;
            assert!(matches!(status.outcome,Outcome::Update {value} if value.phase=="proposal_pending"
                && value.proposal_hash.as_deref()==Some(expected.new_record_hash.as_str())
                && value.peer_ref.as_ref()==Some(&recipient.install.recipient_ref)
                && value.emoji_indices.is_none()),"test: source review did not bind decrypted candidate to its own native/base context");
            assert_eq!(vault.primary_reads.load(Ordering::Relaxed),0,"test: encrypted peer message granted management signing approval");
            assert!(rig.primary.affirmed_full_source_preservation().is_err(),"test: relay candidate minted source preservation");
            Box::pin(deliver_source_ready(&mut rig,&expected,&recipient)).await?;
            rig.primary.lock().await?;
            rig.secondary.lock().await?;
            Ok(())
        })).await;
        hold.finish().await?;
        outcome
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_source_affirmation_is_one_shot_and_keeps_sas_retired() -> TestResult {
        let hold = ClockHold::new();
        let outcome = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            let (mut rig, operation, recipient, vault) = Box::pin(setup()).await?;
            let request = request(&rig, &operation, &recipient)?;
            Box::pin(review_without_approval(&mut rig, &recipient, &request, &vault)).await?;
            Box::pin(consume_once(&mut rig, &request, &vault)).await?;
            rig.participant_a.take_client(&mut rig.source.client)?;
            let submission = rig.primary.prepare_affirmed_source_submission().await?;
            assert_eq!(
                vault.primary_reads.load(Ordering::Relaxed),
                1,
                "test: submission minted another preservation signature"
            );
            assert!(
                rig.primary.prepare_affirmed_source_submission().await.is_err(),
                "test: attended submission token was reused"
            );
            rig.participant_a.return_client(&mut rig.source.client)?;
            drop(submission);
            rig.primary.lock().await?;
            rig.secondary.lock().await?;
            Ok(())
        }))
        .await;
        hold.finish().await?;
        outcome
    }
}

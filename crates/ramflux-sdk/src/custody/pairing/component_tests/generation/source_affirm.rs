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
        rig.primary.replace_full_confirmations_for_test((false, false))?;
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

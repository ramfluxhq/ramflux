// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-Issue bulk work cannot freeze an actor's stale public native head.
#[cfg(test)]
mod tests {
    use super::super::*;
    #[tokio::test(start_paused = true)]
    async fn pairing_full_issue_refreshes_native_head_after_source_preparation() -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
        hold.finish().await?;
        result
    }
    async fn run() -> TestResult {
        let mut rig = Box::pin(Rig::open_profile(true)).await?;
        let account = crate::custody::load_data_account(
            &rig.participant_a.root,
            &rig.participant_a.account_id,
            rig.now,
        )?;
        let original = object_hash(account.record())?;
        let primary = account.group_primary(rig.participant_a.vault.as_ref())?;
        let mut body = account.record().body.clone();
        let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
        body.device_set_epoch = ramflux_protocol::custody::encode_epoch(range, revision + 1)?;
        body.previous_record_hash = Some(object_hash(account.record())?);
        body.profile.display_name = "Fresh native source profile".into();
        let publication = Publication { record: primary.sign_record(body)?, compacted_ids: None };
        drop(primary);
        rig.node.persist_head(&publication, rig.now)?;
        let expected = object_hash(&publication.record)?;
        assert_ne!(original, expected, "test: profile publication did not advance source head");
        let issued = Box::pin(rig.primary.begin_full(full_begin(rig.now))).await?;
        let Outcome::Begin { value } = issued.outcome else {
            return Err("test: refreshed source did not issue a full invitation".into());
        };
        let token = value.invite_token;
        assert_eq!(
            token.invitation.body.base_record_hash, expected,
            "test: Issue used the actor head cached before source preparation"
        );
        rig.primary.lock().await?;
        Ok(())
    }
    use ramflux_protocol::custody::pairing::native::CreateSpec;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
    struct CountingNative {
        calls: Arc<AtomicUsize>,
        loan_released: Arc<AtomicBool>,
        owner: Arc<LocalPairingParticipant>,
    }
    impl PairingNative for CountingNative {
        fn issue(
            &self,
            _: CreateSpec,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            ramflux_protocol::custody::pairing::native::Issued,
                            SdkError,
                        >,
                    > + std::marker::Send,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.loan_released.store(self.owner.db.try_lock().is_ok(), Ordering::SeqCst);
            Box::pin(async { Err(SdkError::PairingCode("WrongContext")) })
        }
        fn create(
            &self,
            _: ramflux_protocol::custody::pairing::native::Create,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            ramflux_protocol::custody::pairing::native::Created,
                            SdkError,
                        >,
                    > + std::marker::Send,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(SdkError::PairingCode("WrongContext")) })
        }
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_begin_unknown_kind_refuses_before_issue_and_releases_source_loan()
    -> ResultOf {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(preflight())).await;
        hold.finish().await?;
        result
    }
    async fn preflight() -> ResultOf {
        let rig = Box::pin(Rig::open_profile(true)).await?;
        let owner = rig.participant_a.clone();
        let account = crate::custody::load_account(&owner.root, &owner.account_id, rig.now)?;
        {
            let slot = owner.db.lock().map_err(|_| "DB")?;
            slot.as_ref().ok_or("DB")?.persist_actor_state("undeclared/full-begin-test", &true)?;
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let loan_released = Arc::new(AtomicBool::new(false));
        let native = Arc::new(CountingNative {
            calls: calls.clone(),
            loan_released: loan_released.clone(),
            owner: owner.clone(),
        });
        let now = crate::custody::network_now()?;
        let store = Arc::new(Mutex::new(ramflux_node_core::pairing_relay::PairingRelayStore::new(
            ramflux_node_core::pairing_relay::PairingRelayConfig {
                clock: ramflux_node_core::pairing_relay::TestPairingClock::new(now),
                node_seed: [7; 32],
                public_origin: "https://relay.example:443".into(),
            },
        )?));
        let mut actor = PairingActor::new(
            PairingIdentity {
                account_id: owner.account_id.clone(),
                local_ref: account.record().body.master_certificate.body.primary_device_ref.clone(),
                master_public_key: Some(
                    account.record().body.master_certificate.body.master_public_key.clone(),
                ),
                base_record_hash: object_hash(account.record())?,
                base_epoch: account.record().body.device_set_epoch,
                is_primary: true,
            },
            Some(native),
            Arc::new(crate::custody::pairing::tests::MemoryRelay { store }),
            PairingConfig { enabled: true, extra_root_ca_pem: None },
        );
        actor.set_participant(owner.clone());
        let begin = full_begin(now);
        let error =
            actor.begin_full(begin.clone()).await.err().ok_or("unsupported actor accepted")?;
        assert_eq!(calls.load(Ordering::SeqCst), 0, "unknown kind allocated native invitation");
        assert!(
            matches!(&error, SdkError::PairingField("UnsupportedRecord")),
            "unexpected preflight refusal: {error}"
        );
        {
            let slot = owner.db.lock().map_err(|_| "DB")?;
            slot.as_ref().ok_or("DB")?.remove_actor_state("undeclared/full-begin-test")?;
        }
        let refused =
            actor.begin_full(begin).await.err().ok_or("test: counting native accepted")?;
        assert!(
            matches!(refused, SdkError::PairingCode("WrongContext")),
            "test: supported source did not reach counting native: {refused}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "supported preflight never reached Issue");
        assert!(loan_released.load(Ordering::SeqCst), "native Issue retained the source DB loan");
        Ok(())
    }
}

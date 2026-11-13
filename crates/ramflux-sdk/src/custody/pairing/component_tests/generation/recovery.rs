// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lose the real G2 in-memory owner, reopen with B's password, reverify bytes and finish G3.
use super::*;
use crate::custody::pairing::full_generation::owner::FullGenerationCommitted;
pub(super) fn finish_after_g2_restart(
    rig: &Rig,
    committed: FullGenerationCommitted,
    install: &Install,
    authority: &CustodyAuthority,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    // The old ordinary B writer is positively retired. No key/proof from this
    // committed owner crosses into recovery; only the original private credential does.
    drop(committed);
    let mut frontend = crate::RamfluxClient::new();
    frontend.open_account_index(&rig.participant_b.root)?;
    assert!(
        frontend.unlock_account(&rig.participant_b.account_id, b"wrong-original-password").is_err(),
        "test: G2 crash recovery bypassed B's wrapping"
    );
    frontend.unlock_account(&rig.participant_b.account_id, b"component-recipient-passphrase")?;
    assert!(
        !crate::custody::pairing::ordinary_session_admitted(
            &frontend,
            &rig.participant_b.account_id
        )?,
        "test: G2-only password unlock opened ordinary admission"
    );
    let current = rig.participant_b.query.current_authority(&install.account_anchor)?;
    assert_eq!(
        current.publication.record, authority.publication.record,
        "test: recovery query returned another candidate"
    );
    let verified = ramflux_crypto::custody::verify_publication(&current, rig.now)?;
    let db = frontend.account_db()?;
    let stage = db.open_full_recipient_install_stage(&install.operation_id, &verified, rig.now)?;
    let local = Installation {
        root: &rig.participant_b.root,
        db,
        vault: rig.participant_b.vault.as_ref(),
        now: rig.now,
    };
    let mut wrong = install.clone();
    wrong.full_transfer.as_mut().ok_or("test: full install")?.generation_nonce =
        encode_base64url([99; 32]);
    assert!(
        FullGenerationCommitted::recover(&local, &stage, wrong, &current).is_err(),
        "test: recovery accepted another G1 nonce with identical paths"
    );
    let preparation =
        FullGenerationCommitted::pin_recovery(&local, &stage, install.clone(), &current)?;
    drop(stage);
    // The private byte traversal carries only its own keys and weak unlock scope.
    let prepared = preparation.verify()?;
    let current = rig.participant_b.query.current_authority(&install.account_anchor)?;
    let verified = ramflux_crypto::custody::verify_publication(&current, rig.now)?;
    let stage = db.open_full_recipient_install_stage(&install.operation_id, &verified, rig.now)?;
    let recovered = prepared.accept(&local, &stage, &current)?;
    drop(stage);
    let selected = super::finish_installed(rig, recovered, install, &current)?;
    assert!(
        crate::custody::pairing::ordinary_session_admitted(
            &frontend,
            &rig.participant_b.account_id
        )?,
        "test: exact recovered G3 did not admit the original data owner"
    );
    Ok(selected)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn pairing_full_selected_g2_reopens_from_encrypted_union_before_g3() -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
        hold.finish().await?;
        result
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_cold_status_recovers_selected_g2_without_approval() -> TestResult {
        let hold = ClockHold::new();
        let result =
            crate::bus::credentials::contract_tests::deadline(Box::pin(run_actor(2))).await;
        hold.finish().await?;
        result
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_cold_status_rebuilds_unselected_g1_from_current_b() -> TestResult {
        let hold = ClockHold::new();
        for cut in [0, 1] {
            crate::bus::credentials::contract_tests::deadline(Box::pin(run_actor(cut))).await?;
        }
        hold.finish().await?;
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn primary_transfer_full_generation_publication_crash_cuts() -> TestResult {
        let hold = ClockHold::new();
        for cut in [3, 4, 5, 6] {
            crate::bus::credentials::contract_tests::deadline(Box::pin(run_actor(cut))).await?;
        }
        hold.finish().await?;
        Ok(())
    }
    async fn run_actor(cut: u8) -> TestResult {
        use ramflux_protocol::custody::pairing::local_dto::StatusRequest;
        let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
        rig.primary.sync_relay().await?;
        rig.participant_a.return_client(&mut rig.source.client)?;
        Box::pin(finish_owned_stream(&mut rig)).await?;
        let published = Box::pin(publication(&mut rig, &operation)).await?;
        let (install, authority) = retain_crash_cut(&rig, &operation, published, cut)?;
        let mut relay = None;
        rig.secondary.wrap_transport_for_test(|inner| {
            relay = Some(inner.clone());
            inner
        });
        rig.secondary.lock().await?;
        let mut frontend = crate::RamfluxClient::new();
        frontend.open_account_index(&rig.participant_b.root)?;
        let authority_path = rig
            .participant_b
            .root
            .join("custody_accounts")
            .join(&rig.participant_b.account_id)
            .join("authority.json");
        let retained_authority = authority_path.with_extension("retained-test-authority");
        let had_authority = authority_path.try_exists()?;
        if had_authority {
            std::fs::rename(&authority_path, &retained_authority)?;
        }
        std::io::Write::write_all(
            &mut crate::platform::fs::create_new_owner_only(&authority_path)?,
            b"{}",
        )?;
        assert!(
            frontend
                .unlock_account(&rig.participant_b.account_id, b"component-recipient-passphrase")
                .is_err(),
            "test: pending G2 hid malformed native authority"
        );
        std::fs::remove_file(&authority_path)?;
        if had_authority {
            std::fs::rename(&retained_authority, &authority_path)?;
        }
        let request = {
            let pending = crate::custody::pairing::local_credential::load_reservation(
                &rig.participant_b.root,
                &rig.participant_b.account_id,
            )?
            .ok_or("test: reservation")?;
            let generation = install_generation(
                &rig.participant_b.root,
                &rig.participant_b.account_id,
                &operation,
            )?;
            assert!(pending.frontend_generation > 0, "test: lost credential scope");
            StatusRequest {
                schema: "ramflux.pairing.StatusRequest.v2".into(),
                version: 2,
                operation_id: operation.clone(),
                generation,
            }
        };
        let db = crate::bus::unlock_for_test(
            &rig.participant_b.root,
            &rig.participant_b.account_id,
            &request,
            rig.participant_b.provider.as_ref(),
        )?;
        *rig.participant_b.db.lock().map_err(|_| "test: original B owner")? = Some(db);
        Box::pin(exercise_recovered_actor(
            &rig,
            install,
            authority,
            request,
            relay.ok_or("test: relay")?,
            frontend,
        ))
        .await?;
        rig.primary.lock().await?;
        Ok(())
    }
    fn retain_crash_cut(
        rig: &Rig,
        operation: &str,
        published: Published,
        cut: u8,
    ) -> Result<(Install, CustodyAuthority), Box<dyn std::error::Error>> {
        let result = match cut {
            0 => (published.install, published.authority),
            1 => {
                let (prepared, authority) = prepare_generation_case(&rig, &operation, published)?;
                let install = prepared.install().clone();
                drop(prepared);
                (install, authority)
            }
            _ => {
                let (mut committed, mut install, authority) =
                    select_generation_case(&rig, &operation, published)?;
                if cut >= 3 {
                    let selected = committed.open_selected()?;
                    committed.retain_g3_crash_cut_for_test(
                        &Installation {
                            root: &rig.participant_b.root,
                            db: &selected,
                            vault: rig.participant_b.vault.as_ref(),
                            now: rig.now,
                        },
                        &authority,
                        cut,
                    )?;
                    install = committed.install().clone();
                }
                drop(committed);
                (install, authority)
            }
        };
        Ok(result)
    }
    async fn exercise_recovered_actor(
        rig: &Rig,
        install: Install,
        authority: CustodyAuthority,
        request: ramflux_protocol::custody::pairing::local_dto::StatusRequest,
        relay: std::sync::Arc<dyn crate::custody::pairing::PairingTransport>,
        mut frontend: crate::RamfluxClient,
    ) -> TestResult {
        use crate::custody::pairing::{PairingActor, PairingConfig, PairingIdentity};
        use ramflux_protocol::custody::pairing::local_dto::{FullStatusStage, Outcome};
        let mut actor = PairingActor::new(
            PairingIdentity {
                account_id: rig.participant_b.account_id.clone(),
                local_ref: install.recipient_ref.clone(),
                master_public_key: Some(
                    authority
                        .publication
                        .record
                        .body
                        .master_certificate
                        .body
                        .master_public_key
                        .clone(),
                ),
                base_record_hash: ramflux_protocol::custody::object_hash(
                    &authority.publication.record,
                )?,
                base_epoch: authority.publication.record.body.device_set_epoch,
                is_primary: true,
            },
            None,
            relay,
            PairingConfig { enabled: true, extra_root_ca_pem: None },
        );
        actor.set_participant(rig.participant_b.clone());
        let before = rig.node.query_calls.load(std::sync::atomic::Ordering::Relaxed);
        let mut wrong = request.clone();
        wrong.generation += 1;
        assert!(
            actor.recover_full_installation(&wrong).await.is_err(),
            "test: stale generation recovered G3"
        );
        let result =
            actor.recover_full_installation(&request).await?.ok_or("test: recovered status")?;
        assert!(
            matches!(result.outcome, Outcome::FullStatus { value } if value.stage == FullStatusStage::Installed),
            "test: exact recovered G3 was not reported installed"
        );
        assert!(
            rig.node.query_calls.load(std::sync::atomic::Ordering::Relaxed) >= before + 2,
            "test: recovery did not reobserve native head around physical verification"
        );
        assert!(actor.displayed_proposal().is_err(), "test: recovery restored human approval");
        rig.participant_b.return_client(&mut frontend)?;
        assert!(
            crate::custody::pairing::ordinary_session_admitted(&frontend, &install.account_id)?,
            "test: recovered G3 kept exact ordinary owner fenced"
        );
        assert_eq!(
            actor.transfer_status(&request).await?.version,
            2,
            "test: repeated status lost recovered installation"
        );
        actor.lock().await?;
        Ok(())
    }
    fn install_generation(
        root: &std::path::Path,
        account: &str,
        operation: &str,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let mut client = crate::RamfluxClient::new();
        client.open_account_index(root)?;
        client.unlock_account(account, b"component-recipient-passphrase")?;
        client
            .account_db()?
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .map(|row| row.generation)
            .ok_or_else(|| "test: live operation".into())
    }
    async fn run() -> TestResult {
        let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
        rig.primary.sync_relay().await?;
        rig.participant_a.return_client(&mut rig.source.client)?;
        Box::pin(finish_owned_stream(&mut rig)).await?;
        let published = Box::pin(publication(&mut rig, &operation)).await?;
        install_generation_case(&rig, &operation, published, true)?;
        rig.primary.lock().await?;
        rig.secondary.lock().await?;
        Ok(())
    }
}

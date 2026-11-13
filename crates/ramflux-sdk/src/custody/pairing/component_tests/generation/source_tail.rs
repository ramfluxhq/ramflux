// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native source J6/tail-cut component. Candidate transport and tail stream remain separate.
use super::{CustodyAuthority, Rig, encode_base64url};
use crate::custody::pairing::{FullSourcePublished, FullSourceRetirementOutcome, Installation};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(super) fn acknowledge(
    rig: &mut Rig,
    published: &FullSourcePublished,
    deferred_cleanup: bool,
) -> TestResult {
    let authority: CustodyAuthority = published.authority().clone();
    let later = rig.now + 301; // Approval expired after native publication; the lease is still live.
    ramflux_crypto::custody::verify_publication(&authority, later)?;
    let candidate_hash = ramflux_protocol::custody::object_hash(&authority.publication.record)?;
    rig.participant_a.take_client(&mut rig.source.client)?;
    let (cut, operation) = {
        let slot = rig.participant_a.db.lock().map_err(|_| "source J6 owner")?;
        let db = slot.as_ref().ok_or("source J6 writer")?;
        let cut = published.acknowledge(db, later).map_err(|error| {
            format!("J6 lost the already-published candidate after approval expiry: {error}")
        })?;
        let head = db.pairing_head()?.ok_or("source J6 head")?;
        assert_eq!(head.state, "acknowledged");
        assert_eq!(head.candidate_hash, candidate_hash);
        retire_with_deferred_cleanup(rig, published, db, later)?;
        let stage = db.open_full_transfer_stage(
            &head.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            later,
        )?;
        assert!(
            stage
                .commit_source_ack_and_pin_tail(
                    &head,
                    &encode_base64url(ramflux_crypto::random_32()?),
                    later
                )
                .is_err(),
            "J6 silently recut the existing source tail"
        );
        assert!(stage.finish_source_tail_capture().is_err(), "missing J6 snapshot silently recut");
        drop(stage);
        (cut, head.operation_id)
    };
    rig.participant_a.return_client(&mut rig.source.client)?;
    assert!(
        crate::custody::pairing::ordinary_session_admitted(
            &rig.source.client,
            &rig.participant_a.account_id
        )?,
        "cleanup_pending closed the installed secondary branch"
    );
    rig.participant_a.take_client(&mut rig.source.client)?;
    let work = {
        let slot = rig.participant_a.db.lock().map_err(|_| "source cleanup retry")?;
        let db = slot.as_ref().ok_or("source cleanup writer")?;
        if !deferred_cleanup {
            complete_and_replay_retirement(rig, published, db, later)?;
        }
        let stage = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            later,
        )?;
        let owner = stage.source_primary_owner()?.ok_or("source old owner")?;
        assert_eq!(
            rig.participant_a.vault.load_primary(owner.reference()).is_ok(),
            deferred_cleanup,
            "source cleanup changed an unexpected owner"
        );
        cut.into_private_work(stage)?
    };
    rig.participant_a.return_client(&mut rig.source.client)?;
    work.copy()?; // No ordinary writer/stage loan crosses the bulk private copy.
    rig.participant_a.take_client(&mut rig.source.client)?;
    {
        let slot = rig.participant_a.db.lock().map_err(|_| "source durable tail")?;
        let db = slot.as_ref().ok_or("source durable writer")?;
        let stage = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            later,
        )?;
        stage.finish_source_tail_capture()?;
        drop(stage);
        let reopened = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            later,
        )?;
        reopened.finish_source_tail_capture()?; // Reopen the keyed cut; never recapture.
    }
    rig.participant_a.return_client(&mut rig.source.client)?;
    Ok(())
}

fn complete_and_replay_retirement(
    rig: &Rig,
    published: &FullSourcePublished,
    db: &ramflux_storage::AccountDb,
    later: u64,
) -> TestResult {
    assert_eq!(
        published.retire_source(&Installation {
            root: &rig.participant_a.root,
            db,
            vault: rig.participant_a.vault.as_ref(),
            now: later,
        })?,
        FullSourceRetirementOutcome::Complete
    );
    // Completed local retirement cannot recreate a cleanup task or touch any provider item.
    let unavailable = DeleteUnavailable(rig.participant_a.vault.as_ref());
    assert_eq!(
        published.retire_source(&Installation {
            root: &rig.participant_a.root,
            db,
            vault: &unavailable,
            now: later,
        })?,
        FullSourceRetirementOutcome::Complete
    );
    Ok(())
}

fn retire_with_deferred_cleanup(
    rig: &Rig,
    published: &FullSourcePublished,
    db: &ramflux_storage::AccountDb,
    later: u64,
) -> TestResult {
    let deferred = DeleteUnavailable(rig.participant_a.vault.as_ref());
    assert_eq!(
        published.retire_source(&Installation {
            root: &rig.participant_a.root,
            db,
            vault: &deferred,
            now: later
        })?,
        FullSourceRetirementOutcome::CleanupPending
    );
    assert!(
        db.pairing_head()?.is_none(),
        "source secondary retained the primary head-writer fence"
    );
    let account = crate::custody::load_account(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        later,
    )?;
    assert_eq!(account.primary_vault_ref(), "");
    assert!(matches!(
        account.group_primary(&deferred),
        Err(crate::SdkError::PairingCode("PrimaryRequired"))
    ));
    let branch = account.credentials(&deferred, account.local_device_id()?, later)?;
    drop(branch);
    Ok(())
}

pub(super) struct DeleteUnavailable<'a>(pub(super) &'a dyn crate::custody::PrimaryVault);
impl crate::custody::PrimaryVault for DeleteUnavailable<'_> {
    fn preflight(&self) -> Result<(), crate::SdkError> {
        self.0.preflight()
    }
    fn store_new(
        &self,
        _: &str,
        _: &ramflux_crypto::custody::SelfSigningKey,
    ) -> Result<(), crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
    fn load_primary(
        &self,
        _: &str,
    ) -> Result<ramflux_crypto::custody::SelfSigningKey, crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
    fn delete(&self, _: &str) -> Result<(), crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
    fn store_branch(
        &self,
        _: &str,
        _: &zeroize::Zeroizing<[u8; 64]>,
    ) -> Result<(), crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<crate::custody::BranchCredentials, crate::SdkError> {
        self.0.load_branch(reference, principal, device)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ClockHold, bootstrap_full_rig, finish_owned_stream, publication};
    use super::*;
    use ramflux_protocol::custody::pairing::{PairingWire, full_transfer::ManifestKind};

    #[tokio::test(start_paused = true)]
    async fn pairing_full_tail_encoder_uses_exact_j6_view_after_source_writes() -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
        hold.finish().await?;
        result
    }
    async fn run() -> TestResult {
        let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
        rig.primary.sync_relay().await?;
        rig.participant_a.return_client(&mut rig.source.client)?;
        Box::pin(finish_owned_stream(&mut rig)).await?;
        let before = rig
            .participant_a
            .query
            .current_authority(&rig.source.client.account_db()?.principal_commitment)?;
        let before = ramflux_crypto::custody::verify_publication(&before, rig.now)?;
        assert!(
            rig.source
                .client
                .account_db()?
                .open_full_transfer_stage(
                    &operation,
                    ramflux_crypto::custody::pairing::PairingRole::Initiator,
                    rig.now,
                )?
                .into_source_tail_encoding_work(&before, rig.now)
                .is_err(),
            "test: a data receipt without native J6 admitted tail encoding"
        );
        let published = Box::pin(publication(&mut rig, &operation)).await?;
        let now = rig.now + 301;
        let current = ramflux_crypto::custody::verify_publication(&published.authority, now)?;
        assert!(
            rig.source
                .client
                .account_db()?
                .open_full_transfer_stage(
                    &operation,
                    ramflux_crypto::custody::pairing::PairingRole::Initiator,
                    now,
                )?
                .into_source_tail_encoding_work(&before, now)
                .is_err(),
            "test: stale own native head with the original primary admitted a tail"
        );
        let prior = rig.source.client.account_db()?.privacy_erasure_generation()?;
        let next = u64::try_from(prior)?.checked_add(1).ok_or("test: erasure overflow")?;
        rig.source.client.account_db()?.seed_full_transfer_object_veto_for_test(
            "after-j6-tail-cut",
            "after-j6-tail-manifest",
            next,
        )?;
        assert_eq!(
            rig.source.client.account_db()?.privacy_erasure_generation()?,
            i64::try_from(next)?,
            "test: late source write did not reach the actual writer"
        );
        verify_saved_tail(&mut rig, &operation, &current, prior, now)?;
        rig.primary.lock().await?;
        rig.secondary.lock().await?;
        Ok(())
    }
    fn verify_saved_tail(
        rig: &mut Rig,
        operation: &str,
        current: &ramflux_crypto::custody::VerifiedRecord,
        prior: i64,
        now: u64,
    ) -> TestResult {
        let mut encoded = None;
        for _ in 0..2 {
            rig.participant_a.take_client(&mut rig.source.client)?;
            let work = {
                let slot = rig.participant_a.db.lock().map_err(|_| "test: source tail owner")?;
                let db = slot.as_ref().ok_or("test: source tail writer")?;
                db.open_full_transfer_stage(
                    operation,
                    ramflux_crypto::custody::pairing::PairingRole::Initiator,
                    now,
                )?
                .into_source_tail_encoding_work(current, now)?
            };
            rig.participant_a.return_client(&mut rig.source.client)?;
            let draft = work.encode()?;
            let manifest = draft.manifest();
            assert_eq!(
                manifest.kind,
                ManifestKind::Tail,
                "test: J6 encoder emitted a prepublication delta"
            );
            assert_eq!(
                manifest.source_erasure_generation.0,
                u64::try_from(prior)?,
                "test: tail encoder recut a later source view"
            );
            assert_ne!(
                manifest.source_ref,
                current.envelope().body.master_certificate.body.primary_device_ref,
                "test: retired source tail was relabeled as new-primary data"
            );
            let bytes = manifest.to_wire_bytes()?;
            if let Some(previous) = &encoded {
                assert_eq!(
                    &bytes, previous,
                    "test: tail retry recut or rewrote its immutable manifest"
                );
            }
            encoded = Some(bytes);
        }
        Ok(())
    }
}

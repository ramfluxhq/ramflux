// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An already published intent retains its keys while a cancelled data owner refuses G1.
#[cfg(test)]
mod tests {
    use super::super::*;
    #[tokio::test(start_paused = true)]
    async fn pairing_full_installation_uses_original_root_cancellation_before_g1() -> TestResult {
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
        let published = Box::pin(publication(&mut rig, &operation)).await?;
        let (cancel, original) = {
            let slot = rig.participant_b.db.lock().map_err(|_| "test: original B writer")?;
            let db = slot.as_ref().ok_or("test: B writer")?;
            let stage = db.open_full_transfer_stage(
                &operation,
                ramflux_crypto::custody::pairing::PairingRole::Responder,
                rig.now,
            )?;
            (stage.io_cancel_handle(), db.path.clone())
        };
        cancel.cancel();
        let outcome = rig.participant_b.install_new_full_generation(&published.install, &cancel);
        assert!(
            matches!(
                outcome,
                Err(crate::SdkError::Storage(ramflux_storage::StorageError::PairingField(
                    "Cancelled"
                )))
            ),
            "test: installation did not bind the original cancelled root before bulk work"
        );
        {
            let slot = rig.participant_b.db.lock().map_err(|_| "test: retained B writer")?;
            let db = slot.as_ref().ok_or("test: retained B")?;
            assert_eq!(db.path, original, "test: cancelled installation selected a generation");
            assert!(db.pairing_adoption()?.is_none(), "test: cancelled installation fabricated G3");
            let pending = crate::custody::pairing::install_store::read_pending(
                &rig.participant_b.root,
                &rig.participant_b.account_id,
                &operation,
            )?
            .ok_or("test: retained published intent")?;
            assert_eq!(
                pending.record_hash, published.install.record_hash,
                "test: cancellation discarded the possibly published candidate"
            );
            let key = rig.participant_b.vault.load_primary(
                pending.primary_vault_ref.as_deref().ok_or("test: retained B primary ref")?,
            )?;
            assert_eq!(
                key.public_key(),
                published
                    .authority
                    .publication
                    .record
                    .body
                    .master_certificate
                    .body
                    .self_signing_public_key,
                "test: cancellation destroyed B's published primary key"
            );
            drop(key);
        }
        rig.primary.lock().await?;
        rig.secondary.lock().await?;
        Ok(())
    }
}

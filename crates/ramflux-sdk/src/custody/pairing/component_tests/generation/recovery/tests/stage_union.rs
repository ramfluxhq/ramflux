// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cold G1/G2 plus adversarial same-path union replacement and concurrent original B writes.
use super::*;
#[derive(Clone, Copy)]
enum Change {
    Writer,
    File,
}
#[tokio::test(start_paused = true)]
async fn pairing_full_stage_link_and_union_install_crash_cuts() -> TestResult {
    let hold = ClockHold::new();
    for cut in [0, 1, 2] {
        crate::bus::credentials::contract_tests::deadline(Box::pin(run_actor(cut))).await?;
    }
    for change in [Change::Writer, Change::File] {
        crate::bus::credentials::contract_tests::deadline(Box::pin(reject_changed_union(change)))
            .await?;
    }
    hold.finish().await?;
    Ok(())
}
async fn reject_changed_union(change: Change) -> TestResult {
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    rig.primary.sync_relay().await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let published = Box::pin(publication(&mut rig, &operation)).await?;
    let (prepared, authority) = prepare_generation_case(&rig, &operation, published)?;
    let install = prepared.install().clone();
    let (prior, head) = {
        let slot = rig.participant_b.db.lock().map_err(|_| "test: current B owner")?;
        let db = slot.as_ref().ok_or("test: current B writer missing")?;
        (
            ramflux_storage::AccountIndex::open(&rig.participant_b.root)?
                .account(&rig.participant_b.account_id)?,
            db.pairing_head()?.ok_or("test: positive B head missing")?,
        )
    };
    match change {
        Change::Writer => {
            let slot = rig.participant_b.db.lock().map_err(|_| "test: B concurrent writer")?;
            slot.as_ref().ok_or("test: B writer absent")?.seed_full_transfer_object_veto_for_test(
                "after-union-validation",
                "union-race-manifest",
                29,
            )?;
        }
        Change::File => {
            let full =
                install.full_transfer.as_ref().ok_or("test: prepared full generation absent")?;
            let path = rig.participant_b.root.join(&full.db_relative_path);
            let replacement = path.with_file_name("same-union-replacement.db");
            std::fs::copy(&path, &replacement)?;
            std::fs::rename(&replacement, &path)?;
        }
    }
    {
        let slot = rig.participant_b.db.lock().map_err(|_| "test: B selection owner")?;
        let db = slot.as_ref().ok_or("test: B selection writer absent")?;
        let stage = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        assert!(
            prepared
                .select(
                    &Installation {
                        root: &rig.participant_b.root,
                        db,
                        vault: rig.participant_b.vault.as_ref(),
                        now: rig.now
                    },
                    &stage,
                    &authority
                )
                .is_err(),
            "test: paths and incoming chain alone admitted a changed prepared union"
        );
    }
    assert_eq!(
        ramflux_storage::AccountIndex::open(&rig.participant_b.root)?
            .account(&rig.participant_b.account_id)?,
        prior,
        "test: refused union changed the selected B generation"
    );
    assert!(
        !ordinary_session_admitted_for_participant(&rig.participant_b)?,
        "test: invalid private union opened ordinary admission"
    );
    // A fresh actual-B copy and physical root check can still complete the same positive native head.
    install_live_generation(
        &rig,
        &operation,
        Published { source_cleanup: None, authority, install, head },
    )?;
    assert!(
        ordinary_session_admitted_for_participant(&rig.participant_b)?,
        "test: refusing a stale union also blocked a fresh valid installation"
    );
    if matches!(change, Change::Writer) {
        let slot = rig.participant_b.db.lock().map_err(|_| "test: selected B owner")?;
        let db = slot.as_ref().ok_or("test: selected B writer absent")?;
        assert!(
            matches!(
                db.check_object_identity("after-union-validation", "union-race-manifest"),
                Err(ramflux_storage::StorageError::ObjectErased)
            ),
            "test: recomputation discarded B's intervening veto"
        );
        assert!(
            db.privacy_erasure_generation()? >= 29,
            "test: recomputed union reduced B's current privacy floor"
        );
    }
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}

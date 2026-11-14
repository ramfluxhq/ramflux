// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A's post-duplex deletion and B's installation writes preserve qualified ownership.
use super::*;
use ramflux_protocol::custody::pairing::local_dto::FullTailStatus;
const CHILD: &str = "race-child";
const HASH: &str = "race-dependency-manifest";
#[tokio::test(start_paused = true)]
async fn primary_transfer_full_source_delete_target_write_races_install() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let mut fixture = Box::pin(prepare_race()).await?;
    let b = fixture.target.account_db()?;
    assert!(
        b.full_transfer_dependency_present_for_test("race-shared-parent", HASH, CHILD, HASH)?,
        "test: A deletion erased B's independently retained dependency"
    );
    assert!(
        !b.full_transfer_dependency_present_for_test("race-a-parent", HASH, CHILD, HASH)?,
        "test: installed B lost A's authenticated tail absence"
    );
    for (wire, manifest) in [
        ("source-veto", "source-manifest"),
        ("target-veto", "target-manifest"),
        ("install-race-3", "install-race-manifest"),
    ] {
        assert!(
            matches!(
                b.check_object_identity(wire, manifest),
                Err(ramflux_storage::StorageError::ObjectErased)
            ),
            "test: delete/install/tail race dropped veto {wire}"
        );
    }
    // Applying source absences can create additional local erasure work. Its
    // monotonic generation must preserve at least the concurrent B floor.
    assert!(
        b.privacy_erasure_generation()? >= 13,
        "test: source tail reduced concurrent B privacy floor"
    );
    fixture.rig.primary.lock().await?;
    fixture.rig.secondary.lock().await?;
    Ok(())
}
async fn prepare_race() -> Result<Linked, Box<dyn std::error::Error>> {
    let fixture = Box::pin(open()).await?;
    let a = fixture.rig.source.client.account_db()?;
    seed(a, &["race-shared-parent", "race-a-parent"])?;
    seed(fixture.target.account_db()?, &["race-shared-parent"])?;
    assert_shared_dependency(&fixture.target, "before DATA")?;
    let mut fixture = Box::pin(run_data_in(fixture, false)).await?;
    assert_shared_dependency(&fixture.target, "after DATA")?;
    // The signed prepublication chain is immutable; these changes belong to J6's tail.
    let a = fixture.rig.source.client.account_db()?;
    // An absence removes only A's assertion. Retiring a transport payload also
    // creates a restrictive erasure fence, which must dominate both contributors.
    a.remove_full_transfer_dependency_for_test("race-shared-parent", HASH, CHILD, HASH)?;
    a.retire_transport_object("race-a-parent", HASH)?;
    assert_shared_dependency(&fixture.target, "after source deletion")?;
    fixture = Box::pin(install_in(fixture, 3)).await?;
    assert_shared_dependency(&fixture.target, "after G3 before explicit tail drive")?;
    Box::pin(merge(&mut fixture)).await?;
    Ok(fixture)
}

fn assert_shared_dependency(client: &crate::RamfluxClient, phase: &str) -> TestResult {
    assert!(
        client.account_db()?.full_transfer_dependency_present_for_test(
            "race-shared-parent",
            HASH,
            CHILD,
            HASH,
        )?,
        "test: B independent dependency lost {phase}"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn primary_transfer_full_linked_union_never_loses_veto() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(cold_vetoes())).await;
    hold.finish().await?;
    result
}
async fn cold_vetoes() -> TestResult {
    let mut fixture = Box::pin(prepare_race()).await?;
    let path = fixture.target.account_db()?.path.clone();
    let floor = fixture.target.account_db()?.privacy_erasure_generation()?;
    fixture.rig.primary.lock().await?;
    fixture.rig.secondary.lock().await?;
    *fixture.target = crate::RamfluxClient::new();
    fixture.target.open_account_index(&fixture.rig.participant_b.root)?;
    fixture
        .target
        .unlock_account(&fixture.rig.participant_b.account_id, b"component-recipient-passphrase")?;
    let db = fixture.target.account_db()?;
    assert_eq!(db.path, path, "test: original B credential reopened a pre-union generation");
    for (wire, manifest) in [
        ("source-veto", "source-manifest"),
        ("target-veto", "target-manifest"),
        ("install-race-1", "install-race-manifest"),
        ("install-race-2", "install-race-manifest"),
        ("install-race-3", "install-race-manifest"),
    ] {
        assert!(
            matches!(
                db.check_object_identity(wire, manifest),
                Err(ramflux_storage::StorageError::ObjectErased)
            ),
            "test: cold original-B generation revived vetoed object {wire}"
        );
    }
    assert_eq!(
        db.privacy_erasure_generation()?,
        floor,
        "test: cold union lost its exact committed privacy floor"
    );
    assert!(
        ordinary_session_admitted(&fixture.target, &fixture.rig.participant_b.account_id)?,
        "test: veto-preserving cold union lost native admission"
    );
    Ok(())
}

fn seed(db: &ramflux_storage::AccountDb, parents: &[&str]) -> TestResult {
    db.retain_object(CHILD, HASH, ramflux_storage::ObjectRetention::Imported)?;
    for parent in parents {
        db.retain_object(parent, HASH, ramflux_storage::ObjectRetention::OwnDeviceTransport)?;
        db.retain_transport_dependency(parent, HASH, CHILD, HASH)?;
    }
    Ok(())
}
pub(super) async fn merge(fixture: &mut Linked) -> TestResult {
    let source = resume_request(&fixture.rig.source.client)?;
    let target = resume_request(&fixture.target)?;
    for _ in 0..96 {
        step(fixture).await?;
        let Linked { rig, target: client, source_service, target_service, .. } = fixture;
        let a = drive(
            Box::pin(rig.primary.transfer_status(&source)),
            source_service,
            &rig.source.client,
            target_service,
            client,
        )
        .await?;
        let b = drive(
            Box::pin(rig.secondary.transfer_status(&target)),
            source_service,
            &rig.source.client,
            target_service,
            client,
        )
        .await?;
        let done = |reply: LocalResult| matches!(reply.outcome, Outcome::FullStatus { value } if value.tail_status == FullTailStatus::Merged);
        if done(a) && done(b) {
            return Ok(());
        }
    }
    Err("test: real source deletion/target writer race did not reach both tail acknowledgements"
        .into())
}

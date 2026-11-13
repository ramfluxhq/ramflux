// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native handoff keeps every original supported data row and A's original credential.
use super::*;
mod traffic;
type Rows = std::collections::BTreeMap<String, Vec<[u8; 32]>>;
const DATA: [&str; 9] = [
    "account_mac_bundle",
    "full_imported_mac_bundle",
    "object_erasure_fence",
    "object_identity_replacement",
    "object_segment_reference_veto",
    "object_erasure_lookup",
    "object_payload_dependency",
    "account_key_check",
    "runtime_account_identity",
];

#[tokio::test(start_paused = true)]
async fn primary_transfer_full_source_remains_secondary_with_all_data() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}

async fn run() -> TestResult {
    let mut saved = None;
    let (mut rig, mut source, mut target_client, mut target, request) =
        Box::pin(setup_with_source(|client, _| {
            saved = Some(capture(client)?);
            Ok(())
        }))
        .await?;
    let saved = saved.ok_or("test: original A data observation missing")?;
    let (path, before) = (&saved.path, &saved.rows);
    Box::pin(merge(&mut rig, &mut source, &target_client, &mut target, &request)).await?;
    let native = crate::custody::load_account(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        crate::custody::network_now()?,
    )?;
    let local = native.local_device_id()?.to_owned();
    assert_ne!(
        native.record().body.master_certificate.body.primary_device_ref.device_id,
        local,
        "test: native handoff retained A as primary"
    );
    assert!(
        native.record().body.devices.iter().any(|device| device.device_id == local),
        "test: handoff revoked A's ordinary device"
    );
    assert_eq!(native.primary_vault_ref(), "", "test: A retained primary management capability");
    assert_eq!(native.branch_vault_ref(), saved.branch, "test: source branch vault owner changed");
    let current = native
        .record()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == local)
        .ok_or("test: source device removed")?;
    assert_branch_retained(&saved.device, current)?;
    Box::pin(primary_operations(&rig, &mut target_client)).await?;
    assert_eq!(&rig.source.client.account_db()?.path, path, "test: A selected B's data generation");
    assert_rows(before, &rig.source.client.account_db()?.test_table_fingerprints(&[])?)?;
    let adoption = rig
        .source
        .client
        .account_db()?
        .pairing_adoption()?
        .ok_or("test: source adoption missing")?;
    assert_eq!(adoption.local_role, "secondary", "test: source adoption still authorizes primary");
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    drop(source);
    rig.source.client = crate::RamfluxClient::new();
    let reopened = reopen(&rig.participant_a, b"fresh-source-data")?;
    assert_eq!(
        &reopened.account_db()?.path,
        path,
        "test: original password reopened another generation"
    );
    assert_rows(before, &reopened.account_db()?.test_table_fingerprints(&[])?)?;
    assert!(
        reopened.account_db()?.privacy_erasure_generation()? >= 7,
        "test: source privacy floor moved backwards on demotion/reopen"
    );
    assert!(
        crate::custody::pairing::ordinary_session_admitted(
            &reopened,
            &rig.participant_a.account_id
        )?,
        "test: primary transfer revoked A's installed secondary admission"
    );
    traffic::both_branches(&rig)?;
    Ok(())
}

fn assert_branch_retained(
    before: &ramflux_protocol::custody::Device,
    after: &ramflux_protocol::custody::Device,
) -> TestResult {
    let old =
        before.branch_certificate.as_ref().ok_or("test: original source certificate missing")?;
    let new =
        after.branch_certificate.as_ref().ok_or("test: surviving source certificate missing")?;
    let mut body = new.body.clone();
    // A new primary reissues the certificate under its new master binding, preserving policy.
    body.master_certificate_hash.clone_from(&old.body.master_certificate_hash);
    body.cert_id.clone_from(&old.body.cert_id);
    assert_eq!(body, old.body, "test: handoff changed A's branch keys, capabilities or lease");
    let mut normalized = after.clone();
    normalized.branch_certificate.clone_from(&before.branch_certificate);
    assert_eq!(
        normalized, *before,
        "test: handoff changed source identity, epoch or revocation status"
    );
    Ok(())
}

fn assert_rows(before: &Rows, after: &Rows) -> TestResult {
    for table in DATA {
        let old = before.get(table).ok_or("test: original data family absent")?;
        let current = after.get(table).ok_or("test: source data family was removed")?;
        assert!(!old.is_empty(), "test: source preservation oracle was vacuous for {table}");
        for row in old {
            assert!(
                current.contains(row),
                "test: demotion discarded original source row in {table}"
            );
        }
    }
    Ok(())
}

struct Snapshot {
    path: std::path::PathBuf,
    rows: Rows,
    device: ramflux_protocol::custody::Device,
    branch: String,
}
fn capture(client: &crate::RamfluxClient) -> Result<Snapshot, Box<dyn std::error::Error>> {
    let db = client.account_db()?;
    db.seed_full_transfer_supported_state_for_test()?;
    let native = crate::custody::load_account(
        client.account_index()?.root(),
        &db.local_account_id,
        crate::custody::network_now()?,
    )?;
    let device = native
        .record()
        .body
        .devices
        .iter()
        .find(|device| Some(device.device_id.as_str()) == native.local_device_id().ok())
        .ok_or("test: source branch missing")?
        .clone();
    Ok(Snapshot {
        path: db.path.clone(),
        rows: db.test_table_fingerprints(&[])?,
        device,
        branch: native.branch_vault_ref().into(),
    })
}
async fn primary_operations(rig: &Rig, target: &mut crate::RamfluxClient) -> TestResult {
    let a = crate::custody::load_account(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        crate::custody::network_now()?,
    )?;
    assert!(
        matches!(
            a.group_primary(rig.participant_a.vault.as_ref()),
            Err(crate::SdkError::PairingCode("PrimaryRequired"))
        ),
        "test: former primary retained group management permission"
    );
    let b = crate::custody::load_account(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
        crate::custody::network_now()?,
    )?;
    let key = b.group_primary(rig.participant_b.vault.as_ref())?;
    target.initialize_born_v3_branch(b.local_device_id()?, rig.participant_b.vault.clone()).await?;
    target.shared_group_create_with_primary(
        "after-primary-handoff",
        "after-primary-handoff-thread",
        Some("New primary".into()),
        "target-handoff",
        Some(&key),
    )?;
    assert!(
        target.account_db()?.next_pairing_own_sync()?.is_none(),
        "test: full transfer scheduled redundant enrollment history export"
    );
    Ok(())
}

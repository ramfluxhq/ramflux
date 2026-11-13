// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Literal transcript, explicit-null and stable-state transfer controls.
use super::*;
use crate::custody::{DeviceRef, Envelope as Signed, framed_hash};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn d(n: u8) -> String {
    crate::encode_base64url([n; 32])
}
fn policy() -> Signed<ReachPolicy> {
    Signed {
        signature: crate::encode_base64url([9; 64]),
        body: ReachPolicy {
            version: 1,
            operation_id: d(1),
            account_anchor: d(2),
            home_head_hash: d(3),
            expected_revision: 0,
            revision: 1,
            mode: ReachMode::ContactsOnly,
            authority_head_hash: d(4),
            master_certificate_hash: d(5),
            actor: DeviceRef { account_anchor: d(2), device_id: "phone".into(), device_epoch: 1 },
            issued_at: 100,
            expires_at: 400,
        },
    }
}
fn records() -> Vec<StateRecord> {
    vec![
        StateRecord::AdmissionMeta { revision: 0, last_update: None },
        StateRecord::Policy { revision: 1, update: policy() },
    ]
}
fn manifest(pages: &[StatePage]) -> Result<StateManifest, Box<dyn std::error::Error>> {
    Ok(StateManifest {
        version: 1,
        account_anchor: d(2),
        requesting_device: policy().body.actor,
        home_head_hash: d(3),
        authority_head_hash: d(4),
        revision: 1,
        policy_revision: 1,
        admission_revision: 0,
        snapshot_id: pages.first().map_or_else(|| d(10), |p| p.snapshot_id.clone()),
        page_count: u64::try_from(pages.len())?,
        record_count: 2,
        pages_hash: framed_hash(STATE_PAGES_DOMAIN, &pages)?,
        state_hash: state_hash(&d(2), 1, 1, 0, &records())?,
        issued_at: 200,
        expires_at: 260,
    })
}
#[test]
fn cr_state_identity_survives_transport_renewal_but_detects_actual_record_changes() -> TestResult {
    let first = vec![StatePage { version: 1, snapshot_id: d(10), page: 0, records: records() }];
    let m1 = manifest(&first)?;
    assert_eq!(
        verify_pages(&m1, &first)?,
        records(),
        "a complete signed-state transcript must round-trip"
    );
    let mut second = Vec::new();
    for (index, record) in records().into_iter().enumerate() {
        second.push(StatePage {
            version: 1,
            snapshot_id: d(11),
            page: u64::try_from(index)?,
            records: vec![record],
        });
    }
    let mut m2 = manifest(&second)?;
    m2.requesting_device.device_id = "sibling".into();
    m2.issued_at = 201;
    m2.expires_at = 261;
    assert_eq!(
        m1.state_hash, m2.state_hash,
        "transport audience, packing and lease cannot change content identity"
    );
    assert_ne!(
        m1.pages_hash, m2.pages_hash,
        "exact page transfer integrity must include changed packing and snapshot ids"
    );
    assert_eq!(
        verify_pages(&m2, &second)?,
        records(),
        "fresh transport must authenticate identical complete state"
    );
    let mut tampered = second.clone();
    tampered.first_mut().ok_or("first page")?.records.clear();
    assert!(
        verify_pages(&m2, &tampered).is_err(),
        "altered pages must fail the exact transfer hash"
    );
    let mut changed = records();
    if let Some(StateRecord::Policy { update, .. }) = changed.get_mut(1) {
        update.body.mode = ReachMode::Open;
    }
    assert_ne!(
        state_hash(&d(2), 1, 1, 0, &changed)?,
        m1.state_hash,
        "a real policy change cannot retain the same state hash"
    );
    let records = records();
    let content = serde_json::json!({"version":1,"account_anchor":d(2),"revision":1,"policy_revision":1,"admission_revision":0,"records":records});
    let mut independent = blake3::Hasher::new();
    independent.update(b"ramflux.contact.reach_state_content.v1\0");
    independent.update(&crate::canonical_json_bytes(&content)?);
    assert_eq!(
        crate::encode_base64url(independent.finalize().as_bytes()),
        m1.state_hash,
        "state content domain must include a literal NUL separator"
    );
    Ok(())
}
#[test]
fn cr_closed_admission_rejects_missing_nulls_duplicates_and_invented_permissions() -> TestResult {
    let p = policy();
    p.body.validate()?;
    let a = Admission {
        version: 2,
        operation_id: d(6),
        recipient_root: d(2),
        home_head_hash: d(3),
        expected_revision: 0,
        subject: Subject::Friendship { root: d(7) },
        decision: Decision::Decline,
        permissions: None,
        grant_until: None,
        authority_head_hash: d(4),
        master_certificate_hash: d(5),
        actor: p.body.actor,
        notice_hash: None,
        evidence_hash: None,
        issued_at: 100,
        expires_at: 400,
    };
    a.validate()?;
    let bytes = crate::canonical_json_bytes(&a)?;
    assert_eq!(
        decode::<Admission>(&bytes, 4096)?,
        a,
        "explicit null decision fields must round-trip"
    );
    let mut value = serde_json::to_value(&a)?;
    value.as_object_mut().ok_or("object")?.remove("permissions");
    assert!(
        decode::<Admission>(&serde_json::to_vec(&value)?, 4096).is_err(),
        "missing nullable permission cannot become implicit null"
    );
    let duplicate = bytes.iter().copied().skip(1).collect::<Vec<_>>();
    let mut bytes = b"{\"version\":2,".to_vec();
    bytes.extend(duplicate);
    assert!(
        decode::<Admission>(&bytes, 4096).is_err(),
        "duplicate version must be rejected from original bytes"
    );
    let mut value = serde_json::to_value(Permissions::UNACCEPTED)?;
    value.as_object_mut().ok_or("permissions")?.insert("reply_count".into(), serde_json::json!(3));
    assert!(
        decode::<Permissions>(&serde_json::to_vec(&value)?, 4096).is_err(),
        "closed permissions cannot acquire an unaudited reply counter"
    );
    Ok(())
}

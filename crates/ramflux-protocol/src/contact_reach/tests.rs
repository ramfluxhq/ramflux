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
        provenance_hash: d(20),
        provenance_count: 1,
        provenance_bytes: 1000,
        issued_at: 200,
        expires_at: 260,
    })
}
#[test]
fn cr_state_identity_survives_transport_renewal_but_detects_actual_record_changes() -> TestResult {
    let first = vec![StatePage {
        version: 1,
        snapshot_id: d(10),
        page: 0,
        records: records(),
        signers: references(&records())?,
    }];
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
            signers: references(std::slice::from_ref(&record))?,
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

#[test]
fn cr_session_query_and_closed_error_metadata_are_correlated() -> TestResult {
    let query = Query {
        version: 1,
        source_node: "a.example".into(),
        target_node: "b.example".into(),
        account_anchor: d(2),
        card_hash: None,
        nonce: d(3),
        base: None,
        device_ref: None,
    };
    let mut request = Request {
        request_id: d(4),
        session_id: "session".into(),
        session_generation: 1,
        remaining_ms: 1000,
        operation: Operation::Query { query: Box::new(query) },
    };
    assert!(request.validate().is_err(), "a query nonce must equal the outer request id");
    request.request_id = d(3);
    request.validate()?;
    let mut response = Response {
        request_id: request.request_id.clone(),
        session_id: request.session_id.clone(),
        session_generation: 2,
        result: OperationResult::Error {
            reason: Reason::ForeignRateLimited,
            retry_after_ms: Some(1000),
            current_revision: None,
        },
    };
    assert!(
        request.validate_response(&response).is_err(),
        "another session generation cannot complete this operation"
    );
    response.session_generation = 1;
    request.validate_response(&response)?;
    response.result = OperationResult::Error {
        reason: Reason::ForeignReadRefused,
        retry_after_ms: Some(1000),
        current_revision: None,
    };
    assert!(
        request.validate_response(&response).is_err(),
        "a generic private denial cannot reveal a retry hint"
    );
    response.result = OperationResult::Error {
        reason: Reason::ReachRevisionConflict,
        retry_after_ms: None,
        current_revision: None,
    };
    assert!(
        request.validate_response(&response).is_err(),
        "CAS conflicts must carry the current revision"
    );
    response.result = OperationResult::Error {
        reason: Reason::ReachRevisionConflict,
        retry_after_ms: None,
        current_revision: Some(7),
    };
    request.validate_response(&response)?;
    Ok(())
}

#[test]
fn cr_original_nested_document_keeps_sixteen_level_budget() -> TestResult {
    let at_limit = format!("{}0{}", "[".repeat(16), "]".repeat(16));
    let value: serde_json::Value = crate::parse_i_json(at_limit.as_bytes())?;
    original_document(&value, at_limit.len())?;
    assert!(
        original_document(&value, at_limit.len() - 1).is_err(),
        "a nested original document must retain its individual byte limit"
    );
    let too_deep = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    let value: serde_json::Value = decode(too_deep.as_bytes(), 128)?;
    assert!(
        original_document(&value, 128).is_err(),
        "the new outer depth of 32 must not silently raise original document depth from 16"
    );
    original_document(&serde_json::json!({"text":"[{{\\\"}]"}), 128)?;
    Ok(())
}

#[test]
fn cr_discovery_cannot_advertise_an_incomplete_reach_profile() {
    let base = vec![
        "opaque_delivery".into(),
        CAPABILITY.into(),
        EPHEMERAL_CAPABILITY.into(),
        DIRECTORY_CAPABILITY.into(),
    ];
    let advertised = advertised_capabilities(&base);
    assert_eq!(
        advertised.contains(&CAPABILITY.into()),
        enabled(),
        "configured strings cannot advertise reach before common release"
    );
    assert_eq!(
        advertised.contains(&EPHEMERAL_CAPABILITY.into()),
        enabled(),
        "volatile federation must have the identical local/foreign common release gate"
    );
    assert_eq!(
        advertised.contains(&DIRECTORY_CAPABILITY.into()),
        enabled() && directory_enabled(),
        "directory additionally requires its independent provisioned profile"
    );
    assert!(
        advertised.contains(&"opaque_delivery".into()),
        "unrelated existing capabilities must survive"
    );
}

#[test]
fn cr_peer_query_literal_carrier_excludes_owner_credentials() -> TestResult {
    const GOLDEN: &[u8] = br#"{"kind":"query","query":{"account_anchor":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","base":null,"card_hash":null,"device_ref":null,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source_node":"source.example","target_node":"target.example","version":1},"remaining_ms":10000,"request_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
    let request: PeerQueryRequest = decode(GOLDEN, 8192)?;
    request.validate()?;
    assert_eq!(
        crate::canonical_json_bytes(&request)?,
        GOLDEN,
        "the internal, snapshot and public peer hops share this exact closed carrier"
    );
    let mut changed = request.clone();
    changed.query.nonce = d(99);
    assert!(
        changed.validate().is_err(),
        "every peer hop retains the original request nonce binding"
    );
    let mut value: serde_json::Value = crate::parse_i_json(GOLDEN)?;
    value.as_object_mut().ok_or("query carrier")?.insert("admin_token".into(), "legacy".into());
    assert!(
        decode::<PeerQueryRequest>(&serde_json::to_vec(&value)?, 8192).is_err(),
        "no administration or session credential may leave the caller's home"
    );
    value.as_object_mut().ok_or("query carrier")?.remove("admin_token");
    value
        .get_mut("query")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("query")?
        .remove("card_hash");
    assert!(
        decode::<PeerQueryRequest>(&serde_json::to_vec(&value)?, 8192).is_err(),
        "card correlation remains explicit null without becoming a possession credential"
    );
    Ok(())
}

fn references(records: &[StateRecord]) -> Result<Vec<SignerReference>, crate::ProtocolError> {
    let mut out = records
        .iter()
        .map(record_signers)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    for reference in &mut out {
        reference.proof_hash = d(21);
    }
    out.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
    out.dedup();
    Ok(out)
}

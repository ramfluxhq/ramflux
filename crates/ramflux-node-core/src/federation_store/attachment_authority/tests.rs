// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! N6a: capability admission, pin history (M8), record encoding (L1) and capacity (L2).
use super::*;
use crate::federation_attachment::{
    AttachmentAuthorityBook, PeerRenewalFacts, PinAnswer, admit_peer_renewal,
};
use crate::relay::attachment::RenewalRefusal;
use crate::{FederationServerRecord, sign_federation_server_record_with_seed};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_760_000_100;

fn key(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn authority(generation: u64, n: u8) -> FederationAttachmentAuthority {
    FederationAttachmentAuthority { generation, signing_public_key: key(n) }
}
fn path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "rf-fed-authority-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ))
}
fn record(authority: Option<FederationAttachmentAuthority>) -> FederationServerRecord {
    FederationServerRecord {
        schema: "ramflux.well_known_server.v1".into(),
        node_id: "node-a".into(),
        node_public_key: ramflux_crypto::public_key_base64url_from_seed([7; 32]),
        node_ca_cert_pem: "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----".into(),
        node_endpoint: "https://a.example".into(),
        protocol_versions: vec!["v1".into()],
        transport_backends: vec!["quic_quinn".into()],
        node_capabilities: vec!["opaque_delivery".into()],
        node_policy_hash: "policy".into(),
        updated_at: NOW,
        expires_at: NOW + 86_400,
        attachment_authority: authority,
        signature: String::new(),
    }
}
fn facts() -> PeerRenewalFacts<'static> {
    PeerRenewalFacts {
        tls_node: "node-b",
        home_node: "node-b",
        admitted: true,
        advertised: true,
        negotiated: true,
    }
}

#[test]
fn large_federation_renewal_requires_negotiated_capability() {
    assert_eq!(admit_peer_renewal(&facts()), Ok(()));
    // One predicate false at a time, from an otherwise fully valid state.
    let rows = [
        (PeerRenewalFacts { advertised: false, ..facts() }, RenewalRefusal::CapabilityUnavailable),
        (PeerRenewalFacts { admitted: false, ..facts() }, RenewalRefusal::SourceUnknown),
        (PeerRenewalFacts { negotiated: false, ..facts() }, RenewalRefusal::CapabilityUnavailable),
        // C's request claiming home B over C's own TLS identity.
        (PeerRenewalFacts { tls_node: "node-c", ..facts() }, RenewalRefusal::HomeMismatch),
        (PeerRenewalFacts { home_node: "node-c", ..facts() }, RenewalRefusal::HomeMismatch),
    ];
    for (row, expected) in rows {
        assert_eq!(admit_peer_renewal(&row), Err(expected), "{row:?}");
    }
}

#[test]
fn pin_history_survives_withdrawal_and_restart_and_refuses_rollback_and_substitution() -> TestResult
{
    let p = path("history");
    let book = AttachmentAuthorityBook::new();
    let store = FederationRedbStore::open(&p)?;
    let g4 = authority(4, 4);
    assert!(
        matches!(book.adopt(&store, "node-a", Some(&g4), true, NOW)?, AuthorityAdoption::Available(pin) if pin.generation == 4)
    );
    assert!(matches!(book.answer("node-a"), PinAnswer::Available { .. }));
    // Withdrawal: field removed. Unavailable, history kept.
    assert_eq!(
        book.adopt(&store, "node-a", None, true, NOW + 1)?,
        AuthorityAdoption::Unavailable(Withdrawn::Absent)
    );
    assert_eq!(book.answer("node-a"), PinAnswer::Unavailable);
    // Capability not negotiated while the field is present is also a withdrawal.
    assert_eq!(
        book.adopt(&store, "node-a", Some(&g4), false, NOW + 1)?,
        AuthorityAdoption::Unavailable(Withdrawn::Absent)
    );
    assert_eq!(store.attachment_authority_history("node-a")?.map(|h| h.max_generation), Some(4));
    drop(store);
    // Restart, then a fresh signed g3 record: rollback, unavailable, history still g4.
    let store = FederationRedbStore::open(&p)?;
    let book = AttachmentAuthorityBook::new();
    assert_eq!(
        book.adopt(&store, "node-a", Some(&authority(3, 3)), true, NOW + 2)?,
        AuthorityAdoption::Unavailable(Withdrawn::Rollback)
    );
    assert_eq!(book.answer("node-a"), PinAnswer::Unavailable);
    let h = store.attachment_authority_history("node-a")?.ok_or("row")?;
    assert_eq!((h.max_generation, h.key_at_max.as_str()), (4, key(4).as_str()));
    // Equal generation with a different key is a substitution; history unchanged.
    assert_eq!(
        book.adopt(&store, "node-a", Some(&authority(4, 9)), true, NOW + 3)?,
        AuthorityAdoption::Unavailable(Withdrawn::Substitution)
    );
    assert_eq!(store.attachment_authority_history("node-a")?, Some(h.clone()));
    // Re-introducing g4 with the same key is available again.
    assert!(matches!(
        book.adopt(&store, "node-a", Some(&g4), true, NOW + 4)?,
        AuthorityAdoption::Available(pin) if pin.generation == 4
    ));
    // Positive: g5 with a new key becomes the history.
    let g5 = authority(5, 5);
    assert!(matches!(
        book.adopt(&store, "node-a", Some(&g5), true, NOW + 5)?,
        AuthorityAdoption::Available(pin) if pin.generation == 5 && pin.key == [5; 32]
    ));
    let h = store.attachment_authority_history("node-a")?.ok_or("row")?;
    assert_eq!((h.max_generation, h.key_at_max.as_str()), (5, key(5).as_str()));
    assert_eq!(store.attachment_authority_nodes()?, 1);
    Ok(())
}

#[test]
fn a_pin_for_a_never_adopted_node_is_unavailable() {
    assert_eq!(AttachmentAuthorityBook::new().answer("node-z"), PinAnswer::Unavailable);
    assert_eq!(PinAnswer::Unavailable.into_pin(), Err(RenewalRefusal::CapabilityUnavailable));
    assert_eq!(PinAnswer::SourceUnknown.into_pin(), Err(RenewalRefusal::SourceUnknown));
}

#[test]
fn history_capacity_is_exactly_4096_nodes_and_never_refunded() -> TestResult {
    assert_eq!(MAX_AUTHORITY_NODES, 4096);
    let p = path("capacity");
    let store = FederationRedbStore::open(&p)?;
    for n in 0..MAX_AUTHORITY_NODES {
        store.adopt_attachment_authority(
            &format!("node-{n}"),
            Some(&authority(1, 1)),
            true,
            NOW,
        )?;
    }
    assert_eq!(store.attachment_authority_nodes()?, 4096);
    // Node 4097: typed refusal, no row, counter unchanged.
    let refused = store.adopt_attachment_authority("node-extra", Some(&authority(1, 1)), true, NOW);
    assert!(matches!(refused, Err(NodeCoreError::AttachmentAuthorityHistoryCapacity)));
    assert_eq!(store.attachment_authority_history("node-extra")?, None);
    assert_eq!(store.attachment_authority_nodes()?, 4096);
    // An existing node's higher generation needs no slot.
    assert!(matches!(
        store.adopt_attachment_authority("node-7", Some(&authority(2, 2)), true, NOW + 1)?,
        AuthorityAdoption::Available(pin) if pin.generation == 2
    ));
    // Withdrawal and restart keep every row; node 4097 is still refused.
    store.adopt_attachment_authority("node-7", None, true, NOW + 2)?;
    drop(store);
    let store = FederationRedbStore::open(&p)?;
    assert_eq!(store.attachment_authority_nodes()?, 4096);
    assert!(matches!(
        store.adopt_attachment_authority("node-extra", Some(&authority(1, 1)), true, NOW + 3),
        Err(NodeCoreError::AttachmentAuthorityHistoryCapacity)
    ));
    // The router sees the refused node as SourceUnknown, not as a withdrawn pin.
    let book = AttachmentAuthorityBook::new();
    assert!(book.adopt(&store, "node-extra", Some(&authority(1, 1)), true, NOW + 4).is_err());
    assert_eq!(book.answer("node-extra"), PinAnswer::SourceUnknown);
    Ok(())
}

#[test]
fn open_fails_closed_when_the_counter_and_the_rows_disagree() -> TestResult {
    for delta in [1i64, -1] {
        let p = path("corrupt");
        let store = FederationRedbStore::open(&p)?;
        store.adopt_attachment_authority("node-a", Some(&authority(1, 1)), true, NOW)?;
        {
            let tx = store.db.begin_write()?;
            tx.open_table(COUNTER)?.insert(COUNTER_KEY, 1u64.saturating_add_signed(delta))?;
            tx.commit()?;
        }
        drop(store);
        assert!(FederationRedbStore::open(&p).is_err(), "delta {delta}");
    }
    Ok(())
}

fn signed(authority: Option<FederationAttachmentAuthority>) -> TestResult<FederationServerRecord> {
    let mut r = record(authority);
    sign_federation_server_record_with_seed(&mut r, [7; 32])?;
    Ok(r)
}

#[test]
fn absent_field_keeps_the_pre_existing_bytes_and_never_emits_null() -> TestResult {
    let r = signed(None)?;
    let json = serde_json::to_string(&r)?;
    assert!(!json.contains("attachment_authority"), "{json}");
    assert!(!json.contains("null"), "{json}");
    // The canonical signed bytes are the pre-change field set, nothing more.
    let bytes = String::from_utf8(ramflux_protocol::signed_bytes(&r)?)?;
    assert_eq!(
        bytes,
        concat!(
            r#"{"expires_at":1760086500,"node_ca_cert_pem":"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----","#,
            r#""node_capabilities":["opaque_delivery"],"node_endpoint":"https://a.example","#,
            r#""node_id":"node-a","node_policy_hash":"policy","#,
            r#""node_public_key":""#,
        )
        .to_owned()
            + &ramflux_crypto::public_key_base64url_from_seed([7; 32])
            + r#"","protocol_versions":["v1"],"schema":"ramflux.well_known_server.v1","#
            + r#""transport_backends":["quic_quinn"],"updated_at":1760000100}"#
    );
    crate::verify_federation_server_record(&r, NOW)?;
    let round: FederationServerRecord = serde_json::from_str(&json)?;
    assert_eq!(round, r);
    Ok(())
}

#[test]
fn present_field_is_signed_and_tamper_or_noncanonical_input_is_refused() -> TestResult {
    let r = signed(Some(authority(4, 4)))?;
    let json = serde_json::to_string(&r)?;
    let expected =
        format!(r#""attachment_authority":{{"generation":4,"signing_public_key":"{}"}}"#, key(4));
    assert!(json.contains(&expected), "{json}");
    assert!(String::from_utf8(ramflux_protocol::signed_bytes(&r)?)?.contains(&expected));
    crate::verify_federation_server_record(&r, NOW)?;
    // Tampering with either member after signing breaks the node signature.
    for (generation, k) in [(5, 4), (4, 5)] {
        let mut t = r.clone();
        t.attachment_authority = Some(authority(generation, k));
        assert!(crate::verify_federation_server_record(&t, NOW).is_err());
    }
    // Decoding refuses every non-canonical form.
    let base: serde_json::Value = serde_json::to_value(&r)?;
    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("null", serde_json::Value::Null),
        ("unknown member", serde_json::json!({"generation":4,"signing_public_key":key(4),"x":1})),
        ("42-char key", serde_json::json!({"generation":4,"signing_public_key":&key(4)[..42]})),
        (
            "44-char key",
            serde_json::json!({"generation":4,"signing_public_key":format!("{}A", key(4))}),
        ),
        ("generation 0", serde_json::json!({"generation":0,"signing_public_key":key(4)})),
        (
            "generation 2^53",
            serde_json::json!({"generation":9_007_199_254_740_992u64,"signing_public_key":key(4)}),
        ),
        ("non-base64 key", serde_json::json!({"generation":4,"signing_public_key":"!".repeat(43)})),
    ];
    for (name, value) in cases {
        let mut v = base.clone();
        v["attachment_authority"] = value;
        assert!(serde_json::from_value::<FederationServerRecord>(v).is_err(), "{name}");
    }
    // Inclusive generation bounds are accepted at both ends.
    for generation in [1u64, 9_007_199_254_740_991] {
        let mut v = base.clone();
        v["attachment_authority"] =
            serde_json::json!({"generation":generation,"signing_public_key":key(4)});
        assert!(serde_json::from_value::<FederationServerRecord>(v).is_ok(), "{generation}");
    }
    Ok(())
}

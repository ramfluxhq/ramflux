// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! N6a: capability admission, pin history (M8), record encoding (L1) and capacity (L2),
//! driven through fresh signed records and the node's real negotiated-capability state.
use super::*;
use crate::federation_attachment::{
    AttachmentAuthorityBook, PeerRenewalFacts, PinAnswer, admit_peer_renewal,
};
use crate::relay::attachment::RenewalRefusal;
use crate::{
    ATTACHMENT_RENEWAL_CAPABILITY, FederationPeerRoute, FederationServerRecord,
    FederationTrustState, FederationTrustStatus, sign_federation_server_record_with_seed,
};
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_760_000_100;
const NODE: &str = "node-a";

const ABSENT_JSON: &str = r#"{"schema":"ramflux.well_known_server.v1","node_id":"node-a","node_public_key":"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw","node_ca_cert_pem":"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----","node_endpoint":"https://a.example","protocol_versions":["v1"],"transport_backends":["quic_quinn"],"node_capabilities":["opaque_delivery"],"node_policy_hash":"policy","updated_at":1760000100,"expires_at":1760086500,"signature":"SXIa2dC8GKKeVePvrsHzo8y48aG0NwMnyJGU7zYvCeGLOphWHFQlZC4uJGuVQEzrauctVbGVHPafivWoJr80DQ"}"#;
const ABSENT_SIGNED: &str = r#"{"expires_at":1760086500,"node_ca_cert_pem":"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----","node_capabilities":["opaque_delivery"],"node_endpoint":"https://a.example","node_id":"node-a","node_policy_hash":"policy","node_public_key":"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw","protocol_versions":["v1"],"schema":"ramflux.well_known_server.v1","transport_backends":["quic_quinn"],"updated_at":1760000100}"#;
const PRESENT_JSON: &str = r#"{"schema":"ramflux.well_known_server.v1","node_id":"node-a","node_public_key":"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw","node_ca_cert_pem":"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----","node_endpoint":"https://a.example","protocol_versions":["v1"],"transport_backends":["quic_quinn"],"node_capabilities":["opaque_delivery"],"node_policy_hash":"policy","updated_at":1760000100,"expires_at":1760086500,"attachment_authority":{"generation":4,"signing_public_key":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"},"signature":"IiHhS4zPJw9O4ciz0oM3AQViZNq-m9pJku2NPah9dt4uAYzu-01M0d_NQtdP74S7qXDACpRa72ZrXy48YMlHDQ"}"#;
const PRESENT_SIGNED: &str = r#"{"attachment_authority":{"generation":4,"signing_public_key":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"},"expires_at":1760086500,"node_ca_cert_pem":"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----","node_capabilities":["opaque_delivery"],"node_endpoint":"https://a.example","node_id":"node-a","node_policy_hash":"policy","node_public_key":"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw","protocol_versions":["v1"],"schema":"ramflux.well_known_server.v1","transport_backends":["quic_quinn"],"updated_at":1760000100}"#;

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
        node_id: NODE.into(),
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
/// A record that also lists `attachment-renewal.v1` in its own capabilities.
fn signed_adv(
    authority: Option<FederationAttachmentAuthority>,
) -> TestResult<FederationServerRecord> {
    let mut r = record(authority);
    r.node_capabilities.push(ATTACHMENT_RENEWAL_CAPABILITY.to_owned());
    sign_federation_server_record_with_seed(&mut r, [7; 32])?;
    Ok(r)
}
fn signed(authority: Option<FederationAttachmentAuthority>) -> TestResult<FederationServerRecord> {
    let mut r = record(authority);
    sign_federation_server_record_with_seed(&mut r, [7; 32])?;
    Ok(r)
}
/// The node's trust state: the route's status, and whether `attachment-renewal.v1` was
/// actually negotiated (an advertisement in a record is not part of this state).
fn state(status: FederationTrustStatus, negotiated: bool) -> FederationTrustState {
    let mut s = FederationTrustState::new();
    s.routes_by_node.insert(
        NODE.into(),
        FederationPeerRoute {
            node_id: NODE.into(),
            endpoint: "https://a.example".into(),
            node_public_key_hash: "h".into(),
            node_capabilities: vec![],
            trust_status: status,
            updated_at: NOW,
            expires_at: NOW + 30 * 86_400,
            route_update_proof_hash: "p".into(),
        },
    );
    if negotiated {
        s.negotiated_capabilities_by_node
            .insert(NODE.into(), BTreeSet::from([ATTACHMENT_RENEWAL_CAPABILITY.to_owned()]));
    }
    s
}
fn active(negotiated: bool) -> FederationTrustState {
    state(FederationTrustStatus::Active, negotiated)
}
fn gen_of(adoption: AuthorityAdoption) -> Option<u64> {
    match adoption {
        AuthorityAdoption::Available(pin) => Some(pin.generation),
        AuthorityAdoption::Unavailable(_) => None,
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
        // C's request claiming home B over C's own TLS identity, and the mirror image.
        (PeerRenewalFacts { tls_node: "node-c", ..facts() }, RenewalRefusal::HomeMismatch),
        (PeerRenewalFacts { home_node: "node-c", ..facts() }, RenewalRefusal::HomeMismatch),
    ];
    for (row, expected) in rows {
        assert_eq!(admit_peer_renewal(&row), Err(expected), "{row:?}");
    }
}

#[test]
fn fresh_signed_records_drive_history_through_withdrawal_restart_and_peer_removal() -> TestResult {
    let p = path("history");
    let store = FederationRedbStore::open(&p)?;
    let book = AttachmentAuthorityBook::new();
    let live = active(true);
    // A fresh signed g4 record is verified, adopted and published.
    let g4 = signed_adv(Some(authority(4, 4)))?;
    assert_eq!(gen_of(book.adopt_record(&store, &live, &g4, NOW)?), Some(4));
    assert!(
        matches!(book.answer(&store, &live, NODE, NOW), PinAnswer::Available { pin } if pin.generation == 4 && pin.key == [4; 32])
    );
    // Peer removal: the route is revoked, so the node is no longer a source at all, while
    // the history keeps its row.
    let removed = state(FederationTrustStatus::Revoked, true);
    assert_eq!(book.answer(&store, &removed, NODE, NOW), PinAnswer::SourceUnknown);
    assert_eq!(store.attachment_authority_history(NODE)?.map(|h| h.max_generation), Some(4));
    // Withdrawal: a fresh record without the field. Unavailable, history kept.
    let none = signed(None)?;
    assert_eq!(
        book.adopt_record(&store, &live, &none, NOW)?,
        AuthorityAdoption::Unavailable(Withdrawn::Absent)
    );
    assert_eq!(book.answer(&store, &live, NODE, NOW), PinAnswer::Unavailable);
    // The field present but the capability not negotiated is the same withdrawal.
    assert_eq!(
        book.adopt_record(&store, &active(false), &g4, NOW)?,
        AuthorityAdoption::Unavailable(Withdrawn::Absent)
    );
    assert_eq!(store.attachment_authority_history(NODE)?.map(|h| h.max_generation), Some(4));
    drop(store);
    // Restart: a fresh signed g3 record is a rollback; history stays g4.
    let store = FederationRedbStore::open(&p)?;
    let book = AttachmentAuthorityBook::new();
    let g3 = signed_adv(Some(authority(3, 3)))?;
    assert_eq!(
        book.adopt_record(&store, &live, &g3, NOW)?,
        AuthorityAdoption::Unavailable(Withdrawn::Rollback)
    );
    assert_eq!(book.answer(&store, &live, NODE, NOW), PinAnswer::Unavailable);
    let h = store.attachment_authority_history(NODE)?.ok_or("row")?;
    assert_eq!((h.max_generation, h.key_at_max.as_str()), (4, key(4).as_str()));
    // Equal generation, different key: substitution, history unchanged.
    let swapped = signed_adv(Some(authority(4, 9)))?;
    assert_eq!(
        book.adopt_record(&store, &live, &swapped, NOW)?,
        AuthorityAdoption::Unavailable(Withdrawn::Substitution)
    );
    assert_eq!(store.attachment_authority_history(NODE)?, Some(h));
    // Re-introducing g4 with the same key is available; g5 with a new key is the new history.
    assert_eq!(gen_of(book.adopt_record(&store, &live, &g4, NOW)?), Some(4));
    let g5 = signed_adv(Some(authority(5, 5)))?;
    assert_eq!(gen_of(book.adopt_record(&store, &live, &g5, NOW)?), Some(5));
    let h = store.attachment_authority_history(NODE)?.ok_or("row")?;
    assert_eq!((h.max_generation, h.key_at_max.as_str()), (5, key(5).as_str()));
    assert_eq!(store.attachment_authority_nodes()?, 1);
    Ok(())
}

#[test]
fn records_that_fail_verification_are_refused_with_the_exact_error_and_change_nothing() -> TestResult
{
    let store = FederationRedbStore::open(path("verify"))?;
    let book = AttachmentAuthorityBook::new();
    let live = active(true);
    assert_eq!(
        gen_of(book.adopt_record(&store, &live, &signed_adv(Some(authority(4, 4)))?, NOW)?),
        Some(4)
    );
    // Tampering with either member after signing breaks the node signature.
    for (generation, k) in [(5, 4), (4, 5)] {
        let mut t = signed_adv(Some(authority(4, 4)))?;
        t.attachment_authority = Some(authority(generation, k));
        let out = book.adopt_record(&store, &live, &t, NOW);
        assert!(
            matches!(&out, Err(NodeCoreError::ItestHttp(m)) if m == "ed25519 verification failed"),
            "{out:?}"
        );
    }
    // A stale record is refused on freshness.
    let mut old = signed(None)?;
    old.updated_at = NOW - 100 * 86_400;
    old.expires_at = old.updated_at + 10;
    let out = book.adopt_record(&store, &live, &old, NOW);
    assert!(
        matches!(&out, Err(NodeCoreError::ItestHttp(m)) if m == "signed request expired"),
        "{out:?}"
    );
    // Nothing above touched the published pin or the history.
    assert!(
        matches!(book.answer(&store, &live, NODE, NOW), PinAnswer::Available { pin } if pin.generation == 4)
    );
    assert_eq!(store.attachment_authority_history(NODE)?.map(|h| h.max_generation), Some(4));
    Ok(())
}

#[test]
fn a_pin_needs_admission_and_a_negotiated_capability_at_every_lookup() -> TestResult {
    let store = FederationRedbStore::open(path("lookup"))?;
    let book = AttachmentAuthorityBook::new();
    // Never adopted: unadmitted is SourceUnknown, admitted is Unavailable.
    assert_eq!(
        book.answer(&store, &state(FederationTrustStatus::Revoked, true), "node-z", NOW),
        PinAnswer::SourceUnknown
    );
    let g4 = signed_adv(Some(authority(4, 4)))?;
    assert_eq!(gen_of(book.adopt_record(&store, &active(true), &g4, NOW)?), Some(4));
    // Published, then the capability drops out of the negotiated set: unavailable at lookup
    // even though the record still advertises it and the pin is still in the book.
    assert_eq!(book.answer(&store, &active(false), NODE, NOW), PinAnswer::Unavailable);
    assert!(matches!(book.answer(&store, &active(true), NODE, NOW), PinAnswer::Available { .. }));
    // Suspended and expired routes are not admitted either.
    assert_eq!(
        book.answer(&store, &state(FederationTrustStatus::Suspended, true), NODE, NOW),
        PinAnswer::SourceUnknown
    );
    assert_eq!(
        book.answer(&store, &active(true), NODE, NOW + 31 * 86_400),
        PinAnswer::SourceUnknown
    );
    // The wire mapping used by the router.
    assert_eq!(PinAnswer::Unavailable.into_pin(), Err(RenewalRefusal::CapabilityUnavailable));
    assert_eq!(PinAnswer::SourceUnknown.into_pin(), Err(RenewalRefusal::SourceUnknown));
    Ok(())
}

#[test]
fn adoption_holds_the_publication_lock_through_the_history_write() -> TestResult {
    let store = FederationRedbStore::open(path("serialize"))?;
    let book = AttachmentAuthorityBook::new();
    let live = active(true);
    // While the g4 history write has committed but g4 is not yet published, the book's
    // lock is held, so no other adoption can publish in between.
    let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = std::sync::Arc::clone(&held);
    *book.after_history_write.lock().map_err(|_| "hook lock")? =
        Some(std::sync::Arc::new(move |b: &AttachmentAuthorityBook| {
            seen.store(b.available.try_lock().is_err(), std::sync::atomic::Ordering::SeqCst);
        }));
    assert_eq!(
        gen_of(book.adopt_record(&store, &live, &signed_adv(Some(authority(4, 4)))?, NOW)?),
        Some(4)
    );
    assert!(
        held.load(std::sync::atomic::Ordering::SeqCst),
        "the lock must be held across the write"
    );
    Ok(())
}

#[test]
fn concurrent_adoptions_never_publish_below_the_durable_maximum() -> TestResult {
    for round in 0..8_u8 {
        let store = std::sync::Arc::new(FederationRedbStore::open(path("race"))?);
        let book = std::sync::Arc::new(AttachmentAuthorityBook::new());
        let live = std::sync::Arc::new(active(true));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(6));
        let threads: Vec<_> = (1..=6_u8)
            .map(|g| {
                let (store, book, live, barrier) =
                    (store.clone(), book.clone(), live.clone(), barrier.clone());
                std::thread::spawn(move || -> Result<(), String> {
                    let record =
                        signed_adv(Some(authority(u64::from(g), g))).map_err(|e| e.to_string())?;
                    barrier.wait();
                    book.adopt_record(&store, &live, &record, NOW).map_err(|e| e.to_string())?;
                    Ok(())
                })
            })
            .collect();
        for t in threads {
            t.join().map_err(|_| "thread panicked")??;
        }
        let max = store.attachment_authority_history(NODE)?.ok_or("row")?.max_generation;
        // Whatever order the threads ran in, a published pin is exactly the durable maximum.
        match book.answer(&store, &live, NODE, NOW) {
            PinAnswer::Available { pin } => assert_eq!(pin.generation, max, "round {round}"),
            PinAnswer::Unavailable => {}
            PinAnswer::SourceUnknown => return Err("unexpected SourceUnknown".into()),
        }
    }
    Ok(())
}

#[test]
fn history_capacity_is_exactly_4096_nodes_never_refunded_and_needs_no_cache() -> TestResult {
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
    let refused = store.adopt_attachment_authority(NODE, Some(&authority(1, 1)), true, NOW);
    assert!(matches!(refused, Err(NodeCoreError::AttachmentAuthorityHistoryCapacity)));
    assert_eq!(store.attachment_authority_history(NODE)?, None);
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
    // The refused node is SourceUnknown for the router, derived from the durable counter
    // (no per-node rejection cache exists), also after the restart above.
    let book = AttachmentAuthorityBook::new();
    let live = active(true);
    assert!(matches!(
        book.adopt_record(&store, &live, &signed_adv(Some(authority(1, 1)))?, NOW),
        Err(NodeCoreError::AttachmentAuthorityHistoryCapacity)
    ));
    assert_eq!(book.answer(&store, &live, NODE, NOW), PinAnswer::SourceUnknown);
    Ok(())
}

#[test]
fn open_fails_closed_with_the_exact_error_when_counter_and_rows_disagree() -> TestResult {
    for delta in [1i64, -1] {
        let p = path("corrupt");
        let store = FederationRedbStore::open(&p)?;
        store.adopt_attachment_authority(NODE, Some(&authority(1, 1)), true, NOW)?;
        {
            let tx = store.db.begin_write()?;
            tx.open_table(COUNTER)?.insert(COUNTER_KEY, 1u64.saturating_add_signed(delta))?;
            tx.commit()?;
        }
        drop(store);
        let out = FederationRedbStore::open(&p);
        assert!(
            matches!(&out, Err(NodeCoreError::Redb(m)) if m == "attachment authority history counter mismatch"),
            "delta {delta}"
        );
    }
    Ok(())
}

#[test]
fn absent_and_present_records_match_the_full_frozen_bytes() -> TestResult {
    // Absent field: the exact pre-change JSON and canonical signed bytes, no `null`.
    let r = signed(None)?;
    assert_eq!(serde_json::to_string(&r)?, ABSENT_JSON);
    assert_eq!(String::from_utf8(ramflux_protocol::signed_bytes(&r)?)?, ABSENT_SIGNED);
    crate::verify_federation_server_record(&r, NOW)?;
    assert_eq!(serde_json::from_str::<FederationServerRecord>(ABSENT_JSON)?, r);
    // Present field: the exact JSON, canonical signed bytes and signature.
    let r = signed(Some(authority(4, 4)))?;
    assert_eq!(serde_json::to_string(&r)?, PRESENT_JSON);
    assert_eq!(String::from_utf8(ramflux_protocol::signed_bytes(&r)?)?, PRESENT_SIGNED);
    crate::verify_federation_server_record(&r, NOW)?;
    let decoded = serde_json::from_str::<FederationServerRecord>(PRESENT_JSON)?;
    assert_eq!(decoded, r);
    assert_eq!(
        serde_json::to_string(&decoded)?,
        PRESENT_JSON,
        "decode -> encode is byte-identical"
    );
    Ok(())
}

#[test]
fn noncanonical_authority_input_is_refused_with_the_exact_decoder_error() -> TestResult {
    let base = serde_json::to_value(signed(Some(authority(4, 4)))?)?;
    let cases: Vec<(&str, serde_json::Value, &str)> = vec![
        (
            "null",
            serde_json::Value::Null,
            "invalid type: null, expected struct FederationAttachmentAuthority",
        ),
        (
            "unknown member",
            serde_json::json!({"generation":4,"signing_public_key":key(4),"x":1}),
            "unknown field `x`, expected `generation` or `signing_public_key`",
        ),
        (
            "42-char key",
            serde_json::json!({"generation":4,"signing_public_key":&key(4)[..42]}),
            "non-canonical attachment_authority",
        ),
        (
            "44-char key",
            serde_json::json!({"generation":4,"signing_public_key":format!("{}A", key(4))}),
            "non-canonical attachment_authority",
        ),
        (
            "generation 0",
            serde_json::json!({"generation":0,"signing_public_key":key(4)}),
            "non-canonical attachment_authority",
        ),
        (
            "generation 2^53",
            serde_json::json!({"generation":9_007_199_254_740_992u64,"signing_public_key":key(4)}),
            "non-canonical attachment_authority",
        ),
        (
            "non-base64 key",
            serde_json::json!({"generation":4,"signing_public_key":"!".repeat(43)}),
            "non-canonical attachment_authority",
        ),
    ];
    for (name, value, message) in cases {
        let mut v = base.clone();
        v["attachment_authority"] = value;
        let error = serde_json::from_value::<FederationServerRecord>(v).err().ok_or(name)?;
        assert_eq!(error.to_string(), message, "{name}");
    }
    // Inclusive generation bounds are accepted at both ends.
    for generation in [1u64, 9_007_199_254_740_991] {
        let mut v = base.clone();
        v["attachment_authority"] =
            serde_json::json!({"generation":generation,"signing_public_key":key(4)});
        let decoded = serde_json::from_value::<FederationServerRecord>(v)?;
        assert_eq!(decoded.attachment_authority.map(|a| a.generation), Some(generation));
    }
    Ok(())
}

#[test]
fn a_first_time_peer_is_available_at_the_first_lookup_after_negotiation() -> TestResult {
    let store = FederationRedbStore::open(path("first-time"))?;
    let book = AttachmentAuthorityBook::new();
    let g4 = signed_adv(Some(authority(4, 4)))?;
    // Discovery verified the record while the handshake had not negotiated anything yet.
    assert_eq!(
        book.adopt_record(&store, &active(false), &g4, NOW)?,
        AuthorityAdoption::Unavailable(Withdrawn::Absent)
    );
    assert_eq!(book.answer(&store, &active(false), NODE, NOW), PinAnswer::Unavailable);
    assert_eq!(store.attachment_authority_history(NODE)?, None);
    // Negotiation completes; the very next lookup publishes the pin and records the history,
    // with no further discovery.
    assert!(matches!(
        book.answer(&store, &active(true), NODE, NOW + 1),
        PinAnswer::Available { pin } if pin.generation == 4 && pin.key == [4; 32]
    ));
    assert_eq!(store.attachment_authority_history(NODE)?.map(|h| h.max_generation), Some(4));
    Ok(())
}

#[test]
fn a_fresh_record_that_withdraws_the_advertisement_clears_the_pin_despite_an_old_negotiated_set()
-> TestResult {
    let store = FederationRedbStore::open(path("withdraw"))?;
    let book = AttachmentAuthorityBook::new();
    let live = active(true);
    assert_eq!(
        gen_of(book.adopt_record(&store, &live, &signed_adv(Some(authority(4, 4)))?, NOW)?),
        Some(4)
    );
    assert!(matches!(book.answer(&store, &live, NODE, NOW), PinAnswer::Available { .. }));
    // Same field, but the record no longer lists the capability; the negotiated set from the
    // earlier handshake still contains it.
    let unlisted = signed(Some(authority(4, 4)))?;
    assert_eq!(
        book.adopt_record(&store, &live, &unlisted, NOW + 1)?,
        AuthorityAdoption::Unavailable(Withdrawn::Absent)
    );
    assert_eq!(book.answer(&store, &live, NODE, NOW + 1), PinAnswer::Unavailable);
    // And it stays withdrawn at every later lookup (no stale candidate resurrects it).
    assert_eq!(book.answer(&store, &live, NODE, NOW + 2), PinAnswer::Unavailable);
    // Dropping the field instead has the same effect.
    assert_eq!(
        gen_of(book.adopt_record(&store, &live, &signed_adv(Some(authority(4, 4)))?, NOW + 3)?),
        Some(4)
    );
    assert_eq!(
        book.adopt_record(&store, &live, &signed_adv(None)?, NOW + 4)?,
        AuthorityAdoption::Unavailable(Withdrawn::Absent)
    );
    assert_eq!(book.answer(&store, &live, NODE, NOW + 4), PinAnswer::Unavailable);
    assert_eq!(store.attachment_authority_history(NODE)?.map(|h| h.max_generation), Some(4));
    Ok(())
}

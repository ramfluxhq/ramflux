// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual consent-history writers, private execution reset and original-contribution DV.
use crate::account_db::full_transfer::{
    full_transfer_catalog,
    receiver_copy::owner_tests::{Case, TestResult, run},
};
use crate::{AccountDb, ContactRequestRecord};
use serde_json::json;
fn peer() -> String {
    ramflux_protocol::encode_base64url([81; 32])
}
type Version = (u8, &'static str, Option<&'static str>, i64, &'static str);
fn seed(db: &AccountDb, direction: &str, version: Version) -> TestResult {
    let (nonce, state, reply, stamp, note) = version;
    let nonce = ramflux_protocol::encode_base64url([nonce; 32]);
    let requester = if direction == "inbound" { peer() } else { db.principal_commitment.clone() };
    let id = ramflux_protocol::hash_base64url(
        "ramflux.contact_request.id.v1",
        &ramflux_protocol::canonical_json_bytes(&(requester, &nonce))?,
    );
    let mut metadata = json!({"nonce":nonce,"issued_at":100,"note":note});
    if let Some(reply) = reply {
        metadata["needs_reply"] = json!(reply);
    }
    assert!(db.persist_contact_request(&ContactRequestRecord {
        contact_identity_commitment: peer(),
        direction: direction.into(),
        request_id: id,
        principal_id: "peer-principal".into(),
        link_id: "contact-history-link".into(),
        state: state.into(),
        request_json: serde_json::to_vec(&metadata)?,
        expires_at: 604_900,
        updated_at: stamp,
    })?);
    Ok(())
}
#[test]
fn contact_history_preserves_complete_independent_denial_version_and_no_reply_execution()
-> TestResult {
    run(Case {
        name: "contact-history-denial-version",
        seed: |a, b| {
            seed(a, "inbound", (82, "accepted", Some("accept"), 300, "A history"))?;
            seed(b, "inbound", (83, "declined", Some("decline"), 200, "B denial"))
        },
        before: None,
        inspect: |private, b| {
            let value = private.db.query_row(
                "SELECT state,request_json,updated_at FROM contact_request_projection",
                [],
                |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?))
                },
            )?;
            assert_eq!((value.0, value.2), ("declined".into(), 200));
            let body: serde_json::Value = ramflux_protocol::parse_i_json(&value.1)?;
            assert_eq!(body["nonce"], ramflux_protocol::encode_base64url([83; 32]));
            assert_eq!(body["note"], "B denial");
            assert!(body.get("needs_reply").is_none());
            let original = b.contact_request(&peer(), "inbound")?.ok_or("original B request")?;
            let metadata: serde_json::Value = serde_json::from_slice(&original.request_json)?;
            assert_eq!(metadata["needs_reply"], "decline", "private reset mutated live B");
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn contact_history_same_request_id_with_different_original_note_refuses_before_dv() -> TestResult {
    run(Case {
        name: "contact-history-body-conflict",
        seed: |a, b| {
            seed(a, "inbound", (84, "accepted", None, 200, "first note"))?;
            seed(b, "inbound", (84, "accepted", None, 300, "changed original"))
        },
        before: None,
        inspect: |_, _| Ok(()),
        conflict: true,
    })
}
#[test]
fn contact_history_b_only_outbound_metadata_is_reset_in_private_generation() -> TestResult {
    run(Case {
        name: "contact-history-b-only",
        seed: |_, b| seed(b, "outbound", (85, "accepted", Some("accept"), 200, "B only")),
        before: None,
        inspect: |private, b| {
            let bytes: Vec<u8> = private.db.query_row(
                "SELECT request_json FROM contact_request_projection",
                [],
                |row| row.get(0),
            )?;
            let body: serde_json::Value = ramflux_protocol::parse_i_json(&bytes)?;
            assert_eq!(body["note"], "B only");
            assert!(body.get("needs_reply").is_none());
            assert!(
                b.contact_request(&peer(), "outbound")?
                    .ok_or("original B row")?
                    .request_json
                    .windows(b"needs_reply".len())
                    .any(|bytes| bytes == b"needs_reply")
            );
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn contact_history_private_validation_cannot_hide_a_restored_execution_field() -> TestResult {
    let (_root, db) = crate::account_db::full_transfer::test_support::owned_source_test_db(
        "contact-private-execution",
    )?;
    seed(&db, "inbound", (86, "accepted", Some("accept"), 200, "original"))?;
    db.connection.call(|raw|Ok((|| -> Result<(),crate::StorageError> {
        assert!(super::super::sql_projection::require_private(raw,full_transfer_catalog()).is_err());
        let tx=raw.transaction()?;
        super::super::sql_projection::canonicalize_private(&tx,full_transfer_catalog())?;
        tx.commit()?;
        super::super::sql_projection::require_private(raw,full_transfer_catalog())?;
        raw.execute("UPDATE contact_request_projection SET request_json=CAST(json_set(CAST(request_json AS TEXT),'$.needs_reply','accept') AS BLOB)",[])?;
        assert!(super::super::sql_projection::require_private(raw,full_transfer_catalog()).is_err());
        Ok(())
    })()))??;
    Ok(())
}
#[test]
fn contact_history_nonce_context_mismatch_refuses_source_without_removing_the_row() -> TestResult {
    let (_root, db) = crate::account_db::full_transfer::test_support::owned_source_test_db(
        "contact-source-binding",
    )?;
    seed(&db, "inbound", (87, "accepted", None, 200, "retained"))?;
    db.connection.execute(
        "UPDATE contact_request_projection SET request_id=?1",
        rusqlite::params![ramflux_protocol::encode_base64url([88; 32])],
    )?;
    assert!(matches!(
        db.inspect_full_transfer_schema(full_transfer_catalog()),
        Err(crate::StorageError::PairingField("UnsupportedRecord"))
    ));
    assert!(db.contact_request(&peer(), "inbound")?.is_some());
    Ok(())
}

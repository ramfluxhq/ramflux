// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Proof preference is coupled to content and cannot survive a native content change.
use super::super::native_payload::test_support;
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Result<(Connection, String, Vec<u8>), Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE runtime_message_content(message_id TEXT PRIMARY KEY,conversation_id TEXT NOT NULL,body BLOB NOT NULL);")?;
    db.execute_batch(SCHEMA)?;
    let inner = test_support::inner(16)?;
    let identity = inner.identity.as_ref().ok_or("identity")?;
    let message = ramflux_protocol::encode_base64url(&identity.id);
    let body = inner.encode_to_vec();
    db.execute(
        "INSERT INTO runtime_message_content VALUES(?1,?2,?3)",
        params![&message, &identity.conversation_id, &body],
    )?;
    db.execute(
        "INSERT INTO runtime_native_history_selection VALUES(?1,'authored',?2,?3)",
        params![&message, &identity.id, blake3::hash(&body).as_bytes().as_slice()],
    )?;
    Ok((db, message, body))
}
#[test]
fn native_selection_checks_current_event_and_exact_body_hash() -> TestResult {
    let (db, message, body) = fixture()?;
    assert!(
        matches!(read(&db, &message, &body)?, Some(Selected::Authored)),
        "matching local proof preference lost"
    );
    db.execute("UPDATE runtime_native_history_selection SET current_id=?1", [vec![4; 32]])?;
    assert!(
        read(&db, &message, &body).is_err(),
        "selection relabeled another current native event"
    );
    let inner = g::Inner::decode(body.as_slice())?;
    db.execute(
        "UPDATE runtime_native_history_selection SET current_id=?1,body_hash=?2",
        params![inner.identity.ok_or("identity")?.id, vec![5_u8; 32]],
    )?;
    assert!(read(&db, &message, &body).is_err(), "selection accepted different exact native bytes");
    Ok(())
}
#[test]
fn native_selection_content_change_and_erasure_clear_the_preference() -> TestResult {
    let (db, message, body) = fixture()?;
    db.execute("UPDATE runtime_message_content SET body=body", [])?;
    assert!(
        read(&db, &message, &body)?.is_some(),
        "identical body write discarded the chosen contributor"
    );
    let changed = test_support::inner(32)?.encode_to_vec();
    db.execute("UPDATE runtime_message_content SET body=?1", [&changed])?;
    assert!(
        read(&db, &message, &changed)?.is_none(),
        "changed native content inherited stale proof selection"
    );
    let id = g::Inner::decode(changed.as_slice())?.identity.ok_or("identity")?.id;
    db.execute(
        "INSERT INTO runtime_native_history_selection VALUES(?1,'authored',?2,?3)",
        params![&message, id, blake3::hash(&changed).as_bytes().as_slice()],
    )?;
    db.execute("DELETE FROM runtime_message_content", [])?;
    let count: u64 =
        db.query_row("SELECT count(*) FROM runtime_native_history_selection", [], |row| {
            row.get(0)
        })?;
    assert_eq!(count, 0, "erased native content retained a selection locator");
    Ok(())
}
#[test]
fn native_selection_orphan_or_noncanonical_id_refuses_inspection() -> TestResult {
    let (db, message, _body) = fixture()?;
    require_rows(&db)?;
    db.execute_batch(
        "DROP TRIGGER native_selection_body_removed; DELETE FROM runtime_message_content;",
    )?;
    assert!(
        require_rows(&db).is_err(),
        "orphan selection hidden behind an empty native body family"
    );
    db.execute("UPDATE runtime_native_history_selection SET message_id=?1", ["!".repeat(43)])?;
    assert!(require_rows(&db).is_err(), "noncanonical selection key admitted");
    let count: u64 = db.query_row(
        "SELECT count(*) FROM runtime_native_history_selection WHERE message_id=?1",
        [message],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "fixture did not replace the key");
    Ok(())
}

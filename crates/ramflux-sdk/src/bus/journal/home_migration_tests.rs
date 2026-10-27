// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The stream projects immutable public transitions rather than the latest private job.
use super::*;
use ramflux_storage::{AccountDbKey, AccountIndex, HomeMigrationWrite};

#[test]
fn home_migration_stream_keeps_each_phase_and_omits_private_admission_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let index = AccountIndex::open(root.path())?;
    let hash = |n| ramflux_protocol::encode_base64url([n; 32]);
    index.create_account("human", &hash(1))?;
    let db = AccountDb::open(&index, "human", &AccountDbKey::generate()?)?;
    for (revision, phase) in [(1, "intent"), (2, "prepare_sent"), (3, "seal_sent")] {
        db.persist_home_migration(HomeMigrationWrite {
            operation_id: &hash(2), account_anchor: &hash(1), intent_hash: &hash(3),
            expected_revision: (revision > 1).then_some(revision - 1), revision,
            active: true, recovery_blocked: phase == "seal_sent", next_attempt_at: 100,
            state: b"PRIVATE_ADMISSION_EVIDENCE",
            progress: &json!({"operation_id":hash(2),"seq":revision,"phase":phase,
                "source":"source","target":null,"home_epoch":null,"home_hash":null,
                "commit_deadline":null,"forward_until":null,
                "backlog":{"scheduled":0,"forwarded":0,"receiver_acked":0,"expired":0,"rejected":0,"evidence_required":0,"remaining":0}}),
        })?;
    }
    let mut client = RamfluxClient::new();
    client.active_account_db = Some(db);
    let entries = client.account_db()?.pending_outbox(256)?;
    let mut phases = Vec::new();
    for entry in entries.iter().filter(|e| e.table_name == "home_migration_progress") {
        let projected = project(&client, entry)?;
        assert_eq!(projected.len(), 1);
        let (topic, body, conversation) = &projected[0];
        assert_eq!(topic, "home_migration.progress");
        assert!(conversation.is_none());
        assert_eq!(body.as_object().ok_or("progress object")?.len(), 10);
        assert!(!serde_json::to_string(body)?.contains("PRIVATE_"));
        phases.push(body["phase"].as_str().ok_or("phase")?.to_owned());
    }
    assert_eq!(phases, ["intent", "prepare_sent", "seal_sent"]);
    let mut absent =
        entries.into_iter().find(|e| e.table_name == "home_migration_progress").ok_or("outbox")?;
    absent.row_id = i64::MAX;
    assert!(project(&client, &absent).is_err());
    Ok(())
}

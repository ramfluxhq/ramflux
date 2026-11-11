// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed revocation classification, durable quarantine and full-entry ACK replay.
use super::*;
use crate::bus::{state::LocalBusAccountState, sync_driver};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
type TestResult = Result<(), Box<dyn std::error::Error>>;
type Snapshot = Vec<Vec<Vec<rusqlite::types::Value>>>;
#[derive(Default)]
struct WireState {
    attempts: usize,
    failures: usize,
    accepted: usize,
    codes: Vec<String>,
    nacks: Vec<String>,
    resumes: usize,
    redeliver: bool,
    /// In-flight mutation of the transmitted ACK: `envelope`, `sequence` or `signature`.
    tamper: Option<&'static str>,
}
struct Wire {
    sql: rusqlite::Connection,
    state: Arc<Mutex<WireState>>,
    queued: VecDeque<Vec<u8>>,
    entry: GatewayInboxEntry,
    device_public_key: String,
}
/// Gateway-side verification of a transmitted ACK against the delivered entry.
fn ack_refusal(
    entry: &GatewayInboxEntry,
    device_public_key: &str,
    ack: &ramflux_protocol::Ack,
) -> Option<&'static str> {
    if ack.envelope_id != entry.envelope.envelope_id {
        return Some("ACK envelope mismatch");
    }
    if ack.ext.ext.get("inbox_seq").and_then(Value::as_u64) != Some(entry.inbox_seq) {
        return Some("ACK sequence mismatch");
    }
    let signed = ramflux_protocol::signed_bytes(ack).ok();
    match signed {
        Some(bytes)
            if ramflux_crypto::verify_canonical_signature(
                &bytes,
                &ack.signed.signature,
                device_public_key,
            )
            .is_ok() =>
        {
            None
        }
        _ => Some("ACK signature invalid"),
    }
}
impl ramflux_transport::GatewaySessionFrameSink for Wire {
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> ramflux_transport::GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            let value: Value = serde_json::from_slice(body)?;
            let response = match value["frame_type"].as_str() {
                Some("resume") => {
                    let mut state = self.state.lock().map_err(|_| {
                        ramflux_transport::TransportError::Quic("wire mutex".into())
                    })?;
                    let deliver = state.resumes == 0 || state.redeliver;
                    state.resumes += 1;
                    GatewayServerFrame::Resume {
                        entries: if deliver { vec![self.entry.clone()] } else { Vec::new() },
                    }
                }
                Some("ack") => {
                    let code: String = self
                        .sql
                        .query_row(
                            "SELECT error_code FROM runtime_inbox_dead_letter LIMIT 1",
                            [],
                            |r| r.get(0),
                        )
                        .optional()
                        .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))?
                        .unwrap_or_default();
                    let mut state = self.state.lock().map_err(|_| {
                        ramflux_transport::TransportError::Quic("wire mutex".into())
                    })?;
                    state.attempts += 1;
                    state.codes.push(code);
                    let mut ack: ramflux_protocol::Ack =
                        serde_json::from_value(value["ack"].clone())?;
                    match state.tamper {
                        Some("envelope") => ack.envelope_id = "forged-envelope".to_owned(),
                        Some("sequence") => {
                            ack.ext.ext.insert("inbox_seq".into(), json!(self.entry.inbox_seq + 1));
                        }
                        Some("signature") => ack.signed.signature = "AAAA".to_owned(),
                        _ => {}
                    }
                    if let Some(reason) = ack_refusal(&self.entry, &self.device_public_key, &ack) {
                        state.nacks.push(reason.to_owned());
                        GatewayServerFrame::Nack { reason: reason.into() }
                    } else if state.attempts <= state.failures {
                        state.nacks.push("injected ACK refusal".into());
                        GatewayServerFrame::Nack { reason: "injected ACK refusal".into() }
                    } else {
                        state.accepted += 1;
                        let cursor = GatewayCursor {
                            target_delivery_id: "bob".into(),
                            inbox_seq: self.entry.inbox_seq,
                            last_envelope_id: Some(self.entry.envelope.envelope_id.clone()),
                            acked_envelope_ids: vec![self.entry.envelope.envelope_id.clone()],
                            nacked_envelope_ids: BTreeMap::new(),
                        };
                        self.queued.push_back(serde_json::to_vec(&GatewayServerFrame::Ack {
                            cursor: cursor.clone(),
                        })?);
                        GatewayServerFrame::Cursor { cursor: Some(cursor) }
                    }
                }
                Some("heartbeat") => {
                    GatewayServerFrame::Heartbeat { now: value["now"].as_u64().unwrap_or(0) }
                }
                _ => {
                    return Err(ramflux_transport::TransportError::Quic(
                        "unexpected revocation frame".into(),
                    ));
                }
            };
            self.queued.push_back(serde_json::to_vec(&response)?);
            Ok(())
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSource for Wire {
    fn recv_idle_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(std::future::pending())
    }
    fn recv_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.queued.pop_front().ok_or_else(|| {
                ramflux_transport::TransportError::Quic("missing revocation reply".into())
            })
        })
    }
}
struct Case {
    _a: Fixture,
    b: Fixture,
    sql: rusqlite::Connection,
    entry: GatewayInboxEntry,
    state: Arc<Mutex<WireState>>,
}
impl Case {
    fn new(legacy: bool, failures: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let a = Fixture::new("alice", 21)?;
        let b = Fixture::new("bob", 31)?;
        b.client.establish_friend_link("friend", "bob", "alice")?;
        let db = b.client.account_db()?;
        db.persist_client_record(
            "object",
            "missing-object",
            &if legacy {
                json!({"owner":"alice","message_id":"original-message","manifest_hash":"manifest"})
            } else {
                json!({"owner":"alice"})
            },
        )?;
        if legacy {
            db.send_direct_message("thread", "original-message", "alice", b"original")?;
            db.persist_actor_state("attachment/reference/missing-object", &json!({"reference":{"object_id":"missing-object","manifest_hash":"manifest","plaintext_hash":"plaintext"}}))?;
        }
        let entry = seal_as(
            &a,
            &b,
            message("signed-revoke", "thread"),
            &serde_json::to_vec(
                &json!({"type":"object.revoke_access","object_id":"missing-object"}),
            )?,
            Route::control(),
        )?;
        let sql = connection(&b)?;
        let retained: usize =
            sql.query_row("SELECT count(*) FROM object_retention_reference", [], |r| r.get(0))?;
        assert_eq!(retained, 0, "legacy actor must not rely on a retention edge");
        let state = Arc::new(Mutex::new(WireState { failures, ..WireState::default() }));
        Ok(Self { _a: a, b, sql, entry, state })
    }
    fn account(&mut self) -> Result<LocalBusAccountState, Box<dyn std::error::Error>> {
        let branch = self.b.config()?.device_branch.ok_or("bob device branch")?;
        let wire = Wire {
            sql: connection(&self.b)?,
            state: self.state.clone(),
            queued: VecDeque::new(),
            entry: self.entry.clone(),
            device_public_key: ramflux_crypto::public_key_base64url_from_seed(
                branch.signing_key.to_bytes(),
            ),
        };
        let engine = GatewaySessionEngine::with_test_transport(self.b.config()?, Box::new(wire));
        Ok(LocalBusAccountState::new(std::mem::take(&mut self.b.client), engine, "bob".into()))
    }
    fn snapshot(&self) -> Result<Snapshot, rusqlite::Error> {
        [
            "object_index",
            "object_retention_reference",
            "object_message_reference",
            "object_retention_payload",
            "runtime_actor_state",
            "object_tombstone",
        ]
        .into_iter()
        .map(|table| {
            let mut query = self.sql.prepare(&format!("SELECT * FROM {table} ORDER BY 1"))?;
            let count = query.column_count();
            query.query_map([], |row| (0..count).map(|n| row.get(n)).collect())?.collect()
        })
        .collect()
    }
    fn rejected(&self, client: &RamfluxClient) -> TestResult {
        assert!(client.routed_seen_marker(&self.entry)?.is_none());
        let code: String =
            self.sql.query_row("SELECT error_code FROM runtime_inbox_dead_letter", [], |row| {
                row.get(0)
            })?;
        assert_eq!(code, "routing_rejected");
        assert_eq!(client.account_db()?.unrouted_count()?, 0);
        assert_eq!(
            self.state.lock().map_err(|_| "wire mutex")?.codes.last().map(String::as_str),
            Some("routing_rejected"),
            "dead letter must commit before transport ACK"
        );
        Ok(())
    }
    async fn raw_error(&mut self) -> Result<SdkError, Box<dyn std::error::Error>> {
        let mut engine =
            GatewaySessionEngine::with_test_transport(self.b.config()?, Box::new(NoNetwork));
        Ok(self
            .b
            .client
            .apply_routed_entry(&mut engine, &review::pool()?, &self.entry, false)
            .await
            .err()
            .ok_or("revoke unexpectedly accepted")?)
    }
}
fn connection(b: &Fixture) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    use ramflux_storage::{FileVaultSecretSource, VaultSecretSource};
    use std::fmt::Write;
    let vault = FileVaultSecretSource::new(&b.root).vault_secret("bob")?;
    let wrapped = b.client.account_index()?.load_wrapped_db_key("bob")?.ok_or("wrapped key")?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &crate::client::account::account_db_key_encryption_key(&vault, b"routed-test"),
        &wrapped,
    )?;
    let sql = rusqlite::Connection::open(&b.client.account_db()?.path)?;
    let mut hex = String::new();
    for byte in key.bytes() {
        write!(&mut hex, "{byte:02x}")?;
    }
    sql.execute_batch(&format!("PRAGMA key=\"x'{hex}'\"; PRAGMA cipher_page_size=4096; PRAGMA kdf_iter=256000; PRAGMA cipher_hmac_algorithm=HMAC_SHA512; PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512; PRAGMA foreign_keys=ON;"))?;
    Ok(sql)
}
fn assert_refusal(error: &SdkError) {
    assert!(
        matches!(error, SdkError::InboundRejected(reason) if reason == "object revocation has no admissible manifest source"),
        "{error:?}"
    );
    assert_eq!(crate::client::inbox_failure::deterministic(error), Some("routing_rejected"));
}
async fn replay(failures: usize, runs: usize, managed: bool) -> TestResult {
    let mut c = Case::new(false, failures)?;
    assert_refusal(&c.raw_error().await?);
    // Include the driver's unrelated contact-maintenance markers in the baseline.
    c.b.client.maintain_contact_requests()?;
    let before = c.snapshot()?;
    {
        let mut state = c.state.lock().map_err(|_| "wire mutex")?;
        state.resumes = usize::from(managed);
        state.redeliver = failures == 0 && runs > 1;
    }
    c.sql.execute_batch("CREATE TABLE e11_rejections(code TEXT NOT NULL); CREATE TRIGGER observe_e11_rejection BEFORE INSERT ON runtime_inbox_dead_letter BEGIN INSERT INTO e11_rejections VALUES(NEW.error_code); END;")?;
    let mut account = c.account()?;
    let key = account.client.inbox_admission_key(&c.entry)?;
    account.client.account_db()?.hold_unrouted(
        &key,
        c.entry.inbox_seq,
        &serde_json::to_vec(&c.entry)?,
        now_unix_timestamp(),
    )?;
    let now = now_unix_timestamp();
    for n in 0..runs {
        if n > 0 {
            // Pin wall time so contact-request/maintenance-next stay in the snapshot.
            // Force the WA retry due so a failed ACK can flush on the next pass.
            c.sql.execute("UPDATE gateway_ack_intent SET next_attempt_at=0", [])?;
        }
        let applied = sync_driver::run_at(&mut account, now).await?;
        if n == 0 {
            assert!(applied >= 1, "first pass must cover the rejected entry, got {applied}");
        }
        assert_eq!(account.client.gateway_receive_cursor("bob")?, c.entry.inbox_seq);
        c.rejected(&account.client)?;
        let codes: Vec<String> = c
            .sql
            .prepare("SELECT code FROM e11_rejections")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        assert_eq!(
            codes,
            vec!["routing_rejected"],
            "W1 terminal cover quarantines once; redelivery is AlreadyCovered"
        );
        assert_eq!(
            c.snapshot()?,
            before,
            "rejection must not change objects, references or actors"
        );
        let retries = account.client.account_db()?.due_inbox_retries(i64::MAX)?;
        assert_eq!(retries.len(), 0, "deterministic reject retires the inbox retry at cover");
        let intents: usize =
            c.sql.query_row("SELECT count(*) FROM gateway_ack_intent", [], |r| r.get(0))?;
        if n < failures {
            assert!(
                intents >= 1,
                "failed ACK must retain the WA intent (pass {n}/{runs}, failures={failures})"
            );
        } else {
            assert_eq!(
                intents, 0,
                "successful ACK must clear the WA intent (pass {n}/{runs}, failures={failures})"
            );
        }
    }
    let attempts = c.state.lock().map_err(|_| "wire mutex")?.attempts;
    assert!(attempts >= 1, "gateway must see at least one ACK, got {attempts}");
    if failures == 0 {
        // Terminal cover ACKs once; redelivery is AlreadyCovered and must not re-ACK.
        assert_eq!(attempts, 1, "AlreadyCovered redelivery must not emit another ACK");
    } else {
        assert_eq!(attempts, runs);
    }
    drop(account);
    Ok(())
}
#[tokio::test]
async fn e11_owner_only_revoke_rejected_once_and_acked() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(replay(0, 1, true))).await
}
#[tokio::test]
async fn e11_redelivered_rejected_entry_changes_no_state() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(replay(0, 2, false))).await
}
#[tokio::test]
async fn e11_failed_ack_retains_ack_retry_then_clears() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(replay(1, 2, true))).await
}
#[tokio::test]
async fn e11_ack_driven_replay_is_deterministic_and_idempotent() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(replay(2, 3, false))).await
}
#[tokio::test]
async fn e11_legacy_actor_with_owner_and_message_id_succeeds() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(async {
        let mut c = Case::new(true, 0)?;
        let mut account = c.account()?;
        let applied = sync_driver::run_at(&mut account, now_unix_timestamp()).await?;
        assert!(applied >= 1, "legacy actor must cover, got {applied}");
        assert_eq!(c.state.lock().map_err(|_| "wire mutex")?.attempts, 1);
        let (manifest, tombstone): (String, bool) = c.sql.query_row("SELECT CAST(manifest_hash AS TEXT), tombstoned FROM object_index WHERE object_id='missing-object'", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
        assert_eq!(manifest, "manifest"); assert!(tombstone);
        account.client.account_db()?.upsert_object(&ramflux_storage::ObjectWrite {
            object_id: "missing-object", manifest_hash: "manifest", nonce: "nonce",
            ciphertext: b"late fetched ciphertext", plaintext_hash: "plaintext",
            tombstoned: false, backup_excluded: false, content_key: Some(&[9; 32]),
            object: &json!({"object_id":"missing-object","tombstoned":false}), updated_at: i64::MAX,
        })?;
        assert!(account.client.account_db()?.object_is_tombstoned("missing-object")?);
        assert!(matches!(account.client.decrypt_object("missing-object"), Err(SdkError::Sync(ramflux_sync::SyncError::ObjectTombstoned))));
        let count: usize = c.sql.query_row("SELECT count(*) FROM runtime_inbox_dead_letter", [], |r| r.get(0))?;
        assert_eq!(count, 0);
        assert_eq!(account.client.account_db()?.due_inbox_retries(i64::MAX)?.len(), 0);
        Ok(())
    })).await
}
#[tokio::test]
async fn e11_storage_io_failure_still_propagates() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(async {
        let mut c = Case::new(true, 0)?;
        c.sql.execute_batch("CREATE TRIGGER fail_revocation BEFORE INSERT ON object_index BEGIN SELECT RAISE(ABORT,'revocation writer failed'); END;")?;
        let error = c.raw_error().await?;
        assert!(matches!(error, SdkError::Storage(ramflux_storage::StorageError::Sqlite(_))), "{error:?}");
        assert_eq!(crate::client::inbox_failure::deterministic(&error), None);
        let mut account = c.account()?;
        let first = sync_driver::run_at(&mut account, now_unix_timestamp()).await;
        assert!(
            matches!(&first, Err(SdkError::Storage(ramflux_storage::StorageError::Sqlite(_)))),
            "{first:?}"
        );
        assert_eq!(c.state.lock().map_err(|_| "wire mutex")?.attempts, 0);
        c.sql.execute_batch("DROP TRIGGER fail_revocation;")?;
        let applied = sync_driver::run_at(&mut account, now_unix_timestamp()).await?;
        assert!(applied >= 1, "retried storage pass must cover, got {applied}");
        assert_eq!(c.state.lock().map_err(|_| "wire mutex")?.attempts, 1);
        assert_eq!(account.client.account_db()?.due_inbox_retries(i64::MAX)?.len(), 0);
        Ok(())
    })).await
}
async fn refused_forged_ack(tamper: &'static str, reason: &'static str) -> TestResult {
    let mut c = Case::new(false, 0)?;
    c.state.lock().map_err(|_| "wire mutex")?.tamper = Some(tamper);
    let mut account = c.account()?;
    let key = account.client.inbox_admission_key(&c.entry)?;
    account.client.account_db()?.hold_unrouted(
        &key,
        c.entry.inbox_seq,
        &serde_json::to_vec(&c.entry)?,
        now_unix_timestamp(),
    )?;
    let applied = sync_driver::run_at(&mut account, now_unix_timestamp()).await?;
    assert!(applied >= 1, "forged ACK pass must still cover, got {applied}");
    c.rejected(&account.client)?;
    {
        let state = c.state.lock().map_err(|_| "wire mutex")?;
        assert!(state.attempts >= 1, "gateway must see the forged ACK, got {}", state.attempts);
        assert_eq!(state.accepted, 0, "a refused ACK must never be accepted by the gateway");
        assert_eq!(
            state.nacks.last().map(String::as_str),
            Some(reason),
            "gateway must refuse the tampered ACK"
        );
    }
    let intents: usize =
        c.sql.query_row("SELECT count(*) FROM gateway_ack_intent", [], |r| r.get(0))?;
    assert_eq!(intents, 1, "forged ACK must retain the WA intent");
    assert_eq!(account.client.account_db()?.due_inbox_retries(i64::MAX)?.len(), 0);
    Ok(())
}
#[tokio::test]
async fn e11_forged_ack_envelope_is_refused() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(refused_forged_ack("envelope", "ACK envelope mismatch")))
        .await
}
#[tokio::test]
async fn e11_forged_ack_sequence_is_refused() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(refused_forged_ack("sequence", "ACK sequence mismatch")))
        .await
}
#[tokio::test]
async fn e11_forged_ack_signature_is_refused() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(refused_forged_ack("signature", "ACK signature invalid")))
        .await
}

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
    codes: Vec<String>,
    resumes: usize,
    redeliver: bool,
}
struct Wire {
    sql: rusqlite::Connection,
    state: Arc<Mutex<WireState>>,
    queued: VecDeque<Vec<u8>>,
    entry: GatewayInboxEntry,
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
                    if state.attempts <= state.failures {
                        GatewayServerFrame::Nack { reason: "injected ACK refusal".into() }
                    } else {
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
        let wire = Wire {
            sql: connection(&self.b)?,
            state: self.state.clone(),
            queued: VecDeque::new(),
            entry: self.entry.clone(),
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
    for n in 0..runs {
        let now = if n == 0 || failures == 0 {
            now_unix_timestamp()
        } else {
            let due: i64 =
                c.sql.query_row("SELECT next_at FROM runtime_inbox_retry", [], |r| r.get(0))?;
            due.max(now_unix_timestamp())
        };
        if managed && n == 0 {
            let mut engine = account.session_client().await?;
            let pressure = crate::bus::sync_driver::prepare_receive(&account)?.backpressure;
            let (prepared, mut pressure) = sync_driver::apply_prepared_receive(
                &mut account,
                crate::bus::connection_manager::ReceiveEntry {
                    entry: c.entry.clone(),
                    retry_key: None,
                    replay: false,
                },
                None,
                pressure,
            )
            .await?;
            let prepared = prepared.ok_or("missing managed rejection ACK")?;
            let cursor = engine.ack(prepared.ack).await;
            let outcome =
                sync_driver::finish_prepared_ack(&account, &prepared.state, cursor, &mut pressure);
            if failures > 0 {
                assert!(outcome.is_err());
            } else {
                assert!(!outcome?);
            }
        } else {
            assert_eq!(sync_driver::run_at(&mut account, now).await?, 0);
        }
        c.rejected(&account.client)?;
        let codes: Vec<String> = c
            .sql
            .prepare("SELECT code FROM e11_rejections")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        assert_eq!(
            codes,
            vec!["routing_rejected"; n + 1],
            "each replay must actually reject and quarantine again"
        );
        assert_eq!(
            c.snapshot()?,
            before,
            "rejection must not change objects, references or actors"
        );
        assert_eq!(account.client.gateway_receive_cursor("bob")?, c.entry.inbox_seq);
        let retries = account.client.account_db()?.due_inbox_retries(i64::MAX)?;
        if n < failures {
            assert_eq!(retries.len(), 1);
            let retained: GatewayInboxEntry = serde_json::from_slice(&retries[0])?;
            assert_eq!(serde_json::to_value(retained)?, serde_json::to_value(&c.entry)?);
        } else {
            assert_eq!(retries.len(), 0);
        }
    }
    assert_eq!(c.state.lock().map_err(|_| "wire mutex")?.attempts, runs);
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
        assert_eq!(sync_driver::run_at(&mut account, now_unix_timestamp()).await?, 1);
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
        assert_eq!(sync_driver::run_at(&mut account, now_unix_timestamp()).await?, 0);
        assert_eq!(c.state.lock().map_err(|_| "wire mutex")?.attempts, 0);
        assert_eq!(account.client.account_db()?.due_inbox_retries(i64::MAX)?.len(), 1);
        c.sql.execute_batch("DROP TRIGGER fail_revocation;")?;
        let now: i64 = c.sql.query_row("SELECT next_at FROM runtime_inbox_retry", [], |r| r.get(0))?;
        assert_eq!(sync_driver::run_at(&mut account, now).await?, 1);
        assert_eq!(c.state.lock().map_err(|_| "wire mutex")?.attempts, 1);
        assert_eq!(account.client.account_db()?.due_inbox_retries(i64::MAX)?.len(), 0);
        Ok(())
    })).await
}

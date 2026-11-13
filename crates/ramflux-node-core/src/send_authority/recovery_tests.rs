// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real redb origin/coordinator recovery, including lost durable ACKs and a second crash.

use super::*;
use crate::test_support::notification_authority::{GATEWAY, NOTIFY, ROUTER};
use std::{
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ACTUAL: TableDefinition<&str, &[u8]> = TableDefinition::new("recovery_authoritative_rows");
const EFFECTS: TableDefinition<&str, u64> = TableDefinition::new("recovery_side_effect_count");

struct Rpc {
    notify: Mutex<Option<Arc<SendAuthorityStore>>>,
    origin: Arc<redb::Database>,
    path: std::path::PathBuf,
    fault: AtomicU8,
}
impl Rpc {
    fn new(root: &std::path::Path) -> TestResult<Arc<Self>> {
        let origin = Arc::new(redb::Database::create(root.join("origin.redb"))?);
        AuthorityOrigin::initialize(&origin)?;
        let tx = origin.begin_write()?;
        tx.open_table(ACTUAL)?;
        tx.open_table(EFFECTS)?;
        tx.commit()?;
        let rpc = Arc::new(Self {
            notify: Mutex::new(None),
            origin,
            path: root.join("notify.redb"),
            fault: AtomicU8::new(0),
        });
        rpc.reboot()?;
        Ok(rpc)
    }
    fn store(&self) -> Result<Arc<SendAuthorityStore>, NodeCoreError> {
        self.notify
            .lock()
            .map_err(storage)?
            .clone()
            .ok_or_else(|| SendAuthorityError::Closed.into())
    }
    fn reboot(&self) -> TestResult {
        self.notify.lock().map_err(storage)?.take();
        let db = Arc::new(redb::Database::create(&self.path)?);
        let store = Arc::new(SendAuthorityStore::new(db, rpc::random_id()?)?);
        store.configure_origins(6, &[ROUTER.into(), GATEWAY.into(), NOTIFY.into()])?;
        *self.notify.lock().map_err(storage)? = Some(store);
        Ok(())
    }
    fn read(&self, request: &AuthorityReadRequest) -> Result<AuthorityReadReply, NodeCoreError> {
        let tx = self.origin.begin_read().map_err(storage)?;
        let table = tx.open_table(ACTUAL).map_err(storage)?;
        let actual = table
            .get("record")
            .map_err(storage)?
            .map(|v| ramflux_protocol::parse_i_json::<serde_json::Value>(v.value()))
            .transpose()
            .map_err(storage)?;
        let record = actual
            .as_ref()
            .and_then(|v| v.get("record"))
            .cloned()
            .map(serde_json::from_value::<AuthorityRecord>)
            .transpose()
            .map_err(storage)?;
        let result = AuthorityOrigin::read(
            &tx,
            &request.scope,
            &request.notify_boot,
            request.purpose,
            request.operation_id.as_deref(),
            record.as_ref(),
        )?;
        Ok(AuthorityReadReply {
            version: 1,
            request_id: request.request_id.clone(),
            notify_boot: request.notify_boot.clone(),
            scope: request.scope.clone(),
            result,
        })
    }
    fn apply(tx: &redb::WriteTransaction, payload: &[u8]) -> Result<(), NodeCoreError> {
        let mut actual = tx.open_table(ACTUAL).map_err(storage)?;
        let unchanged =
            actual.get("record").map_err(storage)?.is_some_and(|v| v.value() == payload);
        if !unchanged {
            actual.insert("record", payload).map_err(storage)?;
            let mut effects = tx.open_table(EFFECTS).map_err(storage)?;
            let count = effects.get("count").map_err(storage)?.map_or(0, |v| v.value());
            effects.insert("count", count + 1).map_err(storage)?;
        }
        Ok(())
    }
    fn effects(&self) -> TestResult<u64> {
        let tx = self.origin.begin_read()?;
        Ok(tx.open_table(EFFECTS)?.get("count")?.map_or(0, |v| v.value()))
    }
}
impl AuthorityRpc for Rpc {
    fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
        deadline: Instant,
    ) -> Result<serde_json::Value, NodeCoreError> {
        if Instant::now() >= deadline {
            return Err(SendAuthorityError::Closed.into());
        }
        let store = self.store()?;
        let decode = ramflux_protocol::canonical_json_bytes(body).map_err(storage)?;
        let result =
            match path {
                SEND_AUTHORITY_BOOT_PATH => serde_json::to_value(store.boot_reply(
                    ROUTER,
                    &ramflux_protocol::parse_i_json(&decode).map_err(storage)?,
                )?),
                SEND_AUTHORITY_STATE_PATH => serde_json::to_value(store.state_reply(
                    ROUTER,
                    &ramflux_protocol::parse_i_json(&decode).map_err(storage)?,
                )?),
                reservation::RESERVATION_PATH => serde_json::to_value(store.reservation_reply(
                    ROUTER,
                    &ramflux_protocol::parse_i_json(&decode).map_err(storage)?,
                    crate::now_unix_seconds(),
                )?),
                reservation::RESERVATIONS_PATH => serde_json::to_value(store.reservations_reply(
                    ROUTER,
                    &ramflux_protocol::parse_i_json(&decode).map_err(storage)?,
                )?),
                SEND_AUTHORITY_PATH => {
                    let request: AuthorityControlRequest =
                        ramflux_protocol::parse_i_json(&decode).map_err(storage)?;
                    let fault = self.fault.load(Ordering::SeqCst);
                    if fault == 1 && request.phase == AuthorityControlPhase::Fence {
                        self.fault.store(0, Ordering::SeqCst);
                        return Err(SendAuthorityError::Closed.into());
                    }
                    let reply = store.control_reply(
                        ROUTER,
                        &request,
                        |query| self.read(query),
                        crate::now_unix_seconds(),
                    )?;
                    if (fault == 2 && request.phase != AuthorityControlPhase::Publish)
                        || (fault == 3 && request.phase == AuthorityControlPhase::Publish)
                    {
                        self.fault.store(0, Ordering::SeqCst);
                        return Err(SendAuthorityError::Closed.into());
                    }
                    serde_json::to_value(reply)
                }
                _ => return Err(SendAuthorityError::Invalid.into()),
            };
        result.map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))
    }
}

fn record() -> TestResult<AuthorityRecord> {
    let target = ramflux_protocol::qualified_device_id(
        &ramflux_protocol::encode_base64url([71; 32]),
        "device",
    )?;
    Ok(AuthorityRecord::Owner {
        version: 1,
        target_delivery_id: target,
        owner: None,
        branch_public_key: None,
        custody_authority: None,
        revoked: true,
    })
}
fn update(client: &AuthorityClient, rpc: &Rpc, revision: u64) -> TestResult {
    let record = record()?;
    let scope = record.scope()?;
    let root = ramflux_protocol::encode_base64url([71; 32]);
    let payload = ramflux_protocol::canonical_json_bytes(
        &serde_json::json!({"record":record,"revision":revision}),
    )?;
    client.update(
        &rpc.origin,
        AuthorityUpdate {
            scope: &scope,
            record: &record,
            recipient_root: &root,
            slot_id: None,
            desired_payload: &payload,
            deadline: Instant::now() + Duration::from_secs(5),
        },
        Rpc::apply,
    )?;
    Ok(())
}

fn recover(fault: u8) -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let rpc = Rpc::new(temp.path())?;
    let client = AuthorityClient::new(rpc.clone())?;
    for revision in 1..=7 {
        update(&client, &rpc, revision)?;
    }
    let scope = record()?.scope()?;
    rpc.fault.store(fault, Ordering::SeqCst);
    assert!(
        update(&client, &rpc, 8).is_err(),
        "lost ACK injection did not interrupt the live state machine"
    );
    let original =
        AuthorityOrigin::pending(&rpc.origin, &scope)?.expect("test: retained operation");
    let high = rpc.store()?.state(&scope)?.generation;
    assert_eq!(original.mutation.generation, 8, "origin did not retain generation eight");
    assert_eq!(
        high,
        if fault == 1 { 7 } else { 8 },
        "coordinator high-water did not match the injected durable boundary"
    );
    rpc.reboot()?;
    let recovered = AuthorityClient::new(rpc.clone())?;
    rpc.fault.store(2, Ordering::SeqCst);
    assert!(update(&recovered, &rpc, 8).is_err(), "second crash did not lose the resync fence ACK");
    let second =
        AuthorityOrigin::pending(&rpc.origin, &scope)?.expect("test: second retained operation");
    assert_eq!(second.mutation.generation, 9, "resync did not use max(origin, notify)+one");
    assert_eq!(
        second.mutation.expected_generation, high,
        "resync guessed the origin's old expected generation"
    );
    assert_eq!(
        second.mutation.operation_id, original.mutation.operation_id,
        "pending desired operation was reminted"
    );
    assert_eq!(second.payload, original.payload, "resync discarded the original desired delta");
    rpc.reboot()?;
    let final_client = AuthorityClient::new(rpc.clone())?;
    update(&final_client, &rpc, 8)?;
    let final_row =
        AuthorityOrigin::pending(&rpc.origin, &scope)?.expect("test: stable recovered operation");
    assert_eq!(final_row.mutation.generation, 10, "second recovery lowered a durable high-water");
    assert_eq!(
        final_row.mutation.phase,
        AuthorityPhase::Stable,
        "recovered operation never reached stable"
    );
    assert_eq!(rpc.effects()?, 8, "recovery replayed a non-idempotent side effect");
    let mut applied = false;
    assert!(
        AuthorityOrigin::commit(&rpc.origin, &scope, &original.mutation, |_| {
            applied = true;
            Ok(())
        })
        .is_err(),
        "stale completion retained transaction ownership"
    );
    assert!(!applied, "stale tuple applied authoritative writes before checking ownership");
    assert!(
        rpc.store()?.publish(&scope, &original.mutation, &original.record).is_err(),
        "an old-boot completion opened the new boot"
    );
    Ok(())
}
#[test]
fn recovery_unreached_fence_uses_both_high_waters() -> TestResult {
    recover(1)
}
#[test]
fn recovery_persisted_fence_lost_ack_survives_second_crash() -> TestResult {
    recover(2)
}
#[test]
fn recovery_committed_lost_publish_ack_does_not_replay_effects() -> TestResult {
    recover(3)
}

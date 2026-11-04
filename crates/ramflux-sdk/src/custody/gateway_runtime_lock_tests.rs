// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native live-RPC preemption joins the host and keeps the admission lease available.

use super::*;
use crate::bus::connection_manager::NetworkingState;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct Child(Arc<AtomicBool>);
impl Drop for Child {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn frame(method: &str, body: serde_json::Value) -> LocalBusFrame {
    LocalBusFrame::request(method, Some("alice".into()), "native-preemption", method, body)
}
#[tokio::test(flavor = "current_thread")]
async fn lock_preempts_a_native_live_rpc_and_releases_its_real_account_lease()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = Box::pin(Fixture::with_mode(&[], true))
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)?;
    let (client, config) =
        Box::pin(budgets::native_config(&fixture, budgets::Origin::ExplicitEngine)).await?;
    let own = manifest(&client).map_err(|e| e as Box<dyn std::error::Error>)?;
    let reader = client.account_db()?.open_reader()?;
    let hold = Arc::new(ordinary::HeldAck {
        id: "held-native-rpc".into(),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    fixture.script.lock().map_err(|_| "script lock")?.ordinary = Some(ordinary::SessionScript {
        manifests: BTreeMap::from([(own.principal_commitment.clone(), own)]),
        held_ack: Some(Arc::clone(&hold)),
        ..ordinary::SessionScript::default()
    });
    let actor = Box::pin(NativeActor::start(
        client,
        config,
        b"native budget fixture".to_vec(),
        RuntimeTimeouts::held_for_test(),
    ))
    .await?;
    let connection = actor.connection()?;
    connection.require_live(Duration::from_secs(600)).await?;
    let path =
        fixture.config.account_root.join("custody_accounts").join("alice").join(".network.lock");
    let contender = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    // The lease covers an admission attempt, not the established session's lifetime.
    fs2::FileExt::try_lock_exclusive(&contender)?;
    fs2::FileExt::unlock(&contender)?;
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&dropped);
    let (ready, started) = tokio::sync::oneshot::channel();
    let ready = Arc::new(std::sync::Mutex::new(Some(ready)));
    connection.spawn_session_child("native-lock-proof", move |_| {
        let guard = Child(Arc::clone(&observed));
        let ready = Arc::clone(&ready);
        Box::pin(async move {
            let _guard = guard;
            if let Some(ready) =
                ready.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
            {
                let _ = ready.send(());
            }
            std::future::pending::<()>().await;
        })
    })?;
    started.await?;
    let generation = connection.generation();
    let mut request = frame(
        "message.ack",
        json!({"envelope_id":"held-native-rpc","receiver_device_id":"primary","received_at":1}),
    );
    request.operation_id = Some("native-preempted-rpc".into());
    let fingerprint = ramflux_crypto::blake3_256_base64url(
        "ramflux.operation.v1",
        &ramflux_protocol::canonical_json_bytes(&(&request.method, &request.body))?,
    );
    let pending = tokio::task::spawn_local(actor.request(request));
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    let wall = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(1), actor.request(frame("account.lock", json!({}))))
        .await??;
    assert!(wall.elapsed() < Duration::from_secs(1));
    assert!(connection.test_finished());
    assert!(dropped.load(Ordering::Acquire));
    assert_ne!(connection.generation(), generation);
    fs2::FileExt::try_lock_exclusive(&contender)?;
    fs2::FileExt::unlock(&contender)?;
    let error = pending.await?.err().ok_or("preempted native RPC succeeded")?;
    assert_eq!(crate::bus::io::local_bus_error_code(&error), "NetworkingPending");
    assert!(
        matches!(
            reader.lookup_operation("native-preempted-rpc", &fingerprint)?,
            ramflux_storage::OperationLookup::Pending
        ),
        "effects-started receipt must remain fail closed"
    );
    hold.release.notify_one();
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(connection.snapshot().state, NetworkingState::NetworkingPending);
    assert!(connection.metadata().is_none());
    actor.stop().await?;
    fixture.server.abort();
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::session_push::tests::support::{ID, sink};
const NEW: &str = "fedcba9876543210fedcba9876543210";
fn frame(seq: u64) -> ramflux_node_core::GatewayServerFrame {
    let mut envelope = crate::session::tests::test_envelope();
    envelope.target_delivery_id = "target".into();
    ramflux_node_core::GatewayServerFrame::Deliver {
        entry: ramflux_node_core::InboxEntry {
            target_delivery_id: "target".into(),
            inbox_seq: seq,
            envelope,
        },
    }
}
#[tokio::test]
async fn observed_assignment_retires_old_registration_and_replacement_survives()
-> anyhow::Result<()> {
    let hub = Arc::new(GatewaySessionHub::default());
    let (send, frames) = sink();
    let mut reg =
        hub.register_session("target".into(), "old".into(), send, Some(ID.into())).await?;
    let queue = hub
        .snapshot()
        .await
        .get("target")
        .ok_or_else(|| anyhow::anyhow!("registration"))?
        .queue
        .clone();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    queue.park_next_write(entered.clone(), release.clone());
    assert!(hub.send_delivery("target", &frame(1), Some((ID, 12345))).await);
    tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified()).await?;
    assert!(hub.send_delivery("target", &frame(2), Some((NEW, 12345))).await);
    tokio::time::timeout(std::time::Duration::from_secs(2), reg.closed.changed()).await??;
    assert!(*reg.closed.borrow());
    let (fresh, rows) = sink();
    let new =
        hub.register_session("target".into(), "fresh".into(), fresh, Some(NEW.into())).await?;
    release.add_permits(1);
    hub.unregister("target", reg.token).await;
    assert!(!*new.closed.borrow());
    assert!(hub.send_delivery("target", &frame(3), Some((NEW, 12345))).await);
    hub.flushed("target").await?;
    assert_eq!(rows.lock().map_err(|_| anyhow::anyhow!("rows"))?[0]["incarnation_id"], NEW);
    assert!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.is_empty());
    Ok(())
}
#[tokio::test]
async fn restore_rotation_stopped_gateway_captures_new_incarnation() -> anyhow::Result<()> {
    use ramflux_node_core::{RouterRedbStore, publication};
    for mode in 0..=2 {
        let root = crate::clients::tests::temp_cert_root(&format!("gateway-rotation-{mode}"))
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let store = publication::open_durability_fixture(&root, mode)?;
        let path = store.path().to_owned();
        store.initialize_inbox("target")?;
        let old = store.inbox_status("target")?.0.ok_or_else(|| anyhow::anyhow!("old E"))?;
        let hub = Arc::new(GatewaySessionHub::default());
        let (send, frames) = sink();
        let reg = hub
            .register_session("target".into(), "before-stop".into(), send, Some(old.clone()))
            .await?;
        let queue = hub
            .snapshot()
            .await
            .get("target")
            .ok_or_else(|| anyhow::anyhow!("registration"))?
            .queue
            .clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        queue.park_next_write(entered.clone(), release.clone());
        assert!(hub.send_delivery("target", &frame(1), Some((&old, 12345))).await);
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified()).await?;
        drop(hub);
        assert!(*reg.closed.borrow());
        drop(store);
        let wal = root.join("wal");
        assert_eq!(
            RouterRedbStore::rotate_inbox_incarnations_at(
                &path,
                (mode > 0).then_some(wal.as_path()),
                None
            )?,
            1
        );
        let reopened = publication::open_durability_fixture(&root, mode)?;
        let fresh = reopened.inbox_status("target")?.0.ok_or_else(|| anyhow::anyhow!("new E"))?;
        assert_ne!(old, fresh);
        let hub = Arc::new(GatewaySessionHub::default());
        let (send, rows) = sink();
        hub.register_session("target".into(), "after-start".into(), send, Some(fresh.clone()))
            .await?;
        release.add_permits(1);
        assert!(hub.send_delivery("target", &frame(2), Some((&fresh, 12345))).await);
        hub.flushed("target").await?;
        assert_eq!(rows.lock().map_err(|_| anyhow::anyhow!("rows"))?[0]["incarnation_id"], fresh);
        assert!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.is_empty());
        drop(hub);
        drop(reopened);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[tokio::test]
async fn lookup_releases_hub_before_final_admission() -> anyhow::Result<()> {
    let hub = Arc::new(GatewaySessionHub::default());
    let (send, _) = sink();
    hub.register_session("target".into(), "session".into(), send, Some(ID.into())).await?;
    let queue = hub
        .snapshot()
        .await
        .get("target")
        .ok_or_else(|| anyhow::anyhow!("registration"))?
        .queue
        .clone();
    let weak = Arc::downgrade(&hub);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    queue.set_admission_probe(Box::new(move || {
        let Some(hub) = weak.upgrade() else {
            return;
        };
        assert!(hub.senders_by_target.try_lock().is_ok());
        observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }));
    assert!(hub.send_delivery("target", &frame(1), Some((ID, 12345))).await);
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    Ok(())
}
#[tokio::test]
async fn mesh_epoch_observations_retire_before_reply() -> anyhow::Result<()> {
    use crate::session_push::tests::support::{Fixture, runtime};
    use serde_json::json;
    for kind in 0..4 {
        let mut fixture = Fixture::new(&format!("epoch-observation-{kind}"))?;
        let rt = runtime()?;
        let (send, rows) = sink();
        let reg = fixture
            .context
            .hub
            .register_session("target".into(), "session".into(), send.clone(), Some(ID.into()))
            .await?;
        let request = match kind {
            0 => {
                json!({"frame_type":"resume","incarnation_id":ID,"resume":{"target_delivery_id":"target","resume_token":rt.resume_token,"after_inbox_seq":0,"limit":16}})
            }
            3 => json!({"frame_type":"ack_batch","incarnation_id":ID,"inbox_seqs":[1]}),
            _ => json!({"frame_type":"fetch_entry","incarnation_id":ID,"inbox_seq":1}),
        };
        let context = fixture.context.clone();
        let task = tokio::spawn(async move {
            crate::session_push::handle(&send, &context, &rt, &serde_json::to_vec(&request)?).await
        });
        if kind >= 2 {
            let req = fixture.next().await?;
            req.respond.send((200,json!({"issued":[{"target_delivery_id":"target","incarnation_id":ID,"inbox_seq":1}]}))).map_err(|_|anyhow::anyhow!("issued cancelled"))?;
        }
        let req = fixture.next().await?;
        let reply = if kind == 1 {
            json!({"issued":[{"target_delivery_id":"target","incarnation_id":NEW,"inbox_seq":1}]})
        } else if kind == 3 {
            json!({"reason":"incarnation_mismatch"})
        } else {
            json!({"incarnation_id":NEW})
        };
        req.respond
            .send((if kind == 3 { 400 } else { 200 }, reply))
            .map_err(|_| anyhow::anyhow!("reply cancelled"))?;
        assert!(tokio::time::timeout(std::time::Duration::from_secs(5), task).await??.is_err());
        assert!(*reg.closed.borrow());
        assert!(rows.lock().map_err(|_| anyhow::anyhow!("rows"))?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn stale_handler_cannot_retire_same_incarnation_replacement() -> anyhow::Result<()> {
    let hub = Arc::new(GatewaySessionHub::default());
    let (old, _) = sink();
    hub.register_session("target".into(), "old".into(), old.clone(), Some(ID.into())).await?;
    let (fresh, _) = sink();
    let new = hub.register_session("target".into(), "new".into(), fresh, Some(ID.into())).await?;
    hub.retire_incarnation("target", ID, &old).await;
    assert!(!*new.closed.borrow());
    assert!(hub.send_delivery("target", &frame(1), Some((ID, 12345))).await);
    Ok(())
}

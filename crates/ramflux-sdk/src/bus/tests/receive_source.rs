// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A cold sender directory lookup cannot retain the account writer while the peer is silent.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{command, controls, start};
use crate::prelude::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_source_manifest_keeps_reads_and_local_mutations_available() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-source-manifest")).await?;
    fixture.inbound().await?;
    let peer = fixture.peer.client.owned_device_identity()?;
    let root = peer.root_commitment().to_owned();
    let db = fixture.source.client.account_db()?;
    db.remove_actor_state(&format!("directory/device/{}", peer.storage_key()))?;
    db.remove_actor_state(&format!("directory/device/{}", peer.device_id()))?;
    assert!(db.client_device_record(&peer)?.is_none());
    let entry = fixture.gateway.lock().map_err(|_| "gateway")?.inbox[0].clone();
    assert_eq!(fixture.source.client.inbound_device_manifest_request(&entry)?, Some(root.clone()));
    let hold = Arc::new(GatewayHold::default());
    fixture.gateway.lock().map_err(|_| "gateway")?.manifest_hold = Some((root, Arc::clone(&hold)));
    let gateway = Arc::clone(&fixture.gateway);
    let started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    controls(&started.actor).await?;
    assert!(
        gateway.lock().map_err(|_| "gateway")?.acked.is_empty(),
        "the source lookup must still be held"
    );
    hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if gateway.lock().map_err(|_| "gateway")?.acked.len() == 2 {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let response = started
        .actor
        .request(command("message.read", json!({"conversation_id":"healthy"})))
        .await?;
    assert!(response.body["messages"].as_array().is_some_and(|messages| {
        messages.iter().any(|message| message["body_utf8"] == "courier stays responsive")
    }));
    let wall = std::time::Instant::now();
    started.actor.stop().await?;
    assert!(wall.elapsed() < Duration::from_secs(1));
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn background_receive_redrives_a_due_contact_floor_behind_the_live_cursor() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            redrive_case(),
        ))))
        .await
}
async fn redrive_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-backpressure-floor")).await?;
    fixture.inbound().await?;
    let now = now_unix_timestamp();
    let client = &fixture.source.client;
    client.persist_gateway_receive_cursor("sender", 100)?;
    // A durable contact floor is a mailbox range, not an in-memory availability hint.
    // Even entries now behind the monotonic live cursor must be looked up again.
    client.account_db()?.persist_actor_state(
        "contact-admission/backpressure",
        &json!({
            "floor":1,"next_at":now-1,"expires_at":now+3600,"scan":null,"roots":{}
        }),
    )?;
    let gateway = Arc::clone(&fixture.gateway);
    let started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if gateway.lock().map_err(|_| "gateway")?.acked.len() == 2 {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    {
        let gateway = gateway.lock().map_err(|_| "gateway")?;
        assert_eq!(gateway.resumes, [100, 0]);
        assert_eq!(gateway.acked.len(), 2);
        assert_eq!(gateway.protocol_errors, Vec::<String>::new());
    }
    let response = started
        .actor
        .request(command("message.read", json!({"conversation_id":"healthy"})))
        .await?;
    assert!(response.body["messages"].as_array().is_some_and(|messages| {
        messages.iter().any(|message| message["body_utf8"] == "courier stays responsive")
    }));
    started.actor.stop().await?;
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn receive_preview_validates_authority_without_publishing_duplicate_directory_observations()
-> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut fixture = Box::pin(Fixture::new("receive-preview-observation")).await?;
            fixture.inbound().await?;
            let entry = fixture.gateway.lock().map_err(|_| "gateway")?.inbox[0].clone();
            let identity = fixture.peer.client.owned_device_identity()?;
            let client = &fixture.source.client;
            client.account_db()?.upsert_device_directory_entry(
                identity.device_id(),
                identity.root_commitment(),
                "prior-observation",
                1,
            )?;
            client.prepare_inbound_device_manifest(&entry, None)?;
            let preview = client
                .account_db()?
                .device_directory_entry(identity.storage_key())?
                .ok_or("prior observation")?;
            assert_eq!(preview.verified_at, 1);
            assert_eq!(preview.source, "prior-observation");
            let mut invalid = entry.clone();
            invalid.envelope.signed.signature = "invalid".into();
            assert!(
                client.prepare_inbound_device_manifest(&invalid, None).is_err(),
                "preview must still authenticate the envelope"
            );
            client.apply_inbound_device_manifest(&entry, None)?;
            let applied = client
                .account_db()?
                .device_directory_entry(identity.storage_key())?
                .ok_or("committed observation")?;
            assert!(applied.verified_at > 1);
            assert_eq!(applied.source, "inbound_signature");
            let root = fixture.root.clone();
            drop(fixture);
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))
        .await
}

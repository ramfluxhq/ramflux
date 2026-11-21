// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Material deadlines cannot cancel an already queued actor checkpoint.

use super::*;
use crate::bus::dispatch::task_transport::Target;
use std::{future::Future as _, task::Poll};

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cached_material_writer_wait_does_not_spend_the_network_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(
        Duration::from_secs(20),
        Box::pin(async {
            use crate::client::native_test_support::{
                Fixture, activation_send::tests::task_content,
            };
            use prost::Message as _;
            let source = Fixture::new("task-courier-sender").await?;
            let peer = Fixture::new("task-courier-peer").await?;
            source.accept_peer(&peer)?;
            peer.accept_peer(&source)?;
            let remote = peer.client.owned_device_identity()?;
            let conversation = source.client.generated_direct_conversation_id(&remote)?;
            let typed = task_content(&source, &peer, &conversation)?;
            let Some(ramflux_protocol::message::content::Value::Task(task)) = typed.value else {
                return Err("test: typed Task content missing".into());
            };
            let task_bytes = task.encode_to_vec();
            let mut account = source.into_bus();
            let local = account.client.owned_device_identity()?;
            let pair = ramflux_crypto::DmSession::initiator(
                [17; 32],
                dm_device_id_hash(local.device_id()),
                dm_device_id_hash(remote.device_id()),
                [3; 32],
            )?;
            account.client.persist_pair(&local, &remote, &[4; 32], &pair)?;
            let draft = Draft::new(
                &account,
                Target {
                    device: remote.device_id().into(),
                    identity: remote,
                    delivery: "peer".into(),
                    federation: None,
                    own: false,
                },
                &conversation,
                &task_bytes,
                crate::client::routed::Route::control(),
            )?;
            assert!(draft.request.root.is_none(), "verified authority is cached");
            assert!(
                draft.request.prekey.is_none(),
                "the established pair needs no network material"
            );
            let mut limits = crate::bus::runtime_limits::RuntimeTimeouts::held_for_test();
            limits.network_wait =
                crate::bus::runtime_limits::RuntimeTimeouts::default().network_wait;
            let (handle, mut sessions) =
                crate::bus::connection_manager::tests::reconnecting_fixture(limits)?;
            let _io = sessions.recv().await.ok_or("session connector did not start")?;
            handle.require_live(Duration::from_secs(5)).await?;
            let context = handle.test_context();
            let (sender, mut queued) = mpsc::channel(1);
            let writer = Writer::new(sender, context.generation);
            let plan = Plan {
                // The item has been removed, so the actor must observe that and skip sealing.
                // A network timeout must not replace that writer-owned validity decision.
                item: Item {
                    key: "task/forward/removed".into(),
                    revision: "removed".into(),
                    requests: Vec::new(),
                    failure: None,
                },
                routing: routing_fingerprint(&account, &conversation)?,
                conversation: conversation.clone(),
                drafts: vec![draft],
                config: account.gateway_config.clone(),
                approval: false,
            };
            let mut sending = Box::pin(send(&context, &writer, plan));
            std::future::poll_fn(|cx| {
                assert!(sending.as_mut().poll(cx).is_pending(), "wait for the actor checkpoint");
                Poll::Ready(())
            })
            .await;
            let AccountWork::Courier(checkpoint) = queued.try_recv()? else {
                return Err("expected a real writer checkpoint".into());
            };
            tokio::time::advance(context.network_wait()).await;
            std::future::poll_fn(|cx| {
                assert!(
                    sending.as_mut().poll(cx).is_pending(),
                    "waiting for the writer must not become a network failure"
                );
                Poll::Ready(())
            })
            .await;
            checkpoint.apply(&mut account);
            assert!(
                matches!(tokio::time::timeout(Duration::from_secs(1), sending).await??, Sent::Done),
                "the actor must skip the removed item without a charged network failure"
            );
            handle.stop().await;
            Ok(())
        }),
    )
    .await?
}

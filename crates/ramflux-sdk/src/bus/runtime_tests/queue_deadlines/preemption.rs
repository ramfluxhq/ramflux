// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Priority lifecycle requests cancel an active exchange without applying its late response.

use super::*;

struct ChildDrop(Arc<AtomicBool>);
impl Drop for ChildDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}
#[tokio::test]
async fn lock_preempts_a_held_live_rpc_and_drops_its_late_reply() -> Case {
    LocalSet::new()
        .run_until(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Fixture { actor, connection, mut io, root, reader, router } =
                fixture(Duration::from_secs(600)).await?;
            let (supervisor, caller) = supervised_actor(&actor, &root)?;
            let (started, entered) = oneshot::channel();
            let started = Arc::new(std::sync::Mutex::new(Some(started)));
            let child_dropped = Arc::new(AtomicBool::new(false));
            let dropped = Arc::clone(&child_dropped);
            connection.spawn_session_child("preemption-proof", move |_| {
                let started = Arc::clone(&started);
                let dropped = Arc::clone(&dropped);
                Box::pin(async move {
                    let _guard = ChildDrop(dropped);
                    if let Some(started) =
                        started.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
                    {
                        let _ = started.send(());
                    }
                    std::future::pending::<()>().await;
                })
            })?;
            entered.await?;
            let generation = connection.generation();
            let owner = actor.clone();
            let held = tokio::task::spawn_local(async move {
                owner
                    .request(command(
                        "message.ack",
                        json!({"envelope_id":"held-live",
                "receiver_device_id":"device-alice","received_at":1}),
                    ))
                    .await
            });
            assert!(
                matches!(io.output.recv().await, Some(GatewayClientFrame::Ack { .. })),
                "real RPC reached its transport hold"
            );
            let wall = std::time::Instant::now();
            tokio::time::timeout(
                Duration::from_secs(1),
                supervisor.request(command("account.lock", json!({})).request, &caller),
            )
            .await??;
            assert!(wall.elapsed() < Duration::from_secs(1));
            assert!(
                connection.test_finished(),
                "lock must join manager and auxiliary tasks before replying"
            );
            assert!(child_dropped.load(std::sync::atomic::Ordering::Acquire));
            assert_ne!(connection.generation(), generation);
            assert_eq!(
                connection.snapshot().state,
                crate::bus::connection_manager::NetworkingState::NetworkingPending
            );
            let error = held.await?.err().ok_or("preempted call unexpectedly completed")?;
            assert_eq!(crate::bus::io::local_bus_error_code(&error), "NetworkingPending");
            assert!(
                io.input
                    .send(serde_json::to_vec(&GatewayServerFrame::Ack {
                        cursor: GatewayCursor {
                            target_delivery_id: "target".into(),
                            inbox_seq: 999,
                            last_envelope_id: Some("held-live".into()),
                            acked_envelope_ids: vec!["held-live".into()],
                            nacked_envelope_ids: BTreeMap::new(),
                        }
                    })?)
                    .is_err(),
                "late reply must have no surviving stream"
            );
            assert!(matches!(
                supervisor.request(command("account.status", json!({})).request, &caller).await,
                Err(SdkError::AccountNotOpen(_))
            ));
            assert_eq!(
                connection.snapshot().state,
                crate::bus::connection_manager::NetworkingState::NetworkingPending
            );
            supervisor.shutdown().await?;
            drop(supervisor);
            actor.stop().await?;
            drop(actor);
            drop(connection);
            drop(reader);
            router.await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        })))
        .await
}

#[tokio::test]
async fn account_switch_answers_while_a_network_command_is_stalled() -> Case {
    LocalSet::new()
        .run_until(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Fixture { actor, connection, mut io, root, reader, router } =
                fixture(Duration::from_secs(600)).await?;
            let config = LocalBusConfig::new(root.join("bus.sock"), &root);
            let bob = crate::bus::runtime_tests::actor_account(
                &root,
                "bob",
                None,
                Arc::new(AtomicBool::new(false)),
            );
            let supervisor = crate::bus::supervisor::Supervisor::from_initializers(
                &config,
                vec![("bob".into(), bob)],
                Some("alice".into()),
            )?;
            supervisor.install_test_actor("alice".into(), actor.clone());
            let caller = actor.clone();
            let held = tokio::task::spawn_local(async move {
                caller
                    .request(command(
                        "message.ack",
                        json!({"envelope_id":"held-switch",
                "receiver_device_id":"device-alice","received_at":1}),
                    ))
                    .await
            });
            assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Ack { .. })));
            let (outbound, _) = mpsc::channel(8);
            let connection_state = LocalBusConnectionState::new(1, outbound);
            for id in ["bob", "alice"] {
                let wall = std::time::Instant::now();
                let request = LocalBusFrame::request(
                    "switch",
                    Some(id.into()),
                    "account",
                    "account.switch",
                    json!({}),
                );
                let result = tokio::time::timeout(
                    Duration::from_secs(1),
                    supervisor.request(request, &connection_state),
                )
                .await??;
                assert!(wall.elapsed() < Duration::from_secs(1));
                assert_eq!(result.body["active_account_id"], id);
                assert!(!held.is_finished(), "switch must finish while the transport remains held");
            }
            assert!(io.output.try_recv().is_err(), "switch must not send on A's session");
            supervisor.shutdown().await?;
            assert!(held.await?.is_err());
            assert!(connection.test_finished());
            drop(supervisor);
            drop(actor);
            drop(connection);
            drop(reader);
            router.await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        })))
        .await
}

fn supervised_actor(
    actor: &AccountActor,
    root: &std::path::Path,
) -> Result<
    (std::rc::Rc<crate::bus::supervisor::Supervisor>, LocalBusConnectionState),
    Box<dyn std::error::Error>,
> {
    let config = LocalBusConfig::new(root.join("bus.sock"), root);
    let supervisor =
        crate::bus::supervisor::Supervisor::from_initializers(&config, Vec::new(), None)?;
    supervisor.install_test_actor("alice".into(), actor.clone());
    let (outbound, _) = mpsc::channel(8);
    Ok((supervisor, LocalBusConnectionState::new(1, outbound)))
}

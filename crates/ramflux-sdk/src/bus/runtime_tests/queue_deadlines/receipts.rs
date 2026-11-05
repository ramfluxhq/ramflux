// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Concurrent keyed calls share one effect; a failed exchange retains its pending receipt.

use super::*;
use crate::bus::mutation_intent::MutationIntent;

fn ack(key: &str) -> AccountCommand {
    let mut request = command(
        "message.ack",
        json!({"envelope_id":key,"receiver_device_id":"device-alice","received_at":1}),
    );
    request.request.operation_id = Some(key.into());
    request
}
#[tokio::test]
async fn concurrent_keyed_network_calls_share_one_effect_and_effects_started_fail_closed() -> Case {
    LocalSet::new()
        .run_until(crate::bus::connection_manager::tests::watchdog(async {
            let Fixture { actor, connection, mut io, root, reader, router } =
                fixture(Duration::from_secs(600)).await?;
            let owner = actor.clone();
            let first =
                tokio::task::spawn_local(async move { owner.request(ack("same-key")).await });
            assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Ack { .. })));
            let owner = actor.clone();
            let second =
                tokio::task::spawn_local(async move { owner.request(ack("same-key")).await });
            let cursor = GatewayCursor {
                target_delivery_id: "target".into(),
                inbox_seq: 7,
                last_envelope_id: Some("same-key".into()),
                acked_envelope_ids: vec!["same-key".into()],
                nacked_envelope_ids: BTreeMap::new(),
            };
            io.input
                .send(serde_json::to_vec(&GatewayServerFrame::Ack { cursor: cursor.clone() })?)?;
            io.input
                .send(serde_json::to_vec(&GatewayServerFrame::Cursor { cursor: Some(cursor) })?)?;
            let original = first.await??;
            let replay = second.await??;
            assert_eq!(original.body, replay.body);
            assert!(io.output.try_recv().is_err(), "same-key retry must not write a second ACK");
            assert!(MutationIntent::new(&ack("same-key").request)?.lookup(&reader)?.is_some());
            let owner = actor.clone();
            let failed =
                tokio::task::spawn_local(
                    async move { owner.request(ack("effects-started")).await },
                );
            assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Ack { .. })));
            io.input.send(serde_json::to_vec(&GatewayServerFrame::Nack {
                reason: "scripted effects-started refusal".into(),
            })?)?;
            assert!(failed.await?.is_err());
            let error = actor
                .request(ack("effects-started"))
                .await
                .err()
                .ok_or("pending key was replayed")?;
            assert!(matches!(
                error,
                SdkError::Storage(StorageError::OperationReconciliationRequired { .. })
            ));
            assert!(
                io.output.try_recv().is_err(),
                "pending receipt must fail closed before another network effect"
            );
            actor.stop().await?;
            drop(actor);
            drop(connection);
            drop(reader);
            router.await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))
        .await
}

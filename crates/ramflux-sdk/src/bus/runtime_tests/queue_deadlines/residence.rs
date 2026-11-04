// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Queued requests expire without receipts or effects while a real actor exchange is held.

use super::*;
use crate::bus::mutation_intent::MutationIntent;

#[tokio::test(start_paused = true)]
async fn queued_ordinary_requests_expire_at_five_seconds_and_full_admission_refuses_immediately()
-> Case {
    Box::pin(
        tokio::task::LocalSet::new()
            .run_until(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))),
    )
    .await
}

async fn case() -> Case {
    let clock = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let Fixture { mut actor, connection, mut io, root, reader, router } =
        fixture(Duration::from_secs(600)).await?;
    let retained = Arc::new(crate::bus::command_admission::ExpiredReplies::default());
    actor.expired_replies = Some(Arc::clone(&retained));
    let owner = actor.clone();
    let mut active = tokio::task::spawn_local(async move {
        owner
            .request(command(
                "message.ack",
                json!({"envelope_id":"active-a",
            "receiver_device_id":"device-alice","received_at":1}),
            ))
            .await
    });
    let first = tokio::select! {
        frame=io.output.recv()=>frame,
        result=&mut active=>return Err(format!("A finished before its transport barrier: {}", match result? {
            Ok(_) => "unexpected success".into(), Err(error) => error.to_string(),
        }).into()),
    };
    assert!(
        matches!(first, Some(GatewayClientFrame::Ack { .. })),
        "A entered its real transport call"
    );
    let start = Instant::now();
    let Queued { frames, replies, fillers } = queue_requests(&actor);
    while actor.sender.capacity() != 0 {
        tokio::task::yield_now().await;
    }
    let read_started = std::time::Instant::now();
    let status = actor.request(command("account.status", json!({}))).await?;
    assert!(read_started.elapsed() < Duration::from_secs(1));
    assert_eq!(status.body["networking"], "live");
    let wall = std::time::Instant::now();
    assert!(
        actor
            .request(command("contact.requests.policy.set", json!({"contact_requests":"manual"})))
            .await
            .is_err()
    );
    assert!(wall.elapsed() < Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(5)).await;
    for (index, reply) in replies.into_iter().enumerate() {
        let result = reply.await?;
        if index < 2 {
            assert!(
                matches!(result, Err(SdkError::NetworkingPendingContext { .. })),
                "network requests must expire as NetworkingPending"
            );
        } else {
            assert!(result.is_err());
        }
    }
    for reply in fillers {
        assert!(reply.await?.is_err());
    }
    assert_eq!(start.elapsed(), Duration::from_secs(5));
    assert_eq!(retained.len(), 64, "receiver closure must not mask the claim fence");
    assert_no_receipts(&reader, &frames)?;
    assert!(reader.client_record("settings", "contact_requests")?.is_none());
    assert!(io.output.try_recv().is_err(), "queued network requests cannot write a frame");
    io.input.send(serde_json::to_vec(&GatewayServerFrame::Nack { reason: "release A".into() })?)?;
    assert!(active.await?.is_err());
    let responder = assert_discard(&actor, &reader, &retained, &frames, io).await?;
    actor.stop().await?;
    responder.abort();
    let _ = responder.await;
    drop(actor);
    drop(connection);
    drop(reader);
    router.await?;
    clock.abort();
    let _ = clock.await;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

type Reply = tokio::task::JoinHandle<Result<crate::bus::actor::ActorResponse, SdkError>>;
struct Queued {
    frames: Vec<LocalBusFrame>,
    replies: Vec<Reply>,
    fillers: Vec<Reply>,
}
fn queue_requests(actor: &AccountActor) -> Queued {
    let requests = [
        command(
            "contact.request",
            json!({"link_id":"new-link","requester_id":"alice","target_id":"bob",
            "conversation_id":"thread","message_id":"message-b","envelope_id":"envelope-b",
            "source_principal_id":"alice","sender_id":"device-alice","recipient_device_id":"device-bob",
            "target_delivery_id":"bob-target","federation":{"federation_url":"http://127.0.0.1:9",
            "source_node_id":"source","target_node_id":"target","required_capability":"contact"}}),
        ),
        command(
            "message.submit",
            json!({"conversation_id":"friend","message_id":"message-c",
            "envelope_id":"envelope-c","source_principal_id":"alice","sender_id":"device-alice",
            "recipient_device_id":"device-alice","target_delivery_id":"target",
            "encrypted_body_base64":"b3BhcXVl","created_at":now_unix_timestamp(),"ttl":600}),
        ),
        command("contact.requests.policy.set", json!({"contact_requests":"auto_accept"})),
    ];
    let frames = requests.iter().map(|command| command.request.clone()).collect::<Vec<_>>();
    let mut replies = Vec::new();
    for (index, mut request) in requests.into_iter().enumerate() {
        if index < 2 {
            request.request.operation_id = Some(format!("queued-{index}"));
        }
        let owner = actor.clone();
        replies.push(tokio::task::spawn_local(async move { owner.request(request).await }));
    }
    let mut fillers = Vec::new();
    for _ in 3..64 {
        let owner = actor.clone();
        fillers.push(tokio::task::spawn_local(async move {
            owner
                .request(command(
                    "contact.requests.policy.set",
                    json!({"contact_requests":"manual"}),
                ))
                .await
        }));
    }

    Queued { frames, replies, fillers }
}

fn assert_no_receipts(reader: &AccountDb, frames: &[LocalBusFrame]) -> Result<(), SdkError> {
    for (index, mut frame) in frames.iter().take(2).cloned().enumerate() {
        frame.operation_id = Some(format!("queued-{index}"));
        assert!(MutationIntent::new(&frame)?.lookup(reader)?.is_none());
    }
    Ok(())
}

async fn assert_discard(
    actor: &AccountActor,
    reader: &AccountDb,
    retained: &crate::bus::command_admission::ExpiredReplies,
    frames: &[LocalBusFrame],
    mut io: SessionIo,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let late_writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let recorded = Arc::clone(&late_writes);
    let reject = io.input.clone();
    let responder = tokio::spawn(async move {
        while io.output.recv().await.is_some() {
            recorded.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let answer = serde_json::to_vec(&GatewayServerFrame::Nack {
                reason: "unexpected expired command".into(),
            });
            if let Ok(answer) = answer {
                let _ = reject.send(answer);
            }
        }
    });
    // A valid local command is ordered after the expired queue; its completion is the discard barrier.
    actor
        .request(command(
            "conversation.mute",
            json!({"conversation_id":"discard-barrier","mute_until":i64::MAX}),
        ))
        .await?;
    assert!(
        reader.client_record("settings", "contact_requests")?.is_none(),
        "D and every filler must be discarded without effects"
    );
    assert_eq!(
        late_writes.load(std::sync::atomic::Ordering::Acquire),
        0,
        "expired command wrote a frame"
    );
    assert!(retained.all_closed(), "the actor must drop every expired command reply");
    assert_no_receipts(reader, frames)?;

    Ok(responder)
}

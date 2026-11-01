// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deadline retries resume confirmed ACKs without skipping an in-flight or differently bound ACK.
use super::*;

#[tokio::test(start_paused = true)]
async fn scheduler_deadline_resumes_durable_ack_progress_instead_of_restarting_the_ack_pass()
-> Result<(), SdkError> {
    let mut fixture = Fixture::new()?;
    let mut seen = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        fixture.client.acknowledge_received_attachment_with(&fixture.reference, 3, async |index| {
            seen.push(index);
            if index == 1 {
                tokio::time::sleep(Duration::from_secs(21)).await;
            }
            Ok(())
        }),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(seen, [0, 1]);
    let indexed: Vec<AckProgress> = fixture
        .client
        .account_db()?
        .message_copy_actor_states("object:remote-object", "attachment/ack/")?;
    assert_eq!(indexed.len(), 1, "ACK progress must participate in message erasure");
    drop(std::mem::replace(&mut fixture.client, RamfluxClient::new()));
    fixture.client = open(&fixture.root, false)?;
    seen.clear();
    fixture
        .client
        .acknowledge_received_attachment_with(&fixture.reference, 3, async |index| {
            seen.push(index);
            Ok(())
        })
        .await?;
    assert_eq!(seen, [1, 2], "unconfirmed ACK must retry, confirmed ACK must not restart");
    seen.clear();
    fixture
        .client
        .acknowledge_received_attachment_with(&fixture.reference, 3, async |index| {
            seen.push(index);
            Ok(())
        })
        .await?;
    assert_eq!(seen, [] as [u32; 0]);
    let mut changed = fixture.reference.clone();
    changed.relay_endpoint = "quic://other-relay.invalid:7447".into();
    fixture
        .client
        .acknowledge_received_attachment_with(&changed, 3, async |index| {
            seen.push(index);
            Ok(())
        })
        .await?;
    assert_eq!(seen, [0, 1, 2], "another relay must not inherit ACK progress");
    Ok(())
}

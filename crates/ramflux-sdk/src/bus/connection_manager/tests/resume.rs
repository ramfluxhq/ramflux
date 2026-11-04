// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authoritative pages cannot inherit a later push's cursor, even during the Resume exchange.

use super::{GatewayClientFrame, GatewayServerFrame, entry, fixture, send};
use std::time::Duration;
use tokio::time::Instant;

#[tokio::test]
async fn account_resume_keeps_future_pushes_out_of_the_durable_page()
-> Result<(), Box<dyn std::error::Error>> {
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let call = {
            let handle = handle.clone();
            tokio::spawn(async move {
                handle.call(
                    |engine| Box::pin(engine.resume_authoritative_after(0, 64)),
                    Instant::now() + Duration::from_secs(600),
                ).await
            })
        };
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Resume { resume }) if resume.after_inbox_seq == 0));
        send(&io, &GatewayServerFrame::Deliver { entry: entry("future-push", 1000)? })?;
        send(&io, &GatewayServerFrame::Resume { entries: vec![entry("first-durable", 1)?] })?;
        let page = call.await??;
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].inbox_seq, 1, "a later push must not skip the unscanned range");
        let remaining = handle.call(
            |engine| Box::pin(async move { Ok(engine.pending_deliveries.len()) }),
            Instant::now() + Duration::from_secs(600),
        ).await?;
        assert_eq!(remaining, 0, "the durable page hands off the bounded push cache");
        handle.stop().await;
        Ok(())
    }).await
}

#[tokio::test]
async fn direct_sdk_resume_keeps_interleaved_push_delivery_compatibility()
-> Result<(), Box<dyn std::error::Error>> {
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let call = {
            let handle = handle.clone();
            tokio::spawn(async move {
                handle
                    .call(
                        |engine| Box::pin(engine.resume_after(0, 64)),
                        Instant::now() + Duration::from_secs(600),
                    )
                    .await
            })
        };
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Resume { .. })));
        send(&io, &GatewayServerFrame::Deliver { entry: entry("interleaved", 1000)? })?;
        send(&io, &GatewayServerFrame::Resume { entries: vec![entry("first", 1)?] })?;
        let page = call.await??;
        assert_eq!(page.iter().map(|entry| entry.inbox_seq).collect::<Vec<_>>(), vec![1000, 1]);
        handle.stop().await;
        Ok(())
    })
    .await
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A ready durable checkpoint must let the session executor run first.

use super::*;
use std::{
    future::Future as _,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
};

#[tokio::test(flavor = "current_thread")]
async fn writer_checkpoint_yields_to_ready_session_tasks() -> Case {
    watch(30, async {
        LocalSet::new()
            .run_until(async {
                let mut fixture = Box::pin(Fixture::new("receive-checkpoint-fairness")).await?;
                stop_peer_session(&mut fixture).await;
                let mut runtime = start_runtime(&mut fixture).await?;
                let handle = account_of(&runtime)?.connection.clone().ok_or("connection handle")?;
                let writer = crate::bus::couriers::writer::Writer::new(
                    runtime.connection_sender.clone(),
                    handle.generation(),
                );
                let polled = Arc::new(AtomicBool::new(false));
                let observed = Arc::clone(&polled);
                let mut checkpoint = Box::pin(writer.apply(move |_account| {
                    assert!(
                        observed.load(Ordering::Acquire),
                        "a ready session task must run before another synchronous writer checkpoint"
                    );
                    Ok(())
                }));
                // Enqueue through the real writer without yielding to the executor yet.
                std::future::poll_fn(|cx| {
                    assert!(
                        checkpoint.as_mut().poll(cx).is_pending(),
                        "the writer must wait for the account-owned checkpoint"
                    );
                    Poll::Ready(())
                })
                .await;
                let work = runtime.connection_work.try_recv()?;
                let observer = tokio::spawn(async move {
                    polled.store(true, Ordering::Release);
                });
                runtime.apply_connection_work(work).await?;
                checkpoint.await?;
                observer.await?;
                runtime.stop_connection().await;
                Ok(())
            })
            .await
    })
    .await
}

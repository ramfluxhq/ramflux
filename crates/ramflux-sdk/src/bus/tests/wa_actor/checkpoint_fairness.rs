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
    watch(60, async {
        LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir()?;
                let mut fixture =
                    Box::pin(Fixture::build_at(root.path().to_path_buf(), false, None)).await?;
                stop_peer_session(&mut fixture).await;
                let mut runtime = start_runtime(&mut fixture).await?;
                let handle = account_of(&runtime)?.connection.clone().ok_or("connection handle")?;
                let (checkpoints, mut queued) = tokio::sync::mpsc::channel(1);
                let writer =
                    crate::bus::couriers::writer::Writer::new(checkpoints, handle.generation());
                let polled = Arc::new(AtomicBool::new(false));
                let session_turn = Arc::clone(&polled);
                let mut checkpoint = Box::pin(tokio::task::unconstrained(writer.apply(move |_account| {
                    assert!(
                        session_turn.load(Ordering::Acquire),
                        "a ready session task must run before another synchronous writer checkpoint"
                    );
                    Ok(())
                })));
                // Enqueue through the real writer without yielding to the executor yet.
                std::future::poll_fn(|cx| {
                    assert!(
                        checkpoint.as_mut().poll(cx).is_pending(),
                        "the writer must wait for the account-owned checkpoint"
                    );
                    Poll::Ready(())
                })
                .await;
                let work = queued.try_recv()?;
                let ready_task = tokio::spawn(async move {
                    polled.store(true, Ordering::Release);
                });
                runtime.apply_connection_work(work).await?;
                checkpoint.await?;
                ready_task.await?;
                runtime.stop_connection().await;
                Ok(())
            })
            .await
    })
    .await
}

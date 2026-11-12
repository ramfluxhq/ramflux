// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded network offloads waits for disk; network workers never wait on the writer gate.
use crate::GatewayQuicContext;

pub(crate) async fn run<T, F>(context: &GatewayQuicContext, work: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&GatewayQuicContext) -> anyhow::Result<T> + Send + 'static,
{
    let permit = context.store.try_admit_async_write()?;
    let context = context.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(&context)
    })
    .await?
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent cancellation, wake and failure backoff for a single courier.

use super::writer::Writer;
use crate::SdkError;
use crate::bus::connection_manager::{AccountWork, SessionContext};
use std::{future::Future, time::Duration};
use tokio::sync::mpsc;

pub(crate) async fn run<F, R>(
    context: SessionContext,
    sender: mpsc::Sender<AccountWork>,
    name: &'static str,
    pass: F,
) where
    F: Fn(SessionContext, Writer) -> R,
    R: Future<Output = Result<bool, SdkError>>,
{
    let writer = Writer::new(sender, context.generation);
    let mut cancel = context.cancel.clone();
    loop {
        let outcome = tokio::select! {biased;_=cancel.changed()=>break,result=pass(context.clone(),writer.clone())=>result};
        let failed = outcome.is_err();
        let active = match outcome {
            Ok(active) => active,
            Err(error) => {
                tracing::debug!(%error,courier=name,"courier deferred");
                false
            }
        };
        let delay = if active { Duration::from_millis(10) } else { context.network_wait() };
        tokio::select! {biased;_=cancel.changed()=>break,()=tokio::time::sleep(delay)=>{},()=context.courier_wake(name),if !failed=>{}}
    }
}

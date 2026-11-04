// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise the production courier phases with a real account writer and resident test transport.

use super::writer::Writer;
use crate::SdkError;
use crate::bus::connection_manager::{AccountWork, SessionContext};
use crate::prelude::LocalBusAccountState;
use std::future::Future;
use tokio::sync::mpsc;

pub(crate) fn drive<'a, F, R>(
    account: &'a mut LocalBusAccountState,
    pass: F,
) -> std::pin::Pin<Box<dyn Future<Output = Result<bool, SdkError>> + 'a>>
where
    F: FnOnce(SessionContext, Writer) -> R + 'a,
    R: Future<Output = Result<bool, SdkError>> + 'a,
{
    Box::pin(async move {
        let session = account.session_client().await?;
        account.apply_session_metadata(session);
        let context = account
            .connection
            .as_ref()
            .ok_or(SdkError::GatewaySessionNotEstablished)?
            .test_context();
        let generation = context.generation;
        let (sender, mut receive) = mpsc::channel(2);
        let future = pass(context, Writer::new(sender, generation));
        tokio::pin!(future);
        loop {
            tokio::select! {
                result=&mut future=>return result,
                work=receive.recv()=>match work {
                    Some(AccountWork::Courier(work)) if work.generation==generation=>work.apply(account),
                    _=>return Err(SdkError::GatewaySessionNotEstablished),
                }
            }
        }
    })
}

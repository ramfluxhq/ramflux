// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session-bound persistence notifications after unsolicited push-route replies are applied.

use super::subscriptions::SessionEvent;
use super::{AccountWork, SessionContext};
use crate::gateway::frame_dispatch::FrameKind;
use tokio::sync::mpsc;

pub(super) async fn run(mut context: SessionContext, work: mpsc::Sender<AccountWork>) {
    let mut subscription = context.subscribe([
        FrameKind::PushRouteRegistered,
        FrameKind::PushRouteRefused,
        FrameKind::PushRouteDeregistered,
    ]);
    loop {
        let event = tokio::select! {biased;_=context.cancel.changed()=>break,event=subscription.recv()=>event};
        let Some(event) = event else {
            break;
        };
        match event {
            SessionEvent::Disconnected { reason, generation } => {
                tracing::trace!(?reason,generation,session_id=%context.session_id,"push route observer stopped");
                break;
            }
            // This child subscribes to push-route kinds only; a capable event never matches.
            SessionEvent::Capable { .. } => continue,
            SessionEvent::Frame { frame, generation } => {
                if generation != context.generation {
                    continue;
                }
                tracing::trace!(kind=?FrameKind::of(&frame),generation,"push route outcome applied");
            }
            SessionEvent::Lagged { dropped, generation } => {
                if generation != context.generation {
                    continue;
                }
                tracing::debug!(
                    dropped,
                    generation,
                    "push route observer using current metadata after lag"
                );
            }
        }
        let metadata = context
            .call(
                |engine| {
                    Box::pin(async move {
                        Ok((engine.config.clone(), engine.session().clone(), engine.mode.clone()))
                    })
                },
                context.call_deadline(),
            )
            .await;
        let Ok((config, session, mode)) = metadata else {
            break;
        };
        let outcome = AccountWork::Metadata {
            metadata: Box::new(super::SessionMetadata {
                config,
                session,
                mode,
                generation: context.generation,
            }),
        };
        tokio::select! {biased;_=context.cancel.changed()=>break,result=work.send(outcome)=>{if result.is_err(){break;}}}
    }
}

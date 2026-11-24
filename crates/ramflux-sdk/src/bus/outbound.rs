// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded outbound queue; immutable producer scopes preserve subscription generations.

use crate::{LocalBusFrame, LocalBusFrameKind, SdkError};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct Scope {
    account: Option<String>,
    generation: u64,
}

#[derive(Clone)]
enum Channel {
    Plain(mpsc::Sender<LocalBusFrame>),
    Tagged(mpsc::Sender<Message>),
}

#[derive(Clone)]
pub(crate) struct LocalBusOutbound {
    channel: Channel,
    scope: Option<Scope>,
    fences: Option<std::sync::Arc<super::app_lock_fence::Fences>>,
    access: Option<super::app_lock_fence::Token>,
    generations: bool,
    control: tokio::sync::watch::Sender<Option<Message>>,
}

#[derive(Clone)]
pub(crate) struct Message {
    pub frame: LocalBusFrame,
    pub generation: Option<u64>,
    pub access: Option<super::app_lock_fence::Token>,
}

impl Message {
    fn take_frame(mut self) -> LocalBusFrame {
        std::mem::replace(
            &mut self.frame,
            LocalBusFrame::request("", None, "", "", serde_json::Value::Null),
        )
    }
}
impl Drop for Message {
    fn drop(&mut self) {
        super::secrets::wipe(&mut self.frame.body);
    }
}
pub(crate) enum Receiver {
    Tagged(mpsc::Receiver<Message>, tokio::sync::watch::Receiver<Option<Message>>),
}

impl From<mpsc::Sender<LocalBusFrame>> for LocalBusOutbound {
    fn from(sender: mpsc::Sender<LocalBusFrame>) -> Self {
        Self {
            channel: Channel::Plain(sender),
            scope: None,
            fences: None,
            access: None,
            generations: false,
            control: tokio::sync::watch::channel(None).0,
        }
    }
}

impl LocalBusOutbound {
    pub fn with_fences(mut self, fences: std::sync::Arc<super::app_lock_fence::Fences>) -> Self {
        self.fences = Some(fences);
        self
    }
    pub fn for_request(mut self, request: &LocalBusFrame) -> Result<Self, SdkError> {
        self.access = if super::app_lock_fence::control(&request.method) {
            None
        } else {
            self.fences
                .as_ref()
                .map(|fences| fences.for_method(&request.method, request.account_id.as_deref()))
                .transpose()?
        };
        Ok(self)
    }
    fn access(
        &self,
        frame: &LocalBusFrame,
    ) -> Result<Option<super::app_lock_fence::Token>, SdkError> {
        if super::app_lock_fence::control(&frame.method) {
            return Ok(None);
        }
        if let Some(access) = &self.access {
            return Ok(Some(access.clone()));
        }
        self.fences.as_ref().map(|fences| fences.token(frame.account_id.as_deref())).transpose()
    }

    pub fn channel(capacity: usize, tagged: bool) -> (Self, Receiver) {
        let (sender, receiver) = mpsc::channel(capacity);
        let (control, changes) = tokio::sync::watch::channel(None);
        (
            Self {
                channel: Channel::Tagged(sender),
                scope: None,
                fences: None,
                access: None,
                generations: tagged,
                control,
            },
            Receiver::Tagged(receiver, changes),
        )
    }

    pub fn subscribe(&self, account: Option<String>) -> Result<Self, SdkError> {
        if matches!(self.channel, Channel::Plain(_)) {
            return Ok(self.clone());
        }
        let previous = NEXT_GENERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| SdkError::LocalBus("subscription generation exhausted".into()))?;
        let generation = previous
            .checked_add(1)
            .ok_or_else(|| SdkError::LocalBus("subscription generation exhausted".into()))?;
        let access =
            self.fences.as_ref().map(|fences| fences.token(account.as_deref())).transpose()?;
        Ok(Self {
            channel: self.channel.clone(),
            scope: Some(Scope { account, generation }),
            fences: self.fences.clone(),
            access,
            generations: self.generations,
            control: self.control.clone(),
        })
    }

    pub fn for_account(&self, account: Option<&str>) -> Self {
        let scope =
            self.scope.as_ref().filter(|scope| scope.account.as_deref() == account).cloned();
        Self {
            channel: self.channel.clone(),
            scope,
            fences: self.fences.clone(),
            access: self.access.clone(),
            generations: self.generations,
            control: self.control.clone(),
        }
    }

    fn generation(&self, frame: &LocalBusFrame) -> Option<u64> {
        if !self.generations {
            return None;
        }
        let subscription_reply =
            matches!(frame.method.as_str(), "subscription.open" | "bus.subscribe");
        if frame.kind == LocalBusFrameKind::Event || subscription_reply {
            Some(
                self.scope
                    .as_ref()
                    .filter(|scope| scope.account == frame.account_id)
                    .map_or(0, |scope| scope.generation),
            )
        } else {
            None
        }
    }

    pub async fn send(
        &self,
        frame: LocalBusFrame,
    ) -> Result<(), Box<mpsc::error::SendError<LocalBusFrame>>> {
        if frame.method == "account.app_lock.changed" {
            let generation = self.generation(&frame);
            self.control.send_replace(Some(Message { frame, generation, access: None }));
            return Ok(());
        }
        match &self.channel {
            Channel::Plain(sender) => sender.send(frame).await.map_err(Box::new),
            Channel::Tagged(sender) => {
                let generation = self.generation(&frame);
                let Ok(access) = self.access(&frame) else {
                    return Err(Box::new(mpsc::error::SendError(frame)));
                };
                sender
                    .send(Message { frame, generation, access })
                    .await
                    .map_err(|error| Box::new(mpsc::error::SendError(error.0.take_frame())))
            }
        }
    }

    pub fn try_send(
        &self,
        frame: LocalBusFrame,
    ) -> Result<(), Box<mpsc::error::TrySendError<LocalBusFrame>>> {
        if frame.method == "account.app_lock.changed" {
            let generation = self.generation(&frame);
            self.control.send_replace(Some(Message { frame, generation, access: None }));
            return Ok(());
        }
        match &self.channel {
            Channel::Plain(sender) => sender.try_send(frame).map_err(Box::new),
            Channel::Tagged(sender) => {
                let generation = self.generation(&frame);
                let Ok(access) = self.access(&frame) else {
                    return Err(Box::new(mpsc::error::TrySendError::Closed(frame)));
                };
                sender
                    .try_send(Message { frame, generation, access })
                    .map_err(|error| match error {
                        mpsc::error::TrySendError::Full(message) => {
                            mpsc::error::TrySendError::Full(message.take_frame())
                        }
                        mpsc::error::TrySendError::Closed(message) => {
                            mpsc::error::TrySendError::Closed(message.take_frame())
                        }
                    })
                    .map_err(Box::new)
            }
        }
    }

    pub fn capacity(&self) -> usize {
        match &self.channel {
            Channel::Plain(sender) => sender.capacity(),
            Channel::Tagged(sender) => sender.capacity(),
        }
    }

    pub fn is_closed(&self) -> bool {
        match &self.channel {
            Channel::Plain(sender) => sender.is_closed(),
            Channel::Tagged(sender) => sender.is_closed(),
        }
    }

    pub async fn closed(&self) {
        match &self.channel {
            Channel::Plain(sender) => sender.closed().await,
            Channel::Tagged(sender) => sender.closed().await,
        }
    }
}

impl Receiver {
    pub async fn recv(&mut self) -> Option<Message> {
        match self {
            Self::Tagged(receiver, changes) => {
                tokio::select! {
                    biased;
                    notification = changes.changed() => {
                        if notification.is_err() { return receiver.recv().await; }
                        changes.borrow_and_update().clone()
                    }
                    frame = receiver.recv() => frame,
                }
            }
        }
    }
}

/// The source snapshot is serialized even when this frame drains after a later reopen.
pub(crate) async fn write<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
) -> Result<(), SdkError> {
    if let Some(generation) = message.generation {
        #[derive(serde::Serialize)]
        struct Tagged<'a> {
            #[serde(flatten)]
            frame: &'a LocalBusFrame,
            subscription_generation: String,
        }
        let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&Tagged {
            frame: &message.frame,
            subscription_generation: generation.to_string(),
        })?);
        super::io::write_encoded_local_bus_frame(writer, &encoded).await
    } else {
        super::io::write_local_bus_frame(writer, &message.frame).await
    }
}

#[cfg(all(test, feature = "c-abi"))]
mod tests {
    use super::*;
    use crate::LocalBusConfig;
    use crate::bus::state::LocalBusConnectionState;
    use crate::bus::{connection, data_root_lock::DataRootLock, supervisor::Supervisor};
    use std::time::Duration;

    #[tokio::test]
    async fn real_dispatcher_preserves_old_generation_after_close_and_reopen() {
        Box::pin(tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::LocalSet::new().run_until(async {
                let root = tempfile::tempdir().expect("test: isolated root");
                let supervisor = Supervisor::new(LocalBusConfig::new("", root.path()))
                    .expect("test: real supervisor");
                *supervisor.root_lease.borrow_mut() =
                    Some(DataRootLock::acquire(root.path()).expect("test: real writer lease"));
                let (outbound, mut receiver) = LocalBusOutbound::channel(64, true);
                let mut connection_state = LocalBusConnectionState::new(1, outbound);
                let body = serde_json::json!({"topics":["message.changed"]});
                let open = LocalBusFrame::request(
                    "open1",
                    Some("same-account".into()),
                    "account",
                    "subscription.open",
                    body.clone(),
                );
                connection::configure_subscription(&supervisor, &mut connection_state, &open)
                    .await
                    .expect("test: dispatch open");
                let first = receiver.recv().await.expect("test: first open reply");
                let first_generation = first.generation.expect("test: dispatcher generation");
                assert_ne!(first_generation, 0, "successful open must assign a generation");
                let old_producer = connection_state.outbound.clone();
                let close = LocalBusFrame::request(
                    "close",
                    Some("same-account".into()),
                    "account",
                    "subscription.close",
                    serde_json::json!({}),
                );
                connection::configure_subscription(&supervisor, &mut connection_state, &close)
                    .await
                    .expect("test: dispatch close");
                let closed = receiver.recv().await.expect("test: close acknowledgement");
                assert_eq!(closed.frame.body["subscribed"], false, "the real stream must close");
                let reopen = LocalBusFrame::request(
                    "open2",
                    Some("same-account".into()),
                    "account",
                    "subscription.open",
                    body,
                );
                connection::configure_subscription(&supervisor, &mut connection_state, &reopen)
                    .await
                    .expect("test: dispatch reopen");
                let second = receiver.recv().await.expect("test: second open reply");
                let second_generation = second.generation.expect("test: replacement generation");
                assert!(
                    second_generation > first_generation,
                    "same-account reopen must advance its generation"
                );
                let late = super::super::io::local_bus_event(
                    &open,
                    "same-account",
                    "account",
                    "message.changed",
                    serde_json::json!({"late":true}),
                );
                old_producer.send(late).await.expect("test: old producer completes after reopen");
                let late = receiver.recv().await.expect("test: late old frame");
                assert_eq!(
                    late.generation,
                    Some(first_generation),
                    "late data cannot inherit the replacement generation"
                );
                let mut encoded = Vec::new();
                write(&mut encoded, &late).await.expect("test: actual wire writer");
                let mut input = encoded.as_slice();
                let bytes = super::super::io::read_encoded_local_bus_frame(&mut input)
                    .await
                    .expect("test: actual frame decoder");
                let wire: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("test: tagged wire JSON");
                assert_eq!(
                    wire["subscription_generation"],
                    first_generation.to_string(),
                    "native hosts must see the immutable old generation"
                );
                supervisor.disconnect(1);
                supervisor.shutdown().await.expect("test: real supervisor shutdown");
            }),
        ))
        .await
        .expect("test: bounded dispatcher lifecycle");
    }
}

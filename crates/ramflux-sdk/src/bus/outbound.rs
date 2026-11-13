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
}

pub(crate) struct Message {
    pub frame: LocalBusFrame,
    pub generation: Option<u64>,
}

pub(crate) enum Receiver {
    Plain(mpsc::Receiver<LocalBusFrame>),
    Tagged(mpsc::Receiver<Message>),
}

impl From<mpsc::Sender<LocalBusFrame>> for LocalBusOutbound {
    fn from(sender: mpsc::Sender<LocalBusFrame>) -> Self {
        Self { channel: Channel::Plain(sender), scope: None }
    }
}

impl LocalBusOutbound {
    pub fn channel(capacity: usize, tagged: bool) -> (Self, Receiver) {
        if tagged {
            let (sender, receiver) = mpsc::channel(capacity);
            (Self { channel: Channel::Tagged(sender), scope: None }, Receiver::Tagged(receiver))
        } else {
            let (sender, receiver) = mpsc::channel(capacity);
            (sender.into(), Receiver::Plain(receiver))
        }
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
        Ok(Self { channel: self.channel.clone(), scope: Some(Scope { account, generation }) })
    }

    pub fn for_account(&self, account: Option<&str>) -> Self {
        let scope =
            self.scope.as_ref().filter(|scope| scope.account.as_deref() == account).cloned();
        Self { channel: self.channel.clone(), scope }
    }

    fn generation(&self, frame: &LocalBusFrame) -> Option<u64> {
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
        match &self.channel {
            Channel::Plain(sender) => sender.send(frame).await.map_err(Box::new),
            Channel::Tagged(sender) => {
                let generation = self.generation(&frame);
                sender
                    .send(Message { frame, generation })
                    .await
                    .map_err(|error| Box::new(mpsc::error::SendError(error.0.frame)))
            }
        }
    }

    pub fn try_send(
        &self,
        frame: LocalBusFrame,
    ) -> Result<(), Box<mpsc::error::TrySendError<LocalBusFrame>>> {
        match &self.channel {
            Channel::Plain(sender) => sender.try_send(frame).map_err(Box::new),
            Channel::Tagged(sender) => {
                let generation = self.generation(&frame);
                sender
                    .try_send(Message { frame, generation })
                    .map_err(|error| match error {
                        mpsc::error::TrySendError::Full(message) => {
                            mpsc::error::TrySendError::Full(message.frame)
                        }
                        mpsc::error::TrySendError::Closed(message) => {
                            mpsc::error::TrySendError::Closed(message.frame)
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
            Self::Plain(receiver) => {
                receiver.recv().await.map(|frame| Message { frame, generation: None })
            }
            Self::Tagged(receiver) => receiver.recv().await,
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
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::LocalSet::new().run_until(async {
                let root = tempfile::tempdir().expect("test: isolated root");
                let supervisor = Supervisor::new(LocalBusConfig::new("", root.path()))
                    .expect("test: real supervisor");
                *supervisor.root_lease.borrow_mut() =
                    Some(DataRootLock::acquire(root.path()).expect("test: real writer lease"));
                let (outbound, mut receiver) = LocalBusOutbound::channel(64, true);
                let mut connection_state = LocalBusConnectionState::new(1, outbound);
                let body = serde_json::json!({"topics":["account.backup.job.changed"]});
                let open = LocalBusFrame::request(
                    "open1",
                    None,
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
                    None,
                    "account",
                    "subscription.close",
                    serde_json::json!({}),
                );
                connection::configure_subscription(&supervisor, &mut connection_state, &close)
                    .await
                    .expect("test: dispatch close");
                let closed = receiver.recv().await.expect("test: close acknowledgement");
                assert_eq!(closed.frame.body["subscribed"], false, "the real stream must close");
                let reopen =
                    LocalBusFrame::request("open2", None, "account", "subscription.open", body);
                connection::configure_subscription(&supervisor, &mut connection_state, &reopen)
                    .await
                    .expect("test: dispatch reopen");
                let second = receiver.recv().await.expect("test: second open reply");
                let second_generation = second.generation.expect("test: replacement generation");
                assert!(
                    second_generation > first_generation,
                    "same-account reopen must advance its generation"
                );
                let mut late = super::super::io::local_bus_event(
                    &open,
                    "",
                    "account",
                    "account.backup.job.changed",
                    serde_json::json!({"late":true}),
                );
                late.account_id = None;
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
        )
        .await
        .expect("test: bounded dispatcher lifecycle");
    }
}

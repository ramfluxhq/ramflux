// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded per-account read routing, independent of network mutations.

use crate::prelude::*;
use tokio::sync::oneshot;

pub(super) enum ReadCommand {
    Request(Box<LocalBusFrame>, oneshot::Sender<Result<serde_json::Value, SdkError>>),
    Stop(oneshot::Sender<()>),
}

#[derive(Clone)]
pub(super) struct AccountReaders {
    senders: Vec<mpsc::Sender<ReadCommand>>,
    next: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AccountReaders {
    pub(super) fn start(db: &AccountDb) -> Result<Self, SdkError> {
        let mut senders = Vec::new();
        for _ in 0..2 {
            let reader = db.open_reader()?;
            let (sender, mut receiver) = mpsc::channel::<ReadCommand>(64);
            std::thread::Builder::new().name("ramflux-account-reader".to_owned()).spawn(
                move || {
                    let mut client = RamfluxClient::new();
                    client.active_account_db = Some(reader);
                    while let Some(command) = receiver.blocking_recv() {
                        match command {
                            ReadCommand::Request(request, reply) => {
                                if !reply.is_closed() {
                                    let result = client.account_db().and_then(|db| {
                                        db.read_snapshot(|| read(&client, &request))
                                    });
                                    let _ = reply.send(result);
                                }
                            }
                            ReadCommand::Stop(reply) => {
                                drop(client);
                                let _ = reply.send(());
                                return;
                            }
                        }
                    }
                },
            )?;
            senders.push(sender);
        }
        Ok(Self { senders, next: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)) })
    }

    pub(super) async fn request(
        &self,
        request: LocalBusFrame,
    ) -> Result<serde_json::Value, SdkError> {
        let index =
            self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.senders.len();
        let (sender, receiver) = oneshot::channel();
        self.senders[index]
            .send(ReadCommand::Request(Box::new(request), sender))
            .await
            .map_err(|_| closed())?;
        receiver.await.map_err(|_| closed())?
    }

    pub(super) async fn stop(&self) {
        for sender in &self.senders {
            let (reply, done) = oneshot::channel();
            if sender.send(ReadCommand::Stop(reply)).await.is_ok() {
                let _ = done.await;
            }
        }
    }
}

pub(super) fn is_reader_request(method: &str) -> bool {
    super::read_model::handles(method)
        || matches!(method, "message.list" | "message.read" | "conversation.list")
}

fn read(client: &RamfluxClient, request: &LocalBusFrame) -> Result<serde_json::Value, SdkError> {
    if super::read_model::handles(&request.method) {
        return super::read_model::read(client, request);
    }
    match request.method.as_str() {
        "conversation.list" => {
            Ok(serde_json::json!({"conversations": client.conversation_list()?}))
        }
        "message.list" | "message.read" => {
            let body: LocalBusConversationRequest = serde_json::from_value(request.body.clone())?;
            Ok(
                serde_json::json!({"messages": client.direct_messages(&body.conversation_id)?, "rejected": client.rejected_inbox(&body.conversation_id)?}),
            )
        }
        _ => Err(SdkError::LocalBus("unsupported reader request".to_owned())),
    }
}

fn closed() -> SdkError {
    SdkError::LocalBus("account reader stopped".to_owned())
}

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
        || matches!(
            method,
            "message.list" | "message.read" | "conversation.list" | "surface.get" | "surface.list"
        )
}

pub(super) fn read(
    client: &RamfluxClient,
    request: &LocalBusFrame,
) -> Result<serde_json::Value, SdkError> {
    if super::read_model::handles(&request.method) {
        return super::read_model::read(client, request);
    }
    if request.method == "stream.read" {
        return super::subscription::read(client.account_db()?, request);
    }
    if matches!(request.method.as_str(), "surface.get" | "surface.list") {
        return super::dispatch::surface::read_surface(client, request);
    }
    match request.method.as_str() {
        "conversation.list" => {
            Ok(serde_json::json!({"conversations": client.conversation_list()?}))
        }
        "message.list" | "message.read" => {
            let body: LocalBusConversationRequest = serde_json::from_value(request.body.clone())?;
            message_page(client, &body.conversation_id)
        }
        _ => Err(SdkError::LocalBus("unsupported reader request".to_owned())),
    }
}

fn closed() -> SdkError {
    SdkError::LocalBus("account reader stopped".to_owned())
}

fn message_page(client: &RamfluxClient, conversation: &str) -> Result<serde_json::Value, SdkError> {
    let db = client.account_db()?;
    let mut messages = Vec::new();
    for message in client.direct_messages(conversation)? {
        let mut value = serde_json::to_value(&message)?;
        if !message.deleted
            && let Some(content) = db.message_content(&message.message_id)?
        {
            value["body_utf8"] = if content.starts_with(crate::client::surface::carrier::PREFIX) {
                serde_json::json!("[Surface pending validation]")
            } else {
                serde_json::json!(String::from_utf8_lossy(&content))
            };
            let mut attachments = Vec::new();
            for object in db.client_message_object_ids(&message.message_id)? {
                let metadata = super::read_model::row(client, "object", &object)?;
                let mut reference = serde_json::json!({"object_id":object,"status":"referenced"});
                for field in [
                    "name",
                    "size",
                    "mime",
                    "owner",
                    "conversation_id",
                    "message_id",
                    "manifest_hash",
                ] {
                    if let Some(value) = metadata.get(field) {
                        reference[field] = value.clone();
                    }
                }
                attachments.push(reference);
            }
            value["attachments"] = serde_json::json!(attachments);
        }
        if !message.deleted
            && let Some((surface, text)) = client.surface_message_fallback(&message.message_id)?
        {
            value["content_type"] = serde_json::json!("surface");
            value["surface_id"] = serde_json::json!(surface);
            value["body_utf8"] = serde_json::json!(text);
        }
        messages.push(value);
    }
    Ok(serde_json::json!({"messages":messages,"rejected":client.rejected_inbox(conversation)?}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_attachment_fetch_keeps_the_conversation_content_snapshot_unchanged()
    -> Result<(), SdkError> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        let root = std::env::temp_dir()
            .join(format!("ramflux-message-fetch-snapshot-{}-{suffix}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.open_account_index(&root)?;
        client.create_account("a", "a")?;
        client.unlock_account("a", b"secret")?;
        client.send_direct_message("thread", "message", "peer", b"ciphertext")?;
        let db = client.account_db()?;
        db.store_message_content("thread", "message", b"approved content")?;
        db.persist_actor_state("attachment/reference/remote", &serde_json::json!({}))?;
        db.persist_client_record("object","remote",&serde_json::json!({"owner":"peer","size":42,"message_id":"message","conversation_id":"thread"}))?;
        let before = message_page(&client, "thread")?;
        db.persist_actor_state("attachment/fetch/remote",&serde_json::json!({"object_id":"remote","operation_id":"fetch","transfer_state":"failed","last_error":"attachment unavailable","attempts":1}))?;
        assert_eq!(message_page(&client, "thread")?, before);
        assert_eq!(
            super::super::read_model::row(&client, "object", "remote")?["transfer_state"],
            "failed"
        );
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

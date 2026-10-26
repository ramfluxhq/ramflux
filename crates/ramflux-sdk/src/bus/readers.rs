// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded per-account read routing, independent of network mutations.

use crate::prelude::*;
use ramflux_crypto::RootQualifiedDeviceRef;
use std::sync::{Arc, RwLock};
use tokio::sync::oneshot;
type ReaderIdentity = Arc<RwLock<Option<RootQualifiedDeviceRef>>>;
#[cfg(test)]
#[path = "readers_backup_tests.rs"]
mod backup_tests;

pub(super) enum ReadCommand {
    Request(Box<LocalBusFrame>, oneshot::Sender<Result<serde_json::Value, SdkError>>),
    MissingAttachments(oneshot::Sender<Result<super::backup_jobs::MissingAttachments, SdkError>>),
    Stop(oneshot::Sender<()>),
}

#[cfg(test)]
pub(crate) async fn test_account_reader_request(
    db: &AccountDb,
    request: LocalBusFrame,
) -> Result<serde_json::Value, SdkError> {
    let readers = AccountReaders::start(db, None)?;
    let result = readers.request(request).await;
    readers.stop().await;
    result
}

#[derive(Clone)]
pub(super) struct AccountReaders {
    identity: ReaderIdentity,
    senders: Vec<mpsc::Sender<ReadCommand>>,
    next: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AccountReaders {
    pub(super) fn start(
        db: &AccountDb,
        device: Option<RootQualifiedDeviceRef>,
    ) -> Result<Self, SdkError> {
        super::sync_status::initialize_coordinates(db)?;
        crate::client::contact::migrate_legacy_contact_verifications(db)?;
        let identity = Arc::new(RwLock::new(device));
        let mut senders = Vec::new();
        for _ in 0..2 {
            let reader = db.open_reader()?;
            let identity = Arc::clone(&identity);
            let (sender, mut receiver) = mpsc::channel::<ReadCommand>(64);
            std::thread::Builder::new().name("ramflux-account-reader".to_owned()).spawn(
                move || {
                    let mut client = RamfluxClient::new();
                    client.active_account_db = Some(reader);
                    while let Some(command) = receiver.blocking_recv() {
                        match command {
                            ReadCommand::Request(request, reply) => {
                                if !reply.is_closed() {
                                    let result = identity
                                        .read()
                                        .map_err(|_| closed())
                                        .map(|device| device.clone())
                                        .and_then(|device| {
                                            client.reader_device_identity = device;
                                            client.account_db().and_then(|db| {
                                                db.read_snapshot(|| read(&client, &request))
                                            })
                                        });
                                    let _ = reply.send(result);
                                }
                            }
                            ReadCommand::MissingAttachments(reply) => {
                                if !reply.is_closed() {
                                    let result = client.account_db().and_then(|db| {
                                        db.read_snapshot(|| {
                                            let selectors = db.backup_missing_selectors()?;
                                            Ok(super::backup_jobs::MissingAttachments {
                                                account_id: db.local_account_id.clone(),
                                                total: selectors.len() as u64,
                                                selectors,
                                            })
                                        })
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
        Ok(Self {
            identity,
            senders,
            next: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    pub(super) fn set_identity(
        &self,
        device: Option<RootQualifiedDeviceRef>,
    ) -> Result<(), SdkError> {
        *self.identity.write().map_err(|_| closed())? = device;
        Ok(())
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

    pub(super) async fn backup_missing_references(
        &self,
    ) -> Result<super::backup_jobs::MissingAttachments, SdkError> {
        let index =
            self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.senders.len();
        let (reply, result) = oneshot::channel();
        self.senders[index]
            .send(ReadCommand::MissingAttachments(reply))
            .await
            .map_err(|_| closed())?;
        result.await.map_err(|_| closed())?
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
            "sync.status.get"
                | "message.list"
                | "message.read"
                | "conversation.list"
                | "surface.get"
                | "surface.list"
                | "task.get"
                | "task.list"
                | "call.list"
        )
}

pub(super) fn read(
    client: &RamfluxClient,
    request: &LocalBusFrame,
) -> Result<serde_json::Value, SdkError> {
    if super::read_model::handles(&request.method) {
        return super::read_model::read(client, request);
    }
    if request.method == "call.list" {
        return super::dispatch::call::list(client);
    }
    if request.method == "sync.status.get" {
        return super::sync_status::read(client.account_db()?);
    }
    if matches!(request.method.as_str(), "stream.read" | "bus.subscribe") {
        return super::subscription::read(client.account_db()?, request);
    }
    if matches!(request.method.as_str(), "task.get" | "task.list") {
        return super::dispatch::task::read_task(client, request);
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
        let origin = client
            .message_origin(conversation, &message.message_id)?
            .unwrap_or(serde_json::Value::Null);
        for field in [
            "sender_device_id",
            "sender_root_commitment",
            "sender_device_display",
            "direction",
            "original_message_id",
            "envelope_id",
        ] {
            value[field] = origin[field].clone();
        }
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
        if !message.deleted
            && let Some(task) = client.task_message_metadata(conversation, &message.message_id)?
        {
            value["content_type"] = serde_json::json!("task");
            value["task_id"] = task["task_id"].clone();
            value["actor_kind_verified"] = task["actor_kind_verified"].clone();
            value["actor_kind"] = task["actor_kind"].clone();
            value["body_utf8"] = task["fallback_text"].clone();
        }
        messages.push(value);
    }
    for row in
        db.voice_call_rows(false)?.into_iter().filter(|row| row.conversation_id == conversation)
    {
        let duration = match (row.answered_at, row.ended_at) {
            (Some(start), Some(end)) => Some(end.saturating_sub(start)),
            _ => None,
        };
        messages.push(serde_json::json!({"id":row.call_id,"message_id":row.call_id,"conversation_id":row.conversation_id,"kind":"call","created_at":row.created_at,"call":row,"duration_seconds":duration,"missed":row.end_reason.as_deref()==Some("missed")}));
    }
    messages.sort_by_key(|row| {
        (
            row["created_at"].as_i64().unwrap_or(0),
            row["message_id"].as_str().unwrap_or("").to_owned(),
        )
    });
    Ok(serde_json::json!({"messages":messages,"rejected":client.rejected_inbox(conversation)?}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn message_rows_preserve_actor_kind_and_leave_legacy_metadata_unknown()
    -> Result<(), SdkError> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |t| t.as_nanos());
        let path = std::env::temp_dir()
            .join(format!("rf-reader-actor-kind-{}-{suffix}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.open_account_index(&path)?;
        client.create_account("reader", "reader")?;
        client.unlock_account("reader", b"secret")?;
        let db = client.account_db()?;
        for id in ["headless", "unknown", "legacy"] {
            client.send_direct_message("thread", id, "peer", b"opaque")?;
            let mut metadata = serde_json::json!({"task_id":id,"actor_kind_verified":false,"fallback_text":"[Task]"});
            if id != "legacy" {
                metadata["actor_kind"] = if id == "headless" {
                    serde_json::json!("headless_ai")
                } else {
                    serde_json::Value::Null
                };
            }
            db.persist_actor_state(
                &crate::client::task::scoped("message", "thread", id)?,
                &metadata,
            )?;
        }
        let readers = AccountReaders::start(db, None)?;
        let result = readers
            .request(LocalBusFrame::request(
                "messages",
                Some("reader".into()),
                "client",
                "message.list",
                serde_json::json!({"conversation_id":"thread"}),
            ))
            .await?;
        readers.stop().await;
        let rows = result["messages"].as_array().ok_or_else(closed)?;
        for id in ["headless", "unknown", "legacy"] {
            let row = rows.iter().find(|row| row["message_id"] == id).ok_or_else(closed)?;
            assert_eq!(row["actor_kind_verified"], false);
            assert_eq!(
                row["actor_kind"],
                if id == "headless" {
                    serde_json::json!("headless_ai")
                } else {
                    serde_json::Value::Null
                }
            );
            assert_eq!(row["task_id"], id);
            assert_eq!(row["body_utf8"], "[Task]");
        }
        drop(client);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
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
    #[tokio::test]
    async fn read_markers_follow_the_authenticated_viewer_root_without_copying_signing_keys()
    -> Result<(), SdkError> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        let root = std::env::temp_dir()
            .join(format!("ramflux-reader-root-{}-{suffix}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.create_identity_root("alice", [1; 32]);
        client.create_device_branch("alice", "phone", 1, [2; 32]);
        client.open_account_index(&root)?;
        client.create_account("a", "a")?;
        client.unlock_account("a", b"secret")?;
        client.send_direct_message("thread", "message", "peer", b"ciphertext")?;
        let own = client.owned_device_identity()?;
        let db = client.account_db()?;
        db.mark_read("thread", &own, "message")?;
        db.persist_client_record(
            "identity",
            "local",
            &serde_json::json!({"principal_id":"alice","device_id":"phone"}),
        )?;
        db.persist_client_record(
            "conversation",
            "thread",
            &serde_json::json!({"kind":"direct","participants":["alice","peer"]}),
        )?;
        let readers = AccountReaders::start(db, Some(own))?;
        let request = LocalBusFrame::request(
            "read",
            Some("a".into()),
            "conversation",
            "conversation.directory",
            serde_json::json!({}),
        );
        let first = readers.request(request.clone()).await?;
        assert_eq!(first["conversations"][0]["unread_count"], 0);
        let other = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
            &ramflux_crypto::create_identity_root("mallory", [3; 32]),
            "phone",
        )?;
        readers.set_identity(Some(other))?;
        let second = readers.request(request).await?;
        assert_eq!(second["conversations"][0]["unread_count"], 1);
        readers.stop().await;
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conversation intent resolves authenticated routes before using the ordinary SDK send paths.
use crate::attachment_send::send_journal;
use crate::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    conversation_id: String,
    text: String,
    #[serde(default)]
    attachments: Vec<Value>,
    #[serde(default)]
    media: Vec<ramflux_protocol::message::MediaRef>,
    #[serde(default)]
    prepares: Vec<PrepareId>,
    /// Names the group when its conversation record has not been captured yet.
    #[serde(default)]
    group_id: Option<String>,
}
#[derive(Deserialize)]
struct PrepareId {
    prepare_id: String,
}
impl Drop for Intent {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}
fn invalid(message: &str, reason: &'static str) -> SdkError {
    let error = crate::bindings::AdapterError::new(
        crate::bindings::GeneratedErrorCode::InvalidArgument,
        message,
    );
    crate::bindings::AdapterError {
        details: crate::bindings::ErrorDetails::Reason { reason: reason.into() },
        ..error
    }
    .into()
}

pub(super) async fn send(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, request_account_id(request)?)?;
    Box::pin(send_account(request, account)).await
}

/// The message content of a send. A send with prepared attachments admits them first; its
/// upload may be parked on the account actor, in which case the stage stays Uploading.
/// The identity of one send, as its attachments and delivery see it.
struct Sending<'a> {
    operation: &'a str,
    message_id: &'a str,
    thread: &'a Value,
    principal: &'a str,
    account_id: &'a str,
}

async fn send_content(
    account: &mut LocalBusAccountState,
    intent: &Intent,
    sending: &Sending<'_>,
) -> Result<ramflux_protocol::message::Content, SdkError> {
    let (operation, message_id, thread, principal, account_id) = (
        sending.operation,
        sending.message_id,
        sending.thread,
        sending.principal,
        sending.account_id,
    );
    if intent.prepares.is_empty() {
        return RamfluxClient::attachment_message_content(&intent.text, &intent.media);
    }
    let ids: Vec<String> = intent.prepares.iter().map(|item| item.prepare_id.clone()).collect();
    record_phase(&account.client, operation, send_journal::SendPhase::Preparing)?;
    if take_paused(&account.client, operation)? {
        // A drain paused this upload before a restart: it stays paused until the owner resumes.
        for prepare in &ids {
            crate::attachment_send::transfer::set_paused(account_id, prepare, true)?;
        }
    }
    let outcome = super::attachment_prepare::publish_prepares(
        account,
        super::attachment_prepare::PrepareSend {
            prepares: &ids,
            caption: &intent.text,
            message_id,
            operation,
            thread,
            principal,
            account_id,
            conversation_id: &intent.conversation_id,
        },
    )
    .await;
    match outcome {
        Ok(content) => Ok(content),
        Err(error) => {
            // The first admission handed its upload to the worker: the stage is Uploading.
            if account.attachment_send.upload.is_some() {
                record_phase(&account.client, operation, send_journal::SendPhase::Uploading)?;
            }
            Err(error)
        }
    }
}

pub(in crate::bus) async fn send_account(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let mut intent: Intent = serde_json::from_value(request.body.clone())?;
    admit_prepares(&intent)?;
    canonicalize_group_conversation(account, &mut intent)?;
    let account_id = request_account_id(request)?;
    let operation = request
        .operation_id
        .as_deref()
        .filter(|key| !key.is_empty() && key.len() <= 256)
        .ok_or_else(|| {
            invalid("conversation.send requires operation_id", "operation_id_required")
        })?;
    let message_id = ramflux_crypto::blake3_256_base64url(
        "ramflux.conversation.send.v1",
        &ramflux_protocol::canonical_json_bytes(&(account_id, operation))?,
    );
    let thread = match account
        .client
        .account_db()?
        .client_record("conversation", &intent.conversation_id)?
    {
        Some(thread) => thread,
        None => group_thread(account, &intent)?,
    };
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let principal = local.principal_id.clone();
    let sender = local.device_id.clone();
    reserve_intent(&account.client, operation, &request.body)?;
    let sending = Sending {
        operation,
        message_id: &message_id,
        thread: &thread,
        principal: &principal,
        account_id,
    };
    let content = send_content(account, &intent, &sending).await?;
    if !intent.prepares.is_empty() {
        let pin = crate::attachment_send::authority(&account.client)?;
        account.client.attachment_binding =
            Some(crate::attachment_send::Binding::of(account, &pin)?);
    }
    if !intent.prepares.is_empty() {
        record_phase(&account.client, operation, send_journal::SendPhase::Delivering)?;
    }
    let sent = Box::pin(deliver(
        account,
        &intent,
        &DirectSend {
            message: &message_id,
            principal: &principal,
            sender: &sender,
            thread: &thread,
            content: &content,
        },
    ))
    .await;
    account.client.attachment_binding = None;
    let deliveries = sent?;
    let submitted =
        deliveries.iter().all(|delivery| delivery.get("state") == Some(&json!("submitted")));
    if submitted {
        complete_intent(&account.client, operation)?;
    }
    let event_id =
        deliveries.iter().find_map(|delivery| delivery.get("message_id").and_then(Value::as_str));
    if deliveries
        .iter()
        .filter_map(|delivery| delivery.get("message_id").and_then(Value::as_str))
        .any(|id| Some(id) != event_id)
    {
        return Err(SdkError::ReplayMismatch);
    }
    if submitted && !intent.prepares.is_empty() {
        // The actual message id exists only now; every record the importer reads is keyed by it.
        let ids: Vec<String> = intent.prepares.iter().map(|item| item.prepare_id.clone()).collect();
        let actual = event_id.ok_or(SdkError::ReplayMismatch)?;
        super::attachment_prepare::note_admitted(&account.client, account_id, &ids, actual)?;
    }
    let mut body = json!({"message_id":event_id,"client_message_id":message_id,"conversation_id":intent.conversation_id,
        "delivery_state":if submitted {"submitted"} else {"failed"},"deliveries":deliveries});
    if !intent.prepares.is_empty() {
        let mut progress = vec!["accepted", "reserved", "sealed", "uploaded", "granted"];
        if submitted {
            progress.push("sent");
        }
        body["progress"] = json!(progress);
    }
    Ok(local_bus_ok(body))
}

fn canonicalize_group_conversation(
    account: &LocalBusAccountState,
    intent: &mut Intent,
) -> Result<(), SdkError> {
    let group = if let Some(group) = intent.group_id.clone() {
        group
    } else if account.client.born_v3_account.is_some()
        && account.client.account_db()?.shared_group_state(&intent.conversation_id)?.is_some()
    {
        intent.conversation_id.clone()
    } else {
        return Ok(());
    };
    intent.conversation_id =
        crate::bus::group_conversation::resolve(&account.client, &group, &intent.conversation_id)?;
    if intent.group_id.is_none() {
        intent.group_id = Some(group);
    }
    Ok(())
}

/// A group that exists but has not sent yet has no conversation record. It is created from the
/// verified group, never from the caller's word alone.
fn group_thread(account: &LocalBusAccountState, intent: &Intent) -> Result<Value, SdkError> {
    let group = intent
        .group_id
        .as_deref()
        .ok_or_else(|| invalid("conversation absent", "conversation_absent"))?;
    if super::super::group_delivery::directory(&account.client, group)?.is_empty() {
        return Err(invalid("group absent", "group_absent"));
    }
    let record = json!({
        "title": null, "direct_route": null, "kind": "group",
        "group_id": group, "participants": [],
    });
    account.client.account_db()?.persist_client_record(
        "conversation",
        &intent.conversation_id,
        &record,
    )?;
    Ok(record)
}

fn admit_prepares(intent: &Intent) -> Result<(), SdkError> {
    if !intent.attachments.is_empty() {
        return Err(SdkError::GeneratedRefused {
            code: crate::GeneratedRefusalCode::Content,
            reason: "retired conversation attachment input; use media with r4 large_manifest"
                .into(),
        });
    }
    if !intent.prepares.is_empty() && !intent.media.is_empty() {
        return Err(crate::attachment_send::Refusal::new(
            crate::attachment_send::CODE_LAYOUT_INVALID,
        )
        .into());
    }
    Ok(())
}

async fn deliver(
    account: &mut LocalBusAccountState,
    intent: &Intent,
    send: &DirectSend<'_>,
) -> Result<Vec<Value>, SdkError> {
    let DirectSend { message: message_id, sender, thread, content, .. } = *send;
    if let Some(group) = thread.get("group_id").and_then(Value::as_str) {
        send_group(account, intent, message_id, sender, group, content).await
    } else {
        Box::pin(send_direct(account, intent, send)).await
    }
}

async fn send_group(
    account: &mut LocalBusAccountState,
    intent: &Intent,
    message: &str,
    sender: &str,
    group: &str,
    content: &ramflux_protocol::message::Content,
) -> Result<Vec<Value>, SdkError> {
    let request = LocalBusFrame::request(
        "conversation-send-group",
        None,
        "group",
        "group.send",
        json!({"group_id":group,"conversation_id":intent.conversation_id,"message_id":message,
            "sender_id":sender,"content":content,
            "encrypted_body_base64":""}),
    );
    // A group send has one outcome for the whole group: a refusal is the command's result, with
    // its own code, never an ok reply carrying a failed row.
    let native = account.client.born_v3_account.is_some();
    let outcome = super::group::dispatch_group_send_request(&request, account)
        .await
        .map_err(|error| super::group::group_operation_error("group.send", error, native))?;
    Ok(vec![delivery(group, Ok(outcome))])
}

pub(in crate::bus) fn peer_root(
    account: &LocalBusAccountState,
    thread: &Value,
    principal: &str,
) -> Result<(String, String), SdkError> {
    let participants = thread
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("direct participants absent", "direct_participants_absent"))?;
    if thread.get("kind").and_then(Value::as_str) != Some("direct")
        || participants.len() != 2
        || !participants.iter().any(|id| id.as_str() == Some(principal))
    {
        return Err(invalid(
            "direct conversation membership mismatch",
            "direct_membership_mismatch",
        ));
    }
    let peer = participants
        .iter()
        .filter_map(Value::as_str)
        .find(|id| *id != principal)
        .ok_or_else(|| invalid("direct peer absent", "direct_peer_absent"))?;
    Ok((peer.into(), peer_commitment(account, thread, peer)?))
}

fn peer_commitment(
    account: &LocalBusAccountState,
    thread: &Value,
    peer: &str,
) -> Result<String, SdkError> {
    if let Some(identity) = account.client.account_db()?.client_record("identity", peer)? {
        return identity
            .get("contact_identity_commitment")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                invalid("direct peer commitment absent", "direct_peer_commitment_absent")
            });
    }
    // History import records the author root before the contact identity row exists.
    let own = account.client.own_account_anchor()?;
    let mut foreign = thread
        .get("participant_roots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|root| *root != own);
    let root = foreign
        .next()
        .ok_or_else(|| invalid("direct peer identity absent", "direct_peer_identity_absent"))?;
    if foreign.next().is_some() {
        return Err(invalid("direct peer identity absent", "direct_peer_identity_absent"));
    }
    Ok(root.to_owned())
}

struct DirectSend<'a> {
    message: &'a str,
    principal: &'a str,
    sender: &'a str,
    thread: &'a Value,
    content: &'a ramflux_protocol::message::Content,
}

async fn send_direct(
    account: &mut LocalBusAccountState,
    intent: &Intent,
    send: &DirectSend<'_>,
) -> Result<Vec<Value>, SdkError> {
    let (peer, root) = peer_root(account, send.thread, send.principal)?;
    let engine = account.session_client().await?;
    let manifest = account
        .client
        .cache_verified_device_manifest(engine.config(), &root, "conversation_peer")
        .await;
    account.apply_session_metadata(engine);
    let manifest = manifest?;
    if manifest.principal_id != peer || manifest.devices.is_empty() || manifest.devices.len() > 64 {
        return Err(invalid(
            "direct peer manifest mismatch or capacity exceeded",
            "direct_peer_manifest_mismatch",
        ));
    }
    let mut deliveries = Vec::new();
    for device in manifest.devices {
        let envelope = ramflux_crypto::blake3_256_base64url(
            "ramflux.conversation.envelope.v1",
            &ramflux_protocol::canonical_json_bytes(&(send.message, &root, &device.device_id))?,
        );
        let body: LocalBusMessageSubmitRequest = serde_json::from_value(json!({
            "conversation_id":intent.conversation_id,"message_id":send.message,"envelope_id":envelope,
            "source_principal_id":send.principal,"sender_id":send.sender,"recipient_device_id":device.device_id,
            "recipient_principal_commitment":root,"target_delivery_id":device.target_delivery_id,
            "content":send.content,
            "encrypted_body_base64":"","created_at":now_unix_timestamp(),
            "ttl":account.client.content_ttl()?}))?;
        let outcome = Box::pin(super::message::submit_conversation_message(account, body)).await;
        deliveries.push(delivery(&device.device_id, outcome));
    }
    Ok(deliveries)
}

fn delivery(target: &str, result: Result<LocalBusDispatchResult, SdkError>) -> Value {
    match result {
        Ok(result) => {
            json!({"target":target,"state":"submitted","message_id":result.response_body.get("message_id")})
        }
        Err(error) => {
            json!({"target":target,"state":"failed", "error_code":super::super::io::local_bus_error_code(&error)})
        }
    }
}

fn prepares_present(body: &Value) -> bool {
    body.get("prepares").and_then(Value::as_array).is_some_and(|rows| !rows.is_empty())
}

fn complete_intent(client: &RamfluxClient, operation: &str) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.write_transaction(|| {
        let key = send_journal::key(operation);
        let mut receipt = db
            .load_actor_state::<send_journal::SendRecord>(&key)?
            .ok_or_else(|| invalid("operation receipt absent", "operation_receipt_absent"))?;
        receipt.completed = true;
        receipt.phase = send_journal::SendPhase::Sent;
        receipt.completed_at = Some(now_unix_timestamp());
        db.persist_actor_state(&key, &receipt)?;
        Ok(())
    })
}
/// Runs `change` on the durable record of `operation` in one transaction and stores the result.
/// A completed record is final and is left as it is.
fn update_record(
    client: &RamfluxClient,
    operation: &str,
    change: impl FnOnce(&mut send_journal::SendRecord) -> Option<bool>,
) -> Result<bool, SdkError> {
    let db = client.account_db()?;
    db.write_transaction(|| {
        let key = send_journal::key(operation);
        let mut record = db
            .load_actor_state::<send_journal::SendRecord>(&key)?
            .ok_or_else(|| invalid("operation receipt absent", "operation_receipt_absent"))?;
        if record.completed {
            return Ok(false);
        }
        let Some(previous) = change(&mut record) else { return Ok(false) };
        db.persist_actor_state(&key, &record)?;
        Ok(previous)
    })
}

/// Records a forward phase transition before the work of that phase starts.
pub(in crate::bus) fn record_phase(
    client: &RamfluxClient,
    operation: &str,
    phase: send_journal::SendPhase,
) -> Result<(), SdkError> {
    update_record(client, operation, |record| {
        send_journal::advance(record, phase);
        Some(true)
    })
    .map(|_| ())
}

/// Persists whether a lock or suspend drain stopped this operation's upload.
pub(in crate::bus) fn record_paused(
    client: &RamfluxClient,
    operation: &str,
    paused: bool,
) -> Result<(), SdkError> {
    update_record(client, operation, |record| {
        record.paused = paused;
        Some(true)
    })
    .map(|_| ())
}

/// Reads and clears the persisted drain pause. The replay that follows starts paused.
fn take_paused(client: &RamfluxClient, operation: &str) -> Result<bool, SdkError> {
    update_record(client, operation, |record| {
        let was = record.paused;
        record.paused = false;
        Some(was)
    })
}

fn reserve_intent(client: &RamfluxClient, operation: &str, body: &Value) -> Result<(), SdkError> {
    let key = send_journal::key(operation);
    let canonical = zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(body)?);
    let fingerprint =
        ramflux_crypto::blake3_256_base64url("ramflux.conversation.send.intent.v1", &canonical);
    let db = client.account_db()?;
    let now = now_unix_timestamp();
    db.write_transaction(|| {
        super::conversation_journal::prune(client, now)?;
        if let Some(old) = db.load_actor_state::<send_journal::SendRecord>(&key)? {
            if old.fingerprint != fingerprint {
                if prepares_present(body) {
                    return Err(crate::attachment_send::Refusal::new(
                        crate::attachment_send::CODE_DUPLICATE,
                    )
                    .into());
                }
                return Err(crate::bindings::AdapterError::new(
                    crate::bindings::GeneratedErrorCode::InvalidArgument,
                    "operation_id reused",
                )
                .into());
            }
            return Ok(());
        }
        super::conversation_journal::capacity(client, "conversation-send/")?;
        let expires_at = super::conversation_journal::expiry(client, now)?;
        db.persist_actor_state(&key, &send_journal::SendRecord::admitted(fingerprint, expires_at))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_intent_fingerprint_survives_account_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let root = tempfile::tempdir()?;
            let make = || {
                crate::bus::runtime_tests::account(
                    root.path(),
                    "sender",
                    None,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )
            };
            let account = make()?;
            let body = json!({"conversation_id":"thread","text":"exact"});
            reserve_intent(&account.client, "operation", &body)?;
            drop(account);
            let account = make()?;
            reserve_intent(&account.client, "operation", &body)?;
            // The retry fence is account-owned metadata, independent of private message copies.
            let error = reserve_intent(
                &account.client,
                "operation",
                &json!({"conversation_id":"other","text":"changed"}),
            )
            .expect_err("test: durable retry fence");
            assert_eq!(
                crate::bindings::AdapterError::from_sdk(&error).code,
                crate::bindings::GeneratedErrorCode::InvalidArgument as i32,
                "reopened account must refuse changed intent"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    #[test]
    fn send_fingerprint_ttl_and_capacity_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let account = crate::bus::runtime_tests::account(
            root.path(),
            "retention",
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        let db = account.client.account_db()?;
        let now = now_unix_timestamp();
        db.persist_actor_state(
            "conversation-send/expired",
            &send_journal::SendRecord {
                fingerprint: "retired".into(),
                expires_at: now - 1,
                completed: false,
                completed_at: None,
                phase: send_journal::SendPhase::default(),
                paused: false,
            },
        )?;
        super::super::conversation_journal::prune(&account.client, now)?;
        assert!(
            !db.actor_state_exists("conversation-send/expired")?,
            "expired fingerprints must be pruned"
        );
        db.write_transaction(|| {
            for n in 0..super::super::conversation_journal::LIMIT {
                db.persist_actor_state(
                    &format!("conversation-send/{n:04}"),
                    &send_journal::SendRecord {
                        fingerprint: n.to_string(),
                        expires_at: now + 3600,
                        completed: false,
                        completed_at: None,
                        phase: send_journal::SendPhase::default(),
                        paused: false,
                    },
                )?;
            }
            Ok::<_, SdkError>(())
        })?;
        let error = reserve_intent(&account.client, "new-operation", &json!({"text":"new"}))
            .expect_err("test: full live retention window");
        assert_eq!(
            crate::bindings::AdapterError::from_sdk(&error).code,
            crate::bindings::GeneratedErrorCode::RateLimited as i32,
            "capacity cannot evict a live idempotency guarantee"
        );
        assert_eq!(
            db.actor_state_usage("conversation-send/")?.0,
            u64::from(super::super::conversation_journal::LIMIT),
            "the retained namespace is bounded"
        );
        for (key, completed_at) in
            [("conversation-send/0001", now - 2), ("conversation-send/0002", now - 1)]
        {
            db.persist_actor_state(
                key,
                &send_journal::SendRecord {
                    fingerprint: key.into(),
                    expires_at: now + 3600,
                    completed: true,
                    completed_at: Some(completed_at),
                    phase: send_journal::SendPhase::default(),
                    paused: false,
                },
            )?;
        }
        reserve_intent(&account.client, "new-operation", &json!({"text":"new"}))?;
        assert!(!db.actor_state_exists("conversation-send/0001")?, "oldest terminal evicted first");
        assert!(db.actor_state_exists("conversation-send/0002")?, "newer terminal retained");
        assert!(db.actor_state_exists("conversation-send/0000")?, "pending receipt retained");
        assert_eq!(db.actor_state_usage("conversation-send/")?.0, 1024);
        complete_intent(&account.client, "new-operation")?;
        let receipt = db
            .load_actor_state::<send_journal::SendRecord>(&send_journal::key("new-operation"))?
            .ok_or("test: completed receipt")?;
        assert!(
            receipt.completed && receipt.completed_at.is_some(),
            "successful send is evictable"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "conversation_send_native_tests.rs"]
mod native_tests;

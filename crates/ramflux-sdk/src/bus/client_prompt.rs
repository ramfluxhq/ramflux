// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-code prompts on a shared `LocalBusClient` connection. A prompt never disconnects:
//! the reply goes back on the same connection, correlated to its pending parent request, and
//! every other request keeps flowing. Without an attended provider the answer is a refusal.
use crate::custody::pairing::{
    CredentialOutcome, LocalCredentialProvider,
    private_credential::{encode_reply, validate_prompt},
};
use crate::{LocalBusFrame, LocalBusFrameKind};
use ramflux_protocol::custody::pairing::{PairingWire, local_dto::CredentialRequest};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

pub(super) const PROMPT_METHOD: &str = "device.credential.request";

pub(super) type Reply = Zeroizing<Vec<u8>>;

pub(super) struct Prompts {
    provider: Option<Arc<dyn LocalCredentialProvider>>,
    /// Secret-free copies of in-flight requests, keyed by request id (provider connections only).
    parents: Mutex<BTreeMap<String, LocalBusFrame>>,
    /// True from the moment a prompt arrives until its reply is written: the daemon reads only
    /// that reply on this connection meanwhile, so the writer holds every other frame back.
    window: watch::Sender<bool>,
    replies: mpsc::Sender<Reply>,
}

impl Prompts {
    pub(super) fn new(
        provider: Option<Arc<dyn LocalCredentialProvider>>,
    ) -> (Arc<Self>, mpsc::Receiver<Reply>, watch::Receiver<bool>) {
        let (replies, reply_rx) = mpsc::channel(1);
        let (window, window_rx) = watch::channel(false);
        let prompts =
            Arc::new(Self { provider, parents: Mutex::new(BTreeMap::new()), window, replies });
        (prompts, reply_rx, window_rx)
    }

    /// Captures the identity of a request before its body is erased. The body keeps only
    /// whether a passphrase was sent, which decides whether the daemon may ask for one.
    pub(super) fn parent_of(&self, request: &LocalBusFrame) -> Option<LocalBusFrame> {
        self.provider.as_ref()?;
        let mut parent = request.clone();
        parent.body = if request.body.get("passphrase").is_some() {
            serde_json::json!({"passphrase": null})
        } else {
            serde_json::json!({})
        };
        Some(parent)
    }

    pub(super) fn register(&self, parent: Option<LocalBusFrame>) {
        if let (Some(parent), Ok(mut parents)) = (parent, self.parents.lock()) {
            parents.insert(parent.request_id.clone(), parent);
        }
    }

    pub(super) fn forget(&self, request_id: &str) {
        if let Ok(mut parents) = self.parents.lock() {
            parents.remove(request_id);
        }
    }

    /// Interrupts attended input when the connection ends while a prompt is open.
    pub(super) fn connection_closed(&self) {
        if *self.window.borrow()
            && let Some(provider) = &self.provider
        {
            provider.cancel();
        }
    }

    /// Answers a prompt frame without blocking the reader. A frame that cannot be answered
    /// (unreadable metadata, or a second prompt while one is open) is dropped.
    pub(super) fn handle(self: &Arc<Self>, frame: &LocalBusFrame) {
        if frame.kind != LocalBusFrameKind::Request || *self.window.borrow() {
            return;
        }
        let Some((generation, action)) = replyable(frame) else {
            return;
        };
        let correlated = self
            .parents
            .lock()
            .ok()
            .and_then(|parents| parents.get(&frame.request_id).cloned())
            .and_then(|parent| validate_prompt(&parent, frame).ok());
        self.window.send_replace(true);
        let prompts = Arc::clone(self);
        if let (Some(provider), Some((_, metadata))) = (&self.provider, correlated) {
            let provider = Arc::clone(provider);
            tokio::spawn(async move {
                let outcome = tokio::task::spawn_blocking(move || provider.provide(&metadata))
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or(CredentialOutcome::Refused);
                prompts.send(generation, &action, &outcome).await;
            });
        } else {
            tokio::spawn(async move {
                prompts.send(generation, &action, &CredentialOutcome::Refused).await;
            });
        }
    }

    async fn send(&self, generation: u64, action: &str, outcome: &CredentialOutcome) {
        let reply = encode_reply(generation, action, outcome)
            .or_else(|_| encode_reply(generation, action, &CredentialOutcome::Refused));
        match reply {
            Ok(reply) => {
                if self.replies.send(reply).await.is_err() {
                    self.window.send_replace(false);
                }
            }
            Err(_) => {
                self.window.send_replace(false);
            }
        }
    }

    /// Called by the writer once the reply bytes are on the wire.
    pub(super) fn reply_written(&self) {
        self.window.send_replace(false);
    }
}

/// Generation and action of a prompt the connection can answer at all.
fn replyable(frame: &LocalBusFrame) -> Option<(u64, String)> {
    let generation = frame.frame_id.strip_prefix("credential-")?.parse::<u64>().ok()?;
    if generation == 0 || frame.frame_id != format!("credential-{generation}") {
        return None;
    }
    let metadata: CredentialRequest = serde_json::from_value(frame.body.clone()).ok()?;
    metadata.validate().ok()?;
    Some((generation, metadata.action))
}

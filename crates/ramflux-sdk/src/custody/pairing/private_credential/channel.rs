// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A connection owns its prompt/reply slot; cancelling a provider wakes its blocking callback.
use super::{
    CredentialOutcome, CredentialRequest, PrivateCredentialReply, PrivateCredentialScope,
    PrivateCredentialSlot, invalid, read_reply_checked,
};
use crate::{SdkError, custody::pairing::LocalCredentialProvider};
use std::{
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
};
/// Emits public prompt metadata only, to the initiating connection.
pub type PrivateCredentialPrompt =
    dyn Fn(u64, &CredentialRequest) -> Result<(), SdkError> + Send + Sync;
/// Prompts for one provider key. The closure sends public metadata only.
pub type HostCredentialPrompt = dyn Fn(u64, &str) -> Result<(), SdkError> + Send + Sync;
/// Revalidates local call metadata/liveness before prompting and before consuming a secret.
/// Implementations must not perform network I/O or acquire an account writer loan.
pub type PrivateCredentialScopeResolver =
    dyn Fn(&CredentialRequest) -> Result<PrivateCredentialScope, SdkError> + Send + Sync;
struct Waiting {
    generation: u64,
    scope: PrivateCredentialScope,
    reply: Option<mpsc::SyncSender<PrivateCredentialReply>>,
}
struct HostWait {
    generation: u64,
    reply: Option<mpsc::SyncSender<Result<zeroize::Zeroizing<String>, SdkError>>>,
}
struct State {
    closed: bool,
    slot: PrivateCredentialSlot,
    waiting: Option<Waiting>,
    host: Option<HostWait>,
}
/// Same-connection private provider endpoint. No secret is retained in its shared state.
pub struct PrivateCredentialChannel {
    connection: u64,
    state: Mutex<State>,
    prompt: Arc<PrivateCredentialPrompt>,
    host_prompt: Mutex<Option<Arc<HostCredentialPrompt>>>,
}
struct Provider {
    channel: Arc<PrivateCredentialChannel>,
    account: String,
    resolve: Arc<PrivateCredentialScopeResolver>,
    cancelled: AtomicBool,
    issued: AtomicU64,
}
struct Pending {
    channel: Arc<PrivateCredentialChannel>,
    generation: u64,
    receiver: Option<mpsc::Receiver<PrivateCredentialReply>>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.channel.retire_generation(self.generation);
    }
}
impl PrivateCredentialChannel {
    #[must_use]
    pub fn new(connection: u64, prompt: Arc<PrivateCredentialPrompt>) -> Self {
        Self {
            connection,
            state: Mutex::new(State {
                closed: false,
                slot: PrivateCredentialSlot::new(connection),
                waiting: None,
                host: None,
            }),
            prompt,
            host_prompt: Mutex::new(None),
        }
    }
    /// Install the desktop prompt used by `agent.host.manage`. Pairing prompts stay unchanged.
    pub fn set_host_prompt(&self, prompt: Arc<HostCredentialPrompt>) {
        *self.host_prompt.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(prompt);
    }
    /// Build a private provider bound to one local account and the initiating connection.
    #[must_use]
    pub fn provider(
        self: &Arc<Self>,
        account: String,
        resolve: Arc<PrivateCredentialScopeResolver>,
    ) -> Arc<dyn LocalCredentialProvider> {
        Arc::new(Provider {
            channel: self.clone(),
            account,
            resolve,
            cancelled: AtomicBool::new(false),
            issued: AtomicU64::new(0),
        })
    }
    /// Current expected binary reply. No secret or account identifiers are returned.
    #[must_use]
    pub fn expects_reply(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .waiting
            .as_ref()
            .is_some_and(|waiting| waiting.reply.is_some())
    }
    /// Public metadata for this connection's one expected private frame.
    #[must_use]
    pub fn expected_reply(&self) -> Option<(u64, String)> {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .waiting
            .as_ref()
            .filter(|waiting| waiting.reply.is_some())
            .map(|waiting| (waiting.generation, waiting.scope.request.action.clone()))
    }
    /// Permanently close this transport; saved provider handles cannot issue another prompt.
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        state.waiting = None;
        state.host = None;
        state.slot.retire();
    }
    /// Generation of the outstanding provider-key prompt, if this connection is waiting for one.
    #[must_use]
    pub fn host_generation(&self) -> Option<u64> {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.host.as_ref().filter(|host| host.reply.is_some()).map(|host| host.generation)
    }
    /// Drop an unanswered provider-key prompt. A late reply is ignored.
    pub fn cancel_host(&self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.host = None;
    }
    /// Retire pending input before waiting for its worker. The connection remains reusable.
    pub fn retire(&self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.waiting = None;
        state.slot.retire();
    }
    fn retire_generation(&self, generation: u64) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.waiting.as_ref().is_some_and(|waiting| waiting.generation == generation) {
            state.waiting = None;
            state.slot.retire();
        }
    }
    fn begin(self: &Arc<Self>, scope: &PrivateCredentialScope) -> Result<Pending, SdkError> {
        let (reply, receiver) = mpsc::sync_channel(1);
        let generation = {
            let mut state = self.state.lock().map_err(|_| invalid())?;
            if state.closed {
                return Err(SdkError::PairingCode("Retired"));
            }
            if state.host.is_some() {
                return Err(SdkError::PairingCode("Busy"));
            }
            let generation = state.slot.issue(scope.clone())?;
            state.waiting = Some(Waiting { generation, scope: scope.clone(), reply: Some(reply) });
            generation
        };
        let pending = Pending { channel: self.clone(), generation, receiver: Some(receiver) };
        (self.prompt)(generation, &scope.request)?;
        Ok(pending)
    }
    /// Consume one raw frame in this connection's private reader, never a JSON reader.
    /// Invalid input retires the callback and erases any decoded secret.
    /// # Errors
    /// Refuses another connection/generation, an absent slot or a malformed binary frame.
    pub fn deliver(&self, connection: u64, reader: &mut impl Read) -> Result<(), SdkError> {
        let (generation, action) = {
            let state = self.state.lock().map_err(|_| invalid())?;
            let waiting = state
                .waiting
                .as_ref()
                .filter(|waiting| waiting.reply.is_some())
                .ok_or_else(invalid)?;
            if connection != self.connection {
                return Err(invalid());
            }
            (waiting.generation, waiting.scope.request.action.clone())
        };
        let reply = match read_reply_checked(reader, &action, Some(generation)) {
            Ok(reply) => reply,
            Err(error) => {
                self.retire_generation(generation);
                return Err(error);
            }
        };
        self.deliver_reply(connection, reply)
    }
    /// Deliver an opaque reply produced by the dedicated bounded async reader.
    /// # Errors
    /// Refuses a closed/replaced slot, wrong connection/action/generation or a second reply.
    pub fn deliver_reply(
        &self,
        connection: u64,
        reply: PrivateCredentialReply,
    ) -> Result<(), SdkError> {
        let sender = {
            let mut state = self.state.lock().map_err(|_| invalid())?;
            if connection != self.connection || state.closed {
                return Err(invalid());
            }
            state
                .waiting
                .as_mut()
                .filter(|waiting| {
                    waiting.generation == reply.generation
                        && waiting.scope.request.action == reply.action
                })
                .and_then(|waiting| waiting.reply.take())
                .ok_or_else(invalid)?
        };
        sender.send(reply).map_err(|_| invalid())
    }
    /// Ask the same connection for one provider key. Fails closed when pairing already holds the slot.
    ///
    /// # Errors
    /// Returns `credential_unavailable` when the slot is busy, closed, or no prompt is installed,
    /// and `field_invalid` when `provider` is not a label.
    pub fn begin_host(
        &self,
        provider: &str,
    ) -> Result<mpsc::Receiver<Result<zeroize::Zeroizing<String>, SdkError>>, SdkError> {
        if !provider_label(provider) {
            return Err(host_refused("field_invalid", "provider"));
        }
        let prompt = self
            .host_prompt
            .lock()
            .map_err(|_| invalid())?
            .clone()
            .ok_or_else(|| host_refused("credential_unavailable", "provider key"))?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let generation = {
            let mut state = self.state.lock().map_err(|_| invalid())?;
            if state.closed || state.waiting.is_some() || state.host.is_some() {
                return Err(host_refused("credential_unavailable", "provider key"));
            }
            let generation = super::NEXT_REQUEST
                .try_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |next| next.checked_add(1),
                )
                .map_err(|_| invalid())?;
            state.host = Some(HostWait { generation, reply: Some(sender) });
            generation
        };
        if let Err(error) = prompt(generation, provider) {
            self.cancel_generation(generation);
            return Err(error);
        }
        Ok(receiver)
    }
    /// Deliver one `provider` reply into the outstanding host slot.
    ///
    /// # Errors
    /// Refuses another connection or a generation that is not the outstanding prompt.
    pub fn deliver_host(
        &self,
        connection: u64,
        reply: PrivateCredentialReply,
    ) -> Result<(), SdkError> {
        let sender = {
            let mut state = self.state.lock().map_err(|_| invalid())?;
            if connection != self.connection {
                return Err(invalid());
            }
            let generation = state.host.as_ref().map(|host| host.generation);
            if generation.is_none() {
                return Ok(());
            }
            if generation != Some(reply.generation) {
                return Err(invalid());
            }
            state.host.take().and_then(|host| host.reply)
        };
        if let Some(sender) = sender {
            let _ = sender.send(provider_secret(reply));
        }
        Ok(())
    }
    fn cancel_generation(&self, generation: u64) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.host.as_ref().is_some_and(|host| host.generation == generation) {
            state.host = None;
        }
    }
}

fn provider_label(value: &str) -> bool {
    let Some((first, rest)) = value.as_bytes().split_first() else {
        return false;
    };
    value.len() <= 64
        && first.is_ascii_alphanumeric()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn provider_secret(reply: PrivateCredentialReply) -> Result<zeroize::Zeroizing<String>, SdkError> {
    match reply.into_provider_key() {
        Ok(secret) => Ok(secret),
        Err(SdkError::PairingCode("Refused")) => {
            Err(host_refused("credential_unavailable", "provider key"))
        }
        Err(error) => Err(error),
    }
}

fn host_refused(code: &'static str, message: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.to_owned(),
        message: message.to_owned(),
        body: Box::new(serde_json::json!({ "reason_code": code })),
    }
}
struct Issued<'a> {
    owner: &'a AtomicU64,
    generation: u64,
}
impl Drop for Issued<'_> {
    fn drop(&mut self) {
        let _ =
            self.owner.compare_exchange(self.generation, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}
impl LocalCredentialProvider for Provider {
    fn provide(&self, request: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(SdkError::PairingCode("Retired"));
        }
        if request.local_account_id != self.account {
            return Err(invalid());
        }
        let scope = (self.resolve)(request)?;
        if scope.request != *request {
            return Err(invalid());
        }
        let mut pending = self.channel.begin(&scope)?;
        self.issued.store(pending.generation, Ordering::Release);
        let _issued = Issued { owner: &self.issued, generation: pending.generation };
        if self.cancelled.load(Ordering::Acquire) {
            return Ok(CredentialOutcome::Refused);
        }
        let receiver = pending.receiver.take().ok_or_else(invalid)?;
        let Ok(reply) = receiver.recv() else {
            return Ok(CredentialOutcome::Refused);
        };
        let current = (self.resolve)(request)?;
        let mut state = self.channel.state.lock().map_err(|_| invalid())?;
        let outcome = state.slot.consume(self.channel.connection, &current, reply);
        state.waiting = None;
        outcome
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let generation = self.issued.load(Ordering::Acquire);
        if generation != 0 {
            self.channel.retire_generation(generation);
        }
    }
}

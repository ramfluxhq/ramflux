// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-generation memory only. No request, response or cadence state is serializable.
use super::{MAX_BYTES, MAX_ROWS};
use crate::{
    SdkError,
    bindings::{AdapterError, GeneratedErrorCode},
};
use ramflux_protocol::message as g;
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

const CADENCE: Duration = Duration::from_millis(4000);
const WINDOW: Duration = Duration::from_secs(60);
const FRAMES_PER_WINDOW: usize = 20;
struct Cached {
    hash: [u8; 32],
    response: Option<g::MessageUpdate>,
    failure: GeneratedErrorCode,
    charge: usize,
    sealed: bool,
}
#[derive(Default)]
struct Target {
    last_active: Option<Instant>,
    active: bool,
    offline_until: Option<Instant>,
}
#[derive(Default)]
pub(crate) struct Sender {
    focused: Option<String>,
    requests: BTreeMap<Vec<u8>, Cached>,
    targets: BTreeMap<(String, String), Target>,
    windows: BTreeMap<String, VecDeque<Instant>>,
}
fn error(code: GeneratedErrorCode, reason: &str) -> SdkError {
    AdapterError::new(code, reason).into()
}
impl Sender {
    pub(crate) fn focus(&mut self, conversation: Option<&str>) -> Result<Option<String>, SdkError> {
        if conversation.is_some_and(|value| value.len() > MAX_BYTES.saturating_sub(self.bytes())) {
            return Err(error(GeneratedErrorCode::RateLimited, "typing memory budget exhausted"));
        }
        if self.focused.as_deref() == conversation {
            return Ok(None);
        }
        let old = self.focused.take();
        self.focused = conversation.map(str::to_owned);
        Ok(old.filter(|old| Some(old.as_str()) != conversation))
    }
    pub(crate) fn is_focused(&self, conversation: &str) -> bool {
        self.focused.as_deref() == Some(conversation)
    }
    pub(crate) fn lookup(
        &self,
        operation: &[u8],
        hash: &[u8; 32],
    ) -> Result<Option<g::MessageUpdate>, SdkError> {
        let Some(cached) = self.requests.get(operation) else {
            return Ok(None);
        };
        if &cached.hash != hash {
            return Err(error(
                GeneratedErrorCode::InvalidArgument,
                "conflicting typing operation id",
            ));
        }
        cached
            .response
            .clone()
            .map(Some)
            .ok_or_else(|| error(cached.failure, "typing request already attempted"))
    }
    pub(crate) fn reserve(
        &mut self,
        operation: &[u8],
        hash: [u8; 32],
        response_bytes: usize,
    ) -> Result<(), SdkError> {
        let charge = operation
            .len()
            .saturating_add(response_bytes)
            .saturating_add(std::mem::size_of::<Cached>());
        if self.bytes().saturating_add(charge) > MAX_BYTES {
            return Err(error(GeneratedErrorCode::RateLimited, "typing memory budget exhausted"));
        }
        self.requests.insert(
            operation.to_vec(),
            Cached {
                hash,
                response: None,
                failure: GeneratedErrorCode::EphemeralUnavailable,
                charge,
                sealed: false,
            },
        );
        Ok(())
    }
    pub(crate) fn finish(&mut self, operation: &[u8], result: &Result<g::MessageUpdate, SdkError>) {
        if result.is_err() && self.requests.get(operation).is_some_and(|cached| !cached.sealed) {
            self.requests.remove(operation);
            return;
        }
        if let Some(cached) = self.requests.get_mut(operation) {
            match result {
                Ok(response) => cached.response = Some(response.clone()),
                Err(error) => {
                    cached.failure =
                        GeneratedErrorCode::try_from(AdapterError::from_sdk(error).code)
                            .unwrap_or(GeneratedErrorCode::Internal);
                }
            }
        }
    }
    pub(crate) fn admit(
        &mut self,
        conversation: &str,
        target: &str,
        active: bool,
        now: Instant,
    ) -> Result<bool, SdkError> {
        self.prune(now);
        if active && !self.is_focused(conversation) {
            return Err(error(
                GeneratedErrorCode::EphemeralUnavailable,
                "typing conversation is not focused",
            ));
        }
        let key = (conversation.to_owned(), target.to_owned());
        if let Some(state) = self.targets.get(&key) {
            if state.offline_until.is_some_and(|until| now < until) {
                return Ok(false);
            }
            if !active && !state.active {
                return Ok(false);
            }
            if active
                && state.last_active.is_some_and(|last| {
                    now.checked_duration_since(last).is_none_or(|elapsed| elapsed < CADENCE)
                })
            {
                return Err(error(GeneratedErrorCode::RateLimited, "typing cadence limit"));
            }
        } else if !active {
            return Ok(false);
        }
        if self.windows.get(conversation).is_some_and(|window| window.len() >= FRAMES_PER_WINDOW) {
            return Err(error(GeneratedErrorCode::RateLimited, "typing conversation rate limit"));
        }
        if !self.targets.contains_key(&key)
            && (self.targets.len() >= MAX_ROWS
                || self
                    .bytes()
                    .saturating_add(conversation.len())
                    .saturating_add(target.len())
                    .saturating_add(std::mem::size_of::<Target>())
                    .saturating_add(conversation.len())
                    .saturating_add(FRAMES_PER_WINDOW * std::mem::size_of::<Instant>())
                    > MAX_BYTES)
        {
            return Err(error(GeneratedErrorCode::RateLimited, "typing scope capacity"));
        }
        Ok(true)
    }
    pub(crate) fn sealed(&mut self, conversation: &str, target: &str, active: bool, now: Instant) {
        let state = self.targets.entry((conversation.into(), target.into())).or_default();
        if active {
            state.last_active = Some(now);
        }
        state.active = active;
        self.windows.entry(conversation.into()).or_default().push_back(now);
    }
    pub(crate) fn mark_sealed(&mut self, operation: &[u8]) {
        if let Some(cached) = self.requests.get_mut(operation) {
            cached.sealed = true;
        }
    }
    pub(crate) fn offline(&mut self, conversation: &str, target: &str, now: Instant) {
        if let Some(state) = self.targets.get_mut(&(conversation.into(), target.into())) {
            state.offline_until = now.checked_add(WINDOW);
        }
    }
    pub(crate) fn received(&mut self, target: &str) {
        for ((_, peer), state) in &mut self.targets {
            if peer == target {
                state.offline_until = None;
            }
        }
    }
    fn prune(&mut self, now: Instant) {
        self.windows.retain(|_, window| {
            window.retain(|at| now.checked_duration_since(*at).is_none_or(|age| age < WINDOW));
            !window.is_empty()
        });
        self.targets.retain(|_, state| {
            if state.last_active.is_some_and(|at| {
                now.checked_duration_since(at).is_some_and(|age| age >= Duration::from_secs(5))
            }) {
                state.active = false;
            }
            state.active
                || state.offline_until.is_some_and(|until| now < until)
                || state
                    .last_active
                    .is_some_and(|at| now.checked_duration_since(at).is_none_or(|age| age < WINDOW))
        });
    }
    fn bytes(&self) -> usize {
        let requests = self.requests.values().map(|cached| cached.charge).sum::<usize>();
        let scopes = self
            .targets
            .keys()
            .map(|(conversation, target)| {
                conversation.len() + target.len() + std::mem::size_of::<Target>()
            })
            .sum::<usize>();
        let windows = self
            .windows
            .iter()
            .map(|(conversation, window)| {
                conversation.len() + window.len() * std::mem::size_of::<Instant>()
            })
            .sum::<usize>();
        requests
            .saturating_add(scopes)
            .saturating_add(windows)
            .saturating_add(self.focused.as_ref().map_or(0, String::len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn typing_rate_limits_are_per_peer_and_conversation() -> TestResult {
        let mut sender = Sender::default();
        let start = Instant::now();
        sender.focus(Some("c"))?;
        for index in 0..10 {
            let at = start + Duration::from_secs(index * 4);
            assert!(sender.admit("c", "peer", true, at)?);
            sender.sealed("c", "peer", true, at);
            assert!(sender.admit("c", "peer", false, at + Duration::from_millis(1))?);
            sender.sealed("c", "peer", false, at + Duration::from_millis(1));
            assert!(!sender.admit("c", "peer", false, at + Duration::from_millis(2))?);
        }
        assert!(sender.admit("c", "another-peer", true, start + Duration::from_secs(40)).is_err());
        assert!(sender.admit("c", "peer", true, start + Duration::from_secs(60))?);
        sender.focus(Some("other"))?;
        assert!(sender.admit("other", "peer", true, start + Duration::from_secs(40))?);
        assert!(sender.admit("c", "peer", true, start + Duration::from_secs(65)).is_err());
        Ok(())
    }
    #[test]
    fn typing_offline_suppression_expires_or_peer_progress_clears_it() -> TestResult {
        let mut sender = Sender::default();
        let start = Instant::now();
        sender.focus(Some("c"))?;
        sender.sealed("c", "peer", true, start);
        assert!(sender.admit("c", "peer", true, start + Duration::from_millis(3999)).is_err());
        sender.offline("c", "peer", start);
        assert!(!sender.admit("c", "peer", true, start + Duration::from_secs(4))?);
        sender.received("peer");
        assert!(sender.admit("c", "peer", true, start + Duration::from_secs(4))?);
        sender.offline("c", "peer", start + Duration::from_secs(4));
        assert!(!sender.admit("c", "peer", true, start + Duration::from_secs(63))?);
        assert!(sender.admit("c", "peer", true, start + Duration::from_secs(64))?);
        Ok(())
    }
    #[test]
    fn typing_duplicate_keeps_original_lifetime_until_generation_drops() -> TestResult {
        let mut sender = Sender::default();
        let operation = vec![1; 16];
        sender.reserve(&operation, [1; 32], 512)?;
        let update = g::MessageUpdate {
            account_id: "a".into(),
            journal_sequence: 0,
            identity: None,
            state: Some(g::message_update::State::Content(g::Content {
                value: Some(g::content::Value::Typing(g::Typing { active: true, expires_at: 5 })),
            })),
        };
        sender.finish(&operation, &Ok(update.clone()));
        sender.prune(Instant::now() + Duration::from_secs(3600));
        assert_eq!(sender.lookup(&operation, &[1; 32])?, Some(update));
        assert!(sender.lookup(&operation, &[2; 32]).is_err());
        assert!(sender.reserve(&[2; 16], [2; 32], MAX_BYTES).is_err());
        assert_eq!(Sender::default().lookup(&operation, &[1; 32])?, None);
        Ok(())
    }
}

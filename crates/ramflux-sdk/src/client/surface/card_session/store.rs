// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-scoped sessions on the actor thread. The VM is not Send.
use super::super::invalid;
use super::sign::Pending;
use crate::SdkError;
use ramflux_card::CardSession;
use std::cell::RefCell;
use std::collections::BTreeSet;

const MAX_SESSIONS: usize = 32;

pub(super) struct Held {
    account_id: String,
    surface_ref: String,
    fallback: String,
    signed_version: u64,
    signed_hash: String,
    session: CardSession,
    pending: Option<Pending>,
    consumed: BTreeSet<String>,
}

thread_local! {
    static SESSIONS: RefCell<Vec<Held>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn insert(
    account: &str,
    surface_ref: &str,
    session: CardSession,
    fallback: &str,
    signed_version: u64,
    signed_hash: &str,
) -> Result<u64, SdkError> {
    with_all(|sessions| {
        sessions.retain(|held| !(held.account_id == account && held.surface_ref == surface_ref));
        if sessions.len() >= MAX_SESSIONS {
            return Err(invalid("card_session_limit"));
        }
        let id = session.id();
        sessions.push(Held {
            account_id: account.to_owned(),
            surface_ref: surface_ref.to_owned(),
            fallback: fallback.to_owned(),
            signed_version,
            signed_hash: signed_hash.to_owned(),
            session,
            pending: None,
            consumed: BTreeSet::new(),
        });
        Ok(id)
    })
}

pub(super) fn with_session<T>(
    account: &str,
    id: u64,
    visit: impl FnOnce(&mut Held) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    with_all(|sessions| {
        let held = sessions
            .iter_mut()
            .find(|held| held.account_id == account && held.session.id() == id)
            .ok_or_else(|| invalid("card_session_inactive"))?;
        visit(held)
    })
}

pub(super) fn remove(account: &str, id: u64) -> Result<Option<String>, SdkError> {
    with_all(|sessions| {
        let Some(index) =
            sessions.iter().position(|held| held.account_id == account && held.session.id() == id)
        else {
            return Ok(None);
        };
        let held = sessions.remove(index);
        Ok(Some(held.fallback))
    })
}

pub(super) fn clear_pending(account: &str, id: u64, message_id: &str) -> Result<(), SdkError> {
    with_session(account, id, |held| {
        if held.pending.as_ref().is_some_and(|pending| pending.message_id == message_id) {
            held.pending = None;
        }
        Ok(())
    })
}

fn with_all<T>(visit: impl FnOnce(&mut Vec<Held>) -> Result<T, SdkError>) -> Result<T, SdkError> {
    SESSIONS.with(|cell| {
        let mut sessions = cell.try_borrow_mut().map_err(|_| invalid("card_session_busy"))?;
        visit(&mut sessions)
    })
}

impl Held {
    pub(super) fn session(&mut self) -> &mut CardSession {
        &mut self.session
    }

    pub(super) fn session_ref(&self) -> &CardSession {
        &self.session
    }

    pub(super) fn set_fallback(&mut self, fallback: &str) {
        fallback.clone_into(&mut self.fallback);
    }

    pub(super) fn surface_ref(&self) -> &str {
        &self.surface_ref
    }

    pub(super) fn pending(&self) -> Option<&Pending> {
        self.pending.as_ref()
    }

    pub(super) fn set_pending(&mut self, pending: Option<Pending>) {
        self.pending = pending;
    }

    pub(super) fn consume(&mut self, request_id: &str) -> bool {
        self.consumed.insert(request_id.to_owned())
    }

    pub(super) fn matches(&self, state: &ramflux_protocol::SurfaceState) -> bool {
        self.signed_version == state.version() && state.hash() == Some(self.signed_hash.as_str())
    }

    pub(super) fn adopt(&mut self, state: &ramflux_protocol::SurfaceState, fallback: &str) {
        self.signed_version = state.version();
        if let Some(hash) = state.hash() {
            hash.clone_into(&mut self.signed_hash);
        }
        fallback.clone_into(&mut self.fallback);
        if self.pending.as_ref().is_some_and(|pending| {
            pending.surface_version != self.signed_version
                || pending.surface_hash != self.signed_hash
        }) {
            self.pending = None;
        }
    }
}

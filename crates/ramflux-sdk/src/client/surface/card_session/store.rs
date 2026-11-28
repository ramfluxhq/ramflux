// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-scoped sessions on the actor thread. The VM is not Send.
use super::codes::{expired, typed};
use super::registry;
use super::sign::Pending;
use crate::SdkError;
use ramflux_card::CardSession;
use std::cell::RefCell;
use std::collections::BTreeSet;

const MAX_SESSIONS: usize = 32;

const MAX_CONSUMED: usize = 256;

pub(super) struct Held {
    account_id: String,
    surface_ref: String,
    conversation: String,
    connection: u64,
    fallback: String,
    locale: String,
    dark: bool,
    signed_version: u64,
    signed_hash: String,
    session: CardSession,
    pending: Option<Pending>,
    consumed: BTreeSet<String>,
}

thread_local! {
    static SESSIONS: RefCell<Vec<Held>> = const { RefCell::new(Vec::new()) };
}

pub(super) struct Opened<'a> {
    pub account: &'a str,
    pub connection: u64,
    pub surface_ref: &'a str,
    pub conversation: &'a str,
    pub fallback: &'a str,
    pub signed_version: u64,
    pub signed_hash: &'a str,
}

pub(super) fn insert(session: CardSession, opened: &Opened<'_>) -> Result<u64, SdkError> {
    let Opened { account, connection, surface_ref, conversation, fallback, .. } = *opened;
    sweep_closed(account);
    with_all(|sessions| {
        sessions.retain(|held| !(held.account_id == account && held.surface_ref == surface_ref));
        if sessions.len() >= MAX_SESSIONS {
            return Err(typed("card_session_limit"));
        }
        let id = session.id();
        sessions.push(Held {
            account_id: account.to_owned(),
            surface_ref: surface_ref.to_owned(),
            conversation: conversation.to_owned(),
            connection,
            fallback: fallback.to_owned(),
            locale: "en".to_owned(),
            dark: false,
            signed_version: opened.signed_version,
            signed_hash: opened.signed_hash.to_owned(),
            session,
            pending: None,
            consumed: BTreeSet::new(),
        });
        registry::track(connection, account)?;
        Ok(id)
    })
}

pub(super) fn with_session<T>(
    account: &str,
    id: u64,
    visit: impl FnOnce(&mut Held) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    sweep_closed(account);
    with_all(|sessions| {
        let Some(held) =
            sessions.iter_mut().find(|held| held.account_id == account && held.session.id() == id)
        else {
            return Err(if registry::is_expired(account, id)? {
                expired(id)
            } else {
                typed("card_session_inactive")
            });
        };
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

/// Drop every session of `account`. Later calls with those ids fail with `card_session_expired`.
pub(super) fn drop_account(account: &str, reason: &str) {
    drop_where(account, reason, |_| true);
    registry::forget_account(account);
}

/// Drop the held session of `surface_ref`, if any, so its VM slot is free before a reopen.
pub(super) fn drop_surface(account: &str, surface_ref: &str) {
    drop_where(account, "reopened", |held| held.surface_ref == surface_ref);
}

/// Drop the sessions of connections that closed. Runs on the actor thread.
pub(super) fn sweep_closed(account: &str) {
    let closed = match registry::take_closed(account) {
        Ok(closed) if !closed.is_empty() => closed,
        Ok(_) => return,
        Err(error) => {
            tracing::warn!(%error, account_id = account, "card session sweep skipped");
            return;
        }
    };
    drop_where(account, "connection_closed", |held| closed.contains(&held.connection));
}

fn drop_where(account: &str, reason: &str, doomed: impl Fn(&Held) -> bool) {
    let dropped = with_all(|sessions| {
        let mut count = 0_usize;
        let mut highest = 0_u64;
        sessions.retain(|held| {
            if held.account_id != account || !doomed(held) {
                return true;
            }
            count += 1;
            highest = highest.max(held.session.id());
            false
        });
        Ok((count, highest))
    });
    match dropped {
        Ok((0, _)) => {}
        Ok((count, highest)) => {
            if let Err(error) = registry::raise_floor(account, highest) {
                tracing::warn!(%error, account_id = account, "card session floor not recorded");
            }
            tracing::info!(account_id = account, reason, sessions = count, "card sessions dropped");
        }
        Err(error) => {
            tracing::warn!(%error, account_id = account, reason, "card sessions not dropped");
        }
    }
}

fn with_all<T>(visit: impl FnOnce(&mut Vec<Held>) -> Result<T, SdkError>) -> Result<T, SdkError> {
    SESSIONS.with(|cell| {
        let mut sessions = cell.try_borrow_mut().map_err(|_| typed("card_session_busy"))?;
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

    pub(super) fn locale(&self) -> &str {
        &self.locale
    }

    pub(super) fn dark(&self) -> bool {
        self.dark
    }

    pub(super) fn set_presentation(&mut self, locale: &str, dark: bool) {
        locale.clone_into(&mut self.locale);
        self.dark = dark;
    }

    pub(super) fn conversation(&self) -> &str {
        &self.conversation
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

    pub(super) fn clear_consumed(&mut self) {
        self.consumed.clear();
    }

    /// One decision for this SDK request, slot and surface revision.
    pub(super) fn consume_binding(&mut self, record: &str, slot: &str, token: &str) -> bool {
        if self.consumed.len() >= MAX_CONSUMED
            || record.len() > 256
            || slot.len() > 1024
            || token.len() > 64
        {
            return false;
        }
        if self
            .consumed
            .iter()
            .any(|item| item.split_once('\n').is_some_and(|(id, _)| id == record))
        {
            return false;
        }
        self.consumed.insert(format!("{record}\n{slot}\n{token}"))
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
        self.clear_consumed();
        if self.pending.as_ref().is_some_and(|pending| {
            pending.surface_version != self.signed_version
                || pending.surface_hash != self.signed_hash
        }) {
            self.pending = None;
        }
    }
}

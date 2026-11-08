// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SQL / inbox-request / outgoing-ACK / hold-delete hooks. The authority on each
//! event is the real token the executor minted, never a caller-supplied label.

use super::executor::authority::AuthorityKind;
use std::cell::RefCell;

thread_local! {
    static SQL: RefCell<Vec<SqlWrite>> = const { RefCell::new(Vec::new()) };
    static ACK: RefCell<Vec<AckFrame>> = const { RefCell::new(Vec::new()) };
    static DELETE: RefCell<Vec<HoldDelete>> = const { RefCell::new(Vec::new()) };
    static INBOX: RefCell<Vec<InboxRequest>> = const { RefCell::new(Vec::new()) };
}

/// Receive-checkpoint SQL write observed by the guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SqlWrite {
    pub seq: u64,
    pub kind: super::executor::authority::AuthorityKind,
}

/// Outgoing Ack / `AckBatch` frame. `kind` is `None` when the frame left WA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AckFrame {
    pub seq: u64,
    pub kind: Option<super::executor::authority::AuthorityKind>,
}

/// Hold-table delete. `kind` is `None` when the delete had no transaction authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HoldDelete {
    pub id: String,
    pub kind: Option<super::executor::authority::AuthorityKind>,
}

/// Inbox Resume / page request issued by the executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InboxRequest {
    pub after: u64,
    pub limit: usize,
}

pub(super) fn record_sql(seq: u64, kind: AuthorityKind) {
    SQL.with(|rows| rows.borrow_mut().push(SqlWrite { seq, kind }));
}

pub(super) fn record_ack(seq: u64, kind: Option<AuthorityKind>) {
    ACK.with(|rows| rows.borrow_mut().push(AckFrame { seq, kind }));
}

pub(super) fn record_delete(id: &str, kind: Option<AuthorityKind>) {
    DELETE.with(|rows| rows.borrow_mut().push(HoldDelete { id: id.to_owned(), kind }));
}

pub(super) fn record_inbox(after: u64, limit: usize) {
    INBOX.with(|rows| rows.borrow_mut().push(InboxRequest { after, limit }));
}

pub(crate) fn take_sql() -> Vec<SqlWrite> {
    SQL.with(|rows| std::mem::take(&mut *rows.borrow_mut()))
}

pub(crate) fn take_acks() -> Vec<AckFrame> {
    ACK.with(|rows| std::mem::take(&mut *rows.borrow_mut()))
}

pub(crate) fn take_deletes() -> Vec<HoldDelete> {
    DELETE.with(|rows| std::mem::take(&mut *rows.borrow_mut()))
}

pub(crate) fn take_inbox() -> Vec<InboxRequest> {
    INBOX.with(|rows| std::mem::take(&mut *rows.borrow_mut()))
}

pub(crate) fn clear() {
    let _ = take_sql();
    let _ = take_acks();
    let _ = take_deletes();
    let _ = take_inbox();
}

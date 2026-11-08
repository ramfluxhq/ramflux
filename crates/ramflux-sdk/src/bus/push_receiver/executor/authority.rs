// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unforgeable W2 / reset / WA / WS / erasure tokens. Constructors are `pub(super)`
//! to [`super::LedgerExecutor`] only; storage-result conversion is the sole mint path.
//! Tokens are neither `Copy` nor `Clone`: each is consumed on use and bound to the
//! `ReceiveTransaction` that minted it (`writer_id`).

/// Kind of ledger write the holder is allowed to perform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityKind {
    /// Ordered cover wrote C (and optional intent) in one W2 transaction.
    W2,
    /// Explicit incarnation reset may rewrite C.
    Reset,
    /// Wire ACK / `AckBatch`. Minted only after a terminal W2/WS intent with s<=C.
    Wa,
    /// Below-C settlement. Never writes C. May delete holds.
    Ws,
    /// Explicit erasure transaction. May delete holds; never ACKs.
    Erasure,
}

/// Token proving the caller is inside W2, reset, WA, WS, or erasure.
/// There is no public constructor; only the executor mint path constructs it.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LedgerAuthority {
    kind: AuthorityKind,
    seq: u64,
    writer_id: u64,
}

impl LedgerAuthority {
    pub(super) const fn w2(seq: u64, writer_id: u64) -> Self {
        Self { kind: AuthorityKind::W2, seq, writer_id }
    }

    pub(super) const fn reset(seq: u64, writer_id: u64) -> Self {
        Self { kind: AuthorityKind::Reset, seq, writer_id }
    }

    pub(super) const fn wa(seq: u64, writer_id: u64) -> Self {
        Self { kind: AuthorityKind::Wa, seq, writer_id }
    }

    pub(super) const fn ws(seq: u64, writer_id: u64) -> Self {
        Self { kind: AuthorityKind::Ws, seq, writer_id }
    }

    pub(super) const fn erasure(seq: u64, writer_id: u64) -> Self {
        Self { kind: AuthorityKind::Erasure, seq, writer_id }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> AuthorityKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub(crate) const fn writer_id(&self) -> u64 {
        self.writer_id
    }

    #[must_use]
    pub(crate) const fn into_parts(self) -> (AuthorityKind, u64, u64) {
        (self.kind, self.seq, self.writer_id)
    }

    #[must_use]
    pub(crate) const fn is_wa(&self) -> bool {
        matches!(self.kind, AuthorityKind::Wa)
    }

    #[must_use]
    pub(crate) const fn allows_receive_checkpoint(&self) -> bool {
        matches!(self.kind, AuthorityKind::W2 | AuthorityKind::Reset)
    }

    #[must_use]
    pub(crate) const fn allows_hold_delete(&self) -> bool {
        matches!(
            self.kind,
            AuthorityKind::W2 | AuthorityKind::Ws | AuthorityKind::Reset | AuthorityKind::Erasure
        )
    }
}

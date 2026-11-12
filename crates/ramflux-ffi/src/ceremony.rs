// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The account-creation ceremony object.
//!
//! Creation is not an `execute` request: the core binds it to a dedicated connection so that
//! the recovery phrase and the passphrase never enter an ordinary request frame. The binding
//! mirrors that with one object per ceremony. Nothing here logs, stores or copies a secret
//! beyond handing it across the boundary once.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{CoreError, code};
use crate::port::CeremonyPort;

/// Public metadata of a pending ceremony. Safe for UI state and expiry timers.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingCeremony {
    pub ceremony_id: String,
    pub expires_in_ms: u64,
}

/// The account a confirmed ceremony created.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CreatedAccount {
    pub account_id: String,
    pub display_name: String,
    /// Local state of the account as the core names it (for example `unlocked`).
    pub state: String,
    /// Networking state as the core names it (for example `ready` or `pending`). An account
    /// is usable locally before networking is ready.
    pub networking: String,
}

/// One pending account creation. Dropping the object cancels a ceremony that was not
/// confirmed.
#[derive(uniffi::Object)]
pub struct AccountCeremony {
    pending: PendingCeremony,
    port: Arc<dyn CeremonyPort>,
    consumed: AtomicBool,
}

impl AccountCeremony {
    pub(crate) fn new(pending: PendingCeremony, port: Arc<dyn CeremonyPort>) -> Arc<Self> {
        Arc::new(Self { pending, port, consumed: AtomicBool::new(false) })
    }
}

#[uniffi::export]
impl AccountCeremony {
    #[must_use]
    pub fn pending(&self) -> PendingCeremony {
        self.pending.clone()
    }

    /// The recovery phrase. Returned once; show it, then discard it before hiding the view.
    ///
    /// # Errors
    /// The core's refusal for a missing, expired or already displayed ceremony.
    pub async fn show_once(&self) -> Result<String, CoreError> {
        self.port.show_once().await
    }

    /// Three one-based word positions to ask the user for, after the phrase was hidden.
    ///
    /// # Errors
    /// The core's refusal for wrong ordering, replay or expiry.
    pub async fn hidden_challenge(&self) -> Result<Vec<u8>, CoreError> {
        self.port.hidden_challenge().await
    }

    /// Consume the single confirmation attempt and open the account.
    ///
    /// # Errors
    /// `InvalidArgument` unless exactly three words are given or when the attempt was already
    /// used; otherwise the core's refusal (wrong words, expiry, persistence failure).
    pub async fn confirm(
        &self,
        words: Vec<String>,
        passphrase: String,
    ) -> Result<CreatedAccount, CoreError> {
        if words.len() != 3 {
            return Err(CoreError::plain(code::INVALID_ARGUMENT, "exactly three words"));
        }
        if self.consumed.swap(true, Ordering::AcqRel) {
            return Err(CoreError::plain(code::INVALID_ARGUMENT, "confirmation already used"));
        }
        self.port.confirm(words, passphrase).await
    }

    /// Cancel a pending ceremony. Succeeds after a consumed or failed confirmation as well.
    ///
    /// # Errors
    /// The core's transport error.
    pub async fn cancel(&self) -> Result<(), CoreError> {
        self.consumed.store(true, Ordering::Release);
        self.port.cancel().await
    }
}

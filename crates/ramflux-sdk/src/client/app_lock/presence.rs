// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Internal platform presence provider. The public C ABI table is installed in a later card;
//! until then no provider exists, presence is unavailable, and only the account code unlocks.
//! A provider result is never trusted on its own: the caller opens the account with the returned
//! key through the ordinary native unlock path before any access epoch changes.

use crate::SdkError;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Monotonic deadline of one provider operation.
pub(crate) const PRESENCE_DEADLINE: Duration = Duration::from_secs(30);

/// Binds one provider operation to the account, the installed device, the policy generation and
/// a fresh nonce, so a result from another operation cannot be replayed into this one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PresenceBinding {
    pub(crate) account_id: String,
    pub(crate) device_id: String,
    pub(crate) generation: u64,
    pub(crate) nonce: [u8; 32],
}

/// Platform presence key operations as the SDK calls them internally.
#[allow(
    dead_code,
    reason = "the public provider table that calls wrap arrives with the C ABI card"
)]
pub(crate) trait AppLockPresence: Send + Sync {
    /// Wraps the 32-byte account key for `binding`; the output is opaque and bounded by storage.
    fn wrap(&self, binding: &PresenceBinding, key: &[u8; 32]) -> Result<Vec<u8>, SdkError>;
    /// Unwraps a stored wrap after a fresh presence proof. The result must be exactly 32 bytes.
    fn unwrap(
        &self,
        binding: &PresenceBinding,
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, SdkError>;
    /// Releases an OS item that was staged but never committed.
    fn discard(&self, binding: &PresenceBinding, wrapped: &[u8]);
}

/// The installed presence provider, if any. Nothing installs one before the C ABI card.
#[must_use]
pub(crate) fn installed_provider() -> Option<Arc<dyn AppLockPresence>> {
    None
}

/// Builds a binding with a fresh 32-byte nonce.
///
/// # Errors
/// Returns `CustodyRandomUnavailable` when the operating system cannot supply the nonce.
pub(crate) fn binding(
    account_id: &str,
    device_id: &str,
    generation: u64,
) -> Result<PresenceBinding, SdkError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    Ok(PresenceBinding {
        account_id: account_id.to_owned(),
        device_id: device_id.to_owned(),
        generation,
        nonce,
    })
}

/// Runs one unwrap under the 30 second deadline. A late or failed provider call is refused and
/// its output is dropped without use.
///
/// # Errors
/// `presence_cancelled` on deadline or a lost worker; the provider's own typed refusal otherwise.
pub(crate) async fn unwrap_key(
    provider: Arc<dyn AppLockPresence>,
    binding: PresenceBinding,
    wrapped: Vec<u8>,
) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let task = tokio::task::spawn_blocking(move || provider.unwrap(&binding, &wrapped));
    match tokio::time::timeout(PRESENCE_DEADLINE, task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(_) => Err(refusal(
            "AppLockPresenceCancelled",
            "presence unlock did not complete",
            "presence_cancelled",
        )),
    }
}

/// `presence_unavailable`: no installed provider, or no usable protected wrap.
#[must_use]
pub(crate) fn unavailable() -> SdkError {
    refusal(
        "AppLockPresenceUnavailable",
        "presence unlock is not available on this device",
        "presence_unavailable",
    )
}

fn refusal(code: &str, message: &str, reason: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.into(),
        message: message.into(),
        body: Box::new(serde_json::json!({"reason_code": reason})),
    }
}

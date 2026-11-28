// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The MLS runtime of the SDK: one process-wide crypto provider and one `Mls` per account, over
//! the `SQLCipher` account database. The bus surface (`debug.mls.*`) is MLS-0 part 0c.
mod authority;
pub(crate) mod channel;
mod device_identity;
pub(crate) mod key_packages;
mod kv_adapter;
pub(crate) mod lifecycle;
pub(crate) mod order;
#[allow(dead_code)]
pub(crate) mod group;

use std::sync::{Arc, OnceLock};

pub use kv_adapter::SqlMlsKv;
use ramflux_mls::{CryptoHandle, Mls, MlsError};

use self::authority::SdkAuthority;
use crate::{RamfluxClient, SdkError};

static PROCESS_CRYPTO: OnceLock<CryptoHandle> = OnceLock::new();

impl From<MlsError> for SdkError {
    fn from(error: MlsError) -> Self {
        Self::Mls { code: error.code(), detail: error.to_string() }
    }
}

/// Probe the OS random source and build the one MLS crypto provider of this process. Call at
/// daemon start; idempotent. A failed probe is an error and the daemon must not start.
///
/// # Errors
/// [`SdkError::Mls`] with code `rng_unavailable` when the random source fails.
pub fn init_process_crypto() -> Result<(), SdkError> {
    if PROCESS_CRYPTO.get().is_some() {
        return Ok(());
    }
    let handle = CryptoHandle::init()?;
    // A concurrent initializer that won the race holds an equivalent provider; keep its one.
    let _ = PROCESS_CRYPTO.set(handle);
    Ok(())
}

/// The shared provider handle (an `Arc` clone).
///
/// # Errors
/// [`SdkError::Mls`] when the daemon start did not initialise it.
pub fn process_crypto() -> Result<CryptoHandle, SdkError> {
    PROCESS_CRYPTO.get().cloned().ok_or_else(|| SdkError::Mls {
        code: "internal",
        detail: "the MLS crypto provider is not initialised".to_owned(),
    })
}

/// The MLS runtime of one open account.
pub struct MlsRuntime {
    mls: Mls<SqlMlsKv>,
    kv: SqlMlsKv,
    custody: Option<CustodyStamp>,
}

/// (device-set epoch, issue time, branch key unlocked, own lease deadline).
type CustodyStamp = (u64, u64, bool, u64);

/// What the own credential was built from: the custody record's epoch and issue time, whether the
/// branch key is unlocked and the own lease deadline. A change means the credential must be
/// rebuilt.
fn custody_stamp(client: &RamfluxClient) -> Option<CustodyStamp> {
    client.born_v3_account.as_ref().map(|account| {
        let body = &account.record().body;
        let lease_deadline = account
            .local_device_id()
            .ok()
            .and_then(|id| body.devices.iter().find(|entry| entry.device_id == id))
            .and_then(|entry| entry.branch_certificate.as_ref())
            .map_or(0, |cert| cert.body.expires_at);
        (body.device_set_epoch, body.issued_at, client.device_branch.is_some(), lease_deadline)
    })
}

impl MlsRuntime {
    /// Open the runtime on the client's unlocked account database, with the own device identity
    /// when the account has one.
    ///
    /// # Errors
    /// The account database is locked, the provider is not initialised or storage fails.
    pub fn open(client: &RamfluxClient) -> Result<Self, SdkError> {
        Self::open_for(client, &[])
    }

    /// As [`Self::open`], with the directory heads of the `peers` accounts copied into the
    /// snapshot too (the DM facade seals and opens for them). A peer without a verified head stays
    /// absent: the leaf checks then answer `authority_needed` and the engine refreshes.
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_for(client: &RamfluxClient, peers: &[&str]) -> Result<Self, SdkError> {
        let kv = SqlMlsKv::new(client.account_db()?.mls_kv());
        let authority = Arc::new(SdkAuthority::default());
        // Own head first; further heads are refreshed by the engine on the card's triggers.
        if let Ok(anchor) = client.own_account_anchor() {
            authority.refresh(client, &anchor)?;
        }
        for peer in peers {
            authority.refresh(client, peer)?;
        }
        let mut mls = Mls::new(kv.clone(), process_crypto()?).with_authority(authority);
        if let Some(identity) = client.mls_device_identity()? {
            mls = mls.with_device_identity(identity);
        }
        #[cfg(feature = "itest-mls-debug")]
        {
            mls = mls.with_pinned_roster();
        }
        Ok(Self { mls, kv, custody: custody_stamp(client) })
    }

    /// The facade (every operation returns a `Staged` that the caller commits).
    #[must_use]
    pub fn mls(&self) -> &Mls<SqlMlsKv> {
        &self.mls
    }

    /// Whether this runtime is bound to the client's current account database and custody record.
    #[must_use]
    pub fn is_open_on(&self, client: &RamfluxClient) -> bool {
        self.custody == custody_stamp(client)
            && client.account_db().is_ok_and(|db| self.kv.is_on(&db.mls_kv()))
    }
}

impl RamfluxClient {
    /// The MLS runtime of the active account; rebuilt when the account database was reopened.
    ///
    /// # Errors
    /// See [`MlsRuntime::open`].
    pub fn mls_runtime<'a>(
        &self,
        slot: &'a mut Option<MlsRuntime>,
    ) -> Result<&'a MlsRuntime, SdkError> {
        if slot.as_ref().is_none_or(|runtime| !runtime.is_open_on(self)) {
            *slot = Some(MlsRuntime::open(self)?);
        }
        slot.as_ref().ok_or_else(|| SdkError::Mls {
            code: "internal",
            detail: "the MLS runtime slot is empty".to_owned(),
        })
    }
}

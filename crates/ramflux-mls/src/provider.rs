// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The crypto handle (one construction per process) and the openmls provider.

use std::sync::Arc;

use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::MlsError;
use crate::storage::MlsStorage;
use crate::storage::kv::MlsKv;

/// Size of the start-up RNG probe buffer.
const RNG_PROBE_BYTES: usize = 32;

/// The process-wide crypto provider. Cloning copies the `Arc`, never the provider.
///
/// The provider seeds a `ChaCha20` generator from the operating system and panics inside its
/// default constructor when that source fails, so [`CryptoHandle::init`] probes the source with the
/// same call first and reports a typed error instead.
#[derive(Clone)]
pub struct CryptoHandle {
    crypto: Arc<RustCrypto>,
}

impl CryptoHandle {
    /// Probe the OS random source, then build the provider. Call once at daemon start.
    ///
    /// # Errors
    /// [`MlsError::RngUnavailable`] when the OS random source fails.
    pub fn init() -> Result<Self, MlsError> {
        let mut probe = zeroize::Zeroizing::new([0_u8; RNG_PROBE_BYTES]);
        getrandom::fill(&mut *probe).map_err(|_| MlsError::RngUnavailable)?;
        Ok(Self { crypto: Arc::new(RustCrypto::default()) })
    }

    /// The shared provider.
    #[must_use]
    pub fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
}

/// Provider handed to openmls for one operation: shared crypto plus the overlay storage.
pub struct RfMlsProvider<'k, K: MlsKv> {
    crypto: CryptoHandle,
    storage: MlsStorage<'k, K>,
}

impl<'k, K: MlsKv> RfMlsProvider<'k, K> {
    /// A provider with an empty overlay over `kv`.
    #[must_use]
    pub fn new(crypto: &CryptoHandle, kv: &'k K) -> Self {
        Self { crypto: crypto.clone(), storage: MlsStorage::new(kv) }
    }

    /// The overlay storage (own rows, flush).
    #[must_use]
    pub fn mls_storage(&self) -> &MlsStorage<'k, K> {
        &self.storage
    }
}

impl<'k, K: MlsKv> OpenMlsProvider for RfMlsProvider<'k, K> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MlsStorage<'k, K>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto.crypto()
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto.crypto()
    }
}

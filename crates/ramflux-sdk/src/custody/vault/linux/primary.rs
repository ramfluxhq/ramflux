// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit dormant typed adapters. `NativePrimaryVault` selection is unchanged.
use super::{
    LinuxVaultConfig, LinuxVaultRole,
    cleanup::Secret,
    codec,
    durability::{DurabilityOps, RealDurabilityOps},
    files, init,
    writer::Operation,
};
use crate::{
    SdkError,
    custody::{BranchCredentials, CustodyVaultReason, PrimaryVault},
};
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::custody::DeviceRef;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub(super) fn unavailable<T>(_: T) -> SdkError {
    SdkError::CustodyVaultUnavailable
}
fn reason(reason: CustodyVaultReason) -> SdkError {
    SdkError::CustodyVault(reason)
}
/// Installation and provider failures with a bounded reason; I/O and cancellation stay unit.
pub(super) fn init_error(error: init::LinuxVaultInitError) -> SdkError {
    use init::LinuxVaultInitError as E;
    match error {
        E::Mode => reason(CustodyVaultReason::ModeMismatch),
        E::Metadata => reason(CustodyVaultReason::Permission),
        E::Missing => reason(CustodyVaultReason::Missing),
        E::Pending => reason(CustodyVaultReason::InitPending),
        E::Corrupt | E::Length | E::Realm => reason(CustodyVaultReason::Corrupt),
        E::Busy => reason(CustodyVaultReason::Busy),
        E::Provider | E::Timeout => reason(CustodyVaultReason::Locked),
        E::Random => SdkError::CustodyRandomUnavailable,
        E::Io | E::Cancelled => SdkError::CustodyVaultUnavailable,
    }
}
/// File-store failures with a bounded reason; I/O, collisions and capacity stay unit.
pub(super) fn files_error(error: files::Error) -> SdkError {
    use files::Error as E;
    match error {
        E::Missing => reason(CustodyVaultReason::Missing),
        E::Path | E::Metadata => reason(CustodyVaultReason::Permission),
        E::Busy => reason(CustodyVaultReason::Busy),
        E::Generation => reason(CustodyVaultReason::Corrupt),
        E::Record(error) => codec_error(CodecContext::Read, error),
        E::Io | E::Exists | E::Full => SdkError::CustodyVaultUnavailable,
        #[cfg(test)]
        E::Replacement => SdkError::CustodyVaultUnavailable,
    }
}
/// Where a codec failure arose; the same variant maps differently per context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CodecContext {
    /// Sealing a new record (input length, binding, nonce randomness).
    Insert,
    /// Opening a stored record: any structural or authentication failure is corruption.
    Read,
    /// Validating the account/reference binding before lookup.
    HandleOpen,
}
/// The one codec-to-SDK mapping. It is exhaustive on purpose (no wildcard arm): a new
/// `codec::Error` variant must be classified here. A randomness failure is never corruption.
pub(super) fn codec_error(context: CodecContext, error: codec::Error) -> SdkError {
    use codec::Error as E;
    match error {
        E::Random => SdkError::CustodyRandomUnavailable,
        E::RecordSize
        | E::Magic
        | E::Version
        | E::Realm
        | E::Kind
        | E::Combination
        | E::Generation
        | E::Length
        | E::Account
        | E::Reference
        | E::Authentication => match context {
            CodecContext::Read => reason(CustodyVaultReason::Corrupt),
            CodecContext::Insert | CodecContext::HandleOpen => SdkError::CustodyVaultUnavailable,
        },
    }
}
pub(super) struct Realm {
    store: files::Store,
    key: Secret<32>,
}
impl Realm {
    pub(super) fn read(&self, reference: &str, kind: u8) -> Result<codec::Plaintext, SdkError> {
        let _slot = init::Slot::acquire().map_err(init_error)?;
        let record = self
            .store
            .apply(Operation::Read { reference: reference.into(), kind, generation: 1 }, |_| {})
            .map_err(files_error)?;
        codec::open(self.store.binding(kind, reference, 1), &self.key, &record)
            .map_err(|error| codec_error(CodecContext::Read, error))
    }
    pub(super) fn insert(&self, reference: &str, kind: u8, secret: &[u8]) -> Result<(), SdkError> {
        self.insert_inner(reference, kind, secret, codec::seal)
    }
    /// Test seam for nonce-randomness failure. It exists only under `cfg(test)`; production has
    /// no way to hand a sealer (which sees the KEK and plaintext) to the insert path.
    #[cfg(test)]
    pub(super) fn insert_with(
        &self,
        reference: &str,
        kind: u8,
        secret: &[u8],
        seal: impl FnOnce(
            codec::Binding<'_>,
            &Secret<32>,
            &codec::Plaintext,
        ) -> Result<Vec<u8>, codec::Error>,
    ) -> Result<(), SdkError> {
        self.insert_inner(reference, kind, secret, seal)
    }
    /// Shared insert path. Private: only `insert` (with `codec::seal`) and the test seam call it.
    fn insert_inner(
        &self,
        reference: &str,
        kind: u8,
        secret: &[u8],
        seal: impl FnOnce(
            codec::Binding<'_>,
            &Secret<32>,
            &codec::Plaintext,
        ) -> Result<Vec<u8>, codec::Error>,
    ) -> Result<(), SdkError> {
        let _slot = init::Slot::acquire().map_err(init_error)?;
        let input = codec::Plaintext::new(secret)
            .map_err(|error| codec_error(CodecContext::Insert, error))?;
        let record = seal(self.store.binding(kind, reference, 1), &self.key, &input)
            .map_err(|error| codec_error(CodecContext::Insert, error))?;
        self.store
            .apply(Operation::Insert { reference: reference.into(), kind, record }, |_| {})
            .map(drop)
            .map_err(files_error)
    }
    pub(super) fn delete(&self, reference: &str, kind: u8) -> Result<(), SdkError> {
        self.delete_with(reference, kind, &RealDurabilityOps)
    }
    /// Deletion is idempotent, and absence is only reported after the parent directory was
    /// durably synced under the writer lock (a previous unlink may have lost its fsync).
    pub(super) fn delete_with(
        &self,
        reference: &str,
        kind: u8,
        ops: &dyn DurabilityOps,
    ) -> Result<(), SdkError> {
        let _slot = init::Slot::acquire().map_err(init_error)?;
        match self.store.publish(
            Operation::Delete { reference: reference.into(), kind, generation: 1 },
            ops,
            &|_| Ok(()),
        ) {
            Ok(_) | Err(files::Error::Missing) => Ok(()),
            Err(e) => Err(files_error(e)),
        }
    }
}

/// Directory creation and fsync are blocking work: the stores are built inside a worker that
/// owns a slot (so the four-operation cap applies), never on the async caller.
async fn build_realms(
    root: PathBuf,
    account: String,
    mut material: init::Material,
) -> Result<[Option<Realm>; 3], SdkError> {
    let slot = init::Slot::acquire().map_err(init_error)?;
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        #[cfg(test)]
        test_seam::record_open_thread(&root);
        let mut realms: [Option<Realm>; 3] = std::array::from_fn(|_| None);
        for (i, slot) in realms.iter_mut().enumerate() {
            if let Some(key) = material.keys[i].take() {
                *slot = Some(Realm {
                    store: files::Store::open(
                        &root,
                        &account,
                        u8::try_from(i + 1).map_err(unavailable)?,
                        material.vault_id,
                        material.key_ids[i],
                    )
                    .map_err(files_error)?,
                    key,
                });
            }
        }
        Ok(realms)
    })
    .await
    .map_err(unavailable)?
}

/// Explicit per-account candidate provider. No production selector calls this factory.
/// Keys are dropped with the last provider handle; no portable authority export exists.
pub struct LinuxPrimaryVault {
    pub(super) realms: [Option<Realm>; 3],
    reference: String,
    class: &'static str,
    role: LinuxVaultRole,
}
impl LinuxPrimaryVault {
    /// Open a committed installation for exactly one account and canonical authority reference.
    /// Current record/device authorization remains the existing custody caller's responsibility.
    /// # Errors
    /// Refuses pending initialization, unsafe files, unavailable scoped KEKs or invalid bindings.
    pub async fn open(
        root: PathBuf,
        account: String,
        reference: String,
        config: LinuxVaultConfig,
    ) -> Result<Self, SdkError> {
        crate::custody::valid_id(&account)?;
        codec::Binding {
            realm: 1,
            kind: 1,
            vault_id: [0; 16],
            generation: 1,
            key_id: [0; 16],
            account: &account,
            reference: &reference,
        }
        .validate_name()
        .map_err(|error| codec_error(CodecContext::HandleOpen, error))?;
        let material = init::material(root.clone(), config.clone()).await.map_err(init_error)?;
        let realms = build_realms(root, account, material).await?;
        Ok(Self { realms, reference, class: config.mode().strength_class(), role: config.role() })
    }
    fn realm(&self, i: usize) -> Result<&Realm, SdkError> {
        self.realms[i].as_ref().ok_or(reason(CustodyVaultReason::PrimaryUnavailable))
    }
    fn bound(&self, reference: &str, prefix: &str) -> Result<(), SdkError> {
        if self.role == LinuxVaultRole::DataOnly {
            return Err(reason(CustodyVaultReason::PrimaryUnavailable));
        }
        if reference.strip_prefix(prefix) != Some(self.reference.as_str()) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        Ok(())
    }
    pub(super) fn take_data(mut self) -> Result<Realm, SdkError> {
        self.realms[2].take().ok_or(SdkError::CustodyVaultUnavailable)
    }
}
impl PrimaryVault for LinuxPrimaryVault {
    fn vault_class(&self) -> &'static str {
        self.class
    }
    fn preflight(&self) -> Result<(), SdkError> {
        // Ceremony preflight requires primary capacity, not a branch-only service handle.
        self.realm(0).map(|_| ())
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.bound(reference, "")?;
        self.realm(0)?.insert(reference, 1, &*key.vault_seed())
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        self.bound(reference, "")?;
        let bytes = self.realm(0)?.read(reference, 1)?;
        let mut seed = Secret::<32>::new("p06-primary-seed");
        seed.bytes_mut().copy_from_slice(bytes.bytes());
        Ok(SelfSigningKey::from_vault_seed(&Zeroizing::new(
            *<&[u8; 32]>::try_from(seed.bytes()).map_err(unavailable)?,
        )))
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.bound(reference, "branch:")?;
        self.realm(1)?.insert(reference, 2, seeds.as_slice())
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        self.bound(reference, "branch:")?;
        let bytes = self.realm(1)?.read(reference, 2)?;
        let mut seed = Secret::<64>::new("p06-branch-seed");
        seed.bytes_mut().copy_from_slice(bytes.bytes());
        BranchCredentials::from_vault_seeds(
            principal,
            device,
            &Zeroizing::new(*<&[u8; 64]>::try_from(seed.bytes()).map_err(unavailable)?),
        )
    }
    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        self.bound(reference, "agent-provisioning:")?;
        self.realm(2)?.insert(reference, 3, secret)
    }
    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.bound(reference, "agent-provisioning:")?;
        Ok(Zeroizing::new(self.realm(2)?.read(reference, 3)?.bytes().to_vec()))
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        if reference.starts_with(ramflux_storage::FileVaultSecretSource::OWNER_PREFIX) {
            return Ok(());
        }
        let (i, kind, prefix) = if reference.starts_with("branch:") {
            (1, 2, "branch:")
        } else if reference.starts_with("agent-provisioning:") {
            (2, 3, "agent-provisioning:")
        } else {
            (0, 1, "")
        };
        self.bound(reference, prefix)?;
        self.realm(i)?.delete(reference, kind)
    }
}

/// Test seam: which thread constructed the stores of each root.
#[cfg(test)]
pub(super) mod test_seam {
    use std::{collections::HashMap, path::Path, sync::Mutex, thread::ThreadId};
    static OPEN_THREADS: Mutex<Option<HashMap<std::path::PathBuf, ThreadId>>> = Mutex::new(None);
    pub(super) fn record_open_thread(root: &Path) {
        OPEN_THREADS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(root.to_owned(), std::thread::current().id());
    }
    pub(super) fn open_thread(root: &Path) -> Option<ThreadId> {
        OPEN_THREADS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|map| map.get(root).copied())
    }
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Debug-only helpers behind the `itest-mls-debug` feature: an in-memory scratch store that is
//! never flushed, synthetic pseudonym KeyPackages for bulk adds, tamper builders, the pinned
//! roster and blob-file helpers. None of this is compiled into production builds.

use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use openmls::prelude::{
    Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey, KeyPackage,
    LeafNodeParameters, MlsMessageOut,
};
use zeroize::Zeroizing;

use crate::credential::{CredentialPolicy, GroupKind, MemberIdentity, pseudonym};
use crate::group::policy::RosterPolicy;
use crate::group::{CommitOutput, KeyPackageOutput, Mls, config, unix_now};
use crate::provider::RfMlsProvider;
use crate::signer::LeafSigner;
use crate::storage::kv::{MlsKv, MlsKvError, RowStats, Staged, WriteBatch};
use crate::{
    CREDENTIAL_TYPE_DEVICE, CREDENTIAL_TYPE_PSEUDONYM, KEY_PACKAGE_LIFETIME_SECS,
    MAX_MLS_MESSAGE_BYTES, MLS_SUITE, MlsError,
};

/// Largest `count` of one bulk add.
pub const MAX_BULK_COUNT: usize = crate::ABSOLUTE_LEAF_CAP;
/// Largest members-per-commit of a bulk add.
pub const MAX_BULK_BATCH: usize = 2_000;
/// The suite a `suite` tamper KeyPackage claims.
const TAMPER_SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// In-memory store that reads nothing and refuses to be flushed. Synthetic key material lives in
/// the overlay of a provider built on it and is dropped with that provider.
pub struct ScratchKv;

impl MlsKv for ScratchKv {
    type Tx<'a> = ();

    fn get(&self, _label: &str, _key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, MlsKvError> {
        Ok(None)
    }

    fn row_stats(&self) -> Result<RowStats, MlsKvError> {
        Ok(RowStats::default())
    }

    fn commit_batch<F>(&self, _batch: WriteBatch, _caller: F) -> Result<(), MlsKvError>
    where
        F: for<'a> FnOnce(&mut Self::Tx<'a>) -> Result<(), MlsKvError>,
    {
        Err(MlsKvError::Backend("the scratch store is never flushed".to_owned()))
    }
}

/// Roster of a pseudonym group in debug builds: only pinned keys belong.
pub struct PinnedRoster {
    policy: Arc<CredentialPolicy>,
}

fn identity_key(member: &MemberIdentity) -> Vec<u8> {
    match member {
        MemberIdentity::Device(device) => device.leaf_sig_pk.to_vec(),
        MemberIdentity::Pseudonym { pseudonym_pk } => pseudonym_pk.to_vec(),
        MemberIdentity::PinnedBasic { signature_key } => signature_key.clone(),
    }
}

impl RosterPolicy for PinnedRoster {
    fn accept_member(&self, member: &MemberIdentity) -> Result<(), MlsError> {
        if self.policy.is_pinned(&identity_key(member)) {
            Ok(())
        } else {
            Err(MlsError::PolicyRejected("member key is not pinned".to_owned()))
        }
    }

    fn accept_successor(
        &self,
        _old: &MemberIdentity,
        new: &MemberIdentity,
    ) -> Result<(), MlsError> {
        self.accept_member(new)
    }

    fn accept_welcome(&self, members: &[MemberIdentity]) -> Result<(), MlsError> {
        if members.iter().any(|member| self.policy.is_pinned(&identity_key(member))) {
            Ok(())
        } else {
            Err(MlsError::PolicyRejected("no pinned key is present in the welcome tree".to_owned()))
        }
    }
}

/// How a debug KeyPackage is damaged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPackageTamper {
    /// The credential no longer verifies.
    Credential,
    /// A valid credential of this account sits in a leaf with another signature key.
    Transplant,
    /// The KeyPackage claims suite 0x0003.
    Suite,
}

/// Result of a bulk add.
#[derive(Debug)]
pub struct BulkOutput {
    /// Epoch after the last commit.
    pub epoch: u64,
    /// Leaves after the last commit.
    pub leaves: usize,
    /// Commits made.
    pub commits: usize,
    /// Largest commit in bytes.
    pub max_commit_bytes: usize,
    /// Largest Welcome in bytes (the Welcomes are discarded).
    pub max_welcome_bytes: usize,
    /// Wall time in milliseconds.
    pub total_ms: u128,
}

fn flip_last_byte(credential: &Credential) -> Credential {
    let mut content = credential.serialized_content().to_vec();
    if let Some(last) = content.last_mut() {
        *last ^= 0x01;
    }
    Credential::new(credential.credential_type(), content)
}

/// Read a blob file: it must be a regular file no larger than `max` bytes.
///
/// # Errors
/// Not a regular file, larger than `max`, or an I/O failure.
pub fn read_blob(path: &Path, max: usize) -> Result<Vec<u8>, MlsError> {
    let file =
        std::fs::File::open(path).map_err(|error| MlsError::Mls(format!("open blob: {error}")))?;
    let metadata = file.metadata().map_err(|error| MlsError::Mls(format!("stat blob: {error}")))?;
    if !metadata.is_file() {
        return Err(MlsError::PolicyRejected("blob path is not a regular file".to_owned()));
    }
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| MlsError::Mls(format!("read blob: {error}")))?;
    if bytes.len() > max {
        return Err(MlsError::TooLarge(format!("blob larger than {max} bytes")));
    }
    Ok(bytes)
}

/// Read a blob file with the MLS message bound.
///
/// # Errors
/// See [`read_blob`].
pub fn read_message_blob(path: &Path) -> Result<Vec<u8>, MlsError> {
    read_blob(path, MAX_MLS_MESSAGE_BYTES)
}

/// Write a blob file: the file must not exist (`create_new`) and gets mode 0600.
///
/// # Errors
/// The file exists or an I/O failure.
pub fn write_blob(path: &Path, bytes: &[u8]) -> Result<(), MlsError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file =
        options.open(path).map_err(|error| MlsError::Mls(format!("create blob: {error}")))?;
    file.write_all(bytes).map_err(|error| MlsError::Mls(format!("write blob: {error}")))
}

impl<K: MlsKv> Mls<K> {
    /// Use the pinned roster for pseudonym groups (debug builds).
    #[must_use]
    pub fn with_pinned_roster(mut self) -> Self {
        self.roster = Box::new(PinnedRoster { policy: Arc::clone(&self.creds) });
        self
    }

    /// Pin one signature key (interop peer and group roster).
    ///
    /// # Errors
    /// The pin list lock is poisoned.
    pub fn trust_pinned(&self, signature_key: &[u8]) -> Result<(), MlsError> {
        self.creds.pin(signature_key)
    }

    /// A KeyPackage, optionally damaged on purpose.
    ///
    /// # Errors
    /// As [`Mls::key_package`].
    pub fn debug_key_package(
        &self,
        kind: GroupKind,
        tamper: Option<KeyPackageTamper>,
    ) -> Result<Staged<'_, K, KeyPackageOutput>, MlsError> {
        let op = self.begin()?;
        let now = unix_now()?;
        op.provider.mls_storage().own_kp_purge_expired(now)?;
        let leaf_signer = LeafSigner::generate(self.crypto.crypto())?;
        let credential_signer = if tamper == Some(KeyPackageTamper::Transplant) {
            LeafSigner::generate(self.crypto.crypto())?
        } else {
            LeafSigner::from_secret(leaf_signer.secret())?
        };
        let mut credential_with_key = self.credential_for(&op, kind, &credential_signer)?;
        match tamper {
            Some(KeyPackageTamper::Credential) => {
                credential_with_key.credential = flip_last_byte(&credential_with_key.credential);
            }
            Some(KeyPackageTamper::Transplant) => {
                credential_with_key.signature_key = leaf_signer.public().to_vec().into();
            }
            Some(KeyPackageTamper::Suite) | None => {}
        }
        let credential_bytes = credential_with_key.credential.serialized_content().len();
        self.store_signer(&op, &leaf_signer)?;
        let (ciphersuite, capabilities) = if tamper == Some(KeyPackageTamper::Suite) {
            (
                TAMPER_SUITE,
                Capabilities::builder()
                    .ciphersuites(vec![TAMPER_SUITE])
                    .credentials(vec![
                        CredentialType::Other(CREDENTIAL_TYPE_DEVICE),
                        CredentialType::Other(CREDENTIAL_TYPE_PSEUDONYM),
                    ])
                    .build(),
            )
        } else {
            (MLS_SUITE, config::capabilities())
        };
        let bundle = KeyPackage::builder()
            .key_package_lifetime(config::key_package_lifetime())
            .leaf_node_capabilities(capabilities)
            .build(ciphersuite, &op.provider, &leaf_signer, credential_with_key)
            .map_err(MlsError::mls)?;
        let hash_ref =
            bundle.key_package().hash_ref(self.crypto.crypto()).map_err(MlsError::mls)?;
        op.provider
            .mls_storage()
            .own_kp_remember(&hash_ref, now.saturating_add(KEY_PACKAGE_LIFETIME_SECS))?;
        let bytes = MlsMessageOut::from(bundle).to_bytes().map_err(MlsError::mls)?;
        op.finish(KeyPackageOutput { bytes, leaf_sig_pk: *leaf_signer.public(), credential_bytes })
    }

    /// An update commit whose new leaf carries a damaged credential. The commit is returned but
    /// never merged and nothing is persisted, so the own state stays unchanged.
    ///
    /// # Errors
    /// `not_found` or a provider failure.
    pub fn tampered_update(&self, group_id: &[u8]) -> Result<CommitOutput, MlsError> {
        let op = self.begin()?;
        let mut loaded = self.load(&op, group_id)?;
        let signer = self.load_signer(&op, &loaded.group)?;
        let own = loaded
            .group
            .own_leaf_node()
            .ok_or_else(|| MlsError::internal("own leaf is missing"))?;
        let damaged = CredentialWithKey {
            credential: flip_last_byte(own.credential()),
            signature_key: own.signature_key().clone(),
        };
        let parameters = LeafNodeParameters::builder().with_credential_with_key(damaged).build();
        let bundle =
            loaded.group.self_update(&op.provider, &signer, parameters).map_err(MlsError::mls)?;
        let (commit, _welcome, _group_info) = bundle.into_contents();
        Ok(CommitOutput {
            epoch: loaded.group.epoch().as_u64(),
            message: commit.to_bytes().map_err(MlsError::mls)?,
        })
    }

    fn synthetic_key_packages(&self, count: usize) -> Result<Vec<KeyPackage>, MlsError> {
        let scratch = ScratchKv;
        let provider = RfMlsProvider::new(&self.crypto, &scratch);
        let mut key_packages = Vec::new();
        for _ in 0..count {
            let signer = LeafSigner::generate(self.crypto.crypto())?;
            self.creds.pin(signer.public())?;
            let credential_with_key = CredentialWithKey {
                credential: pseudonym::issue(signer.public()),
                signature_key: signer.public().to_vec().into(),
            };
            let bundle = KeyPackage::builder()
                .key_package_lifetime(config::key_package_lifetime())
                .leaf_node_capabilities(config::capabilities())
                .build(MLS_SUITE, &provider, &signer, credential_with_key)
                .map_err(MlsError::mls)?;
            key_packages.push(bundle.into_key_package());
        }
        Ok(key_packages)
    }

    /// Add `count` synthetic pseudonym members, `batch` per commit (group kind only). Their keys
    /// are pinned and dropped; the Welcomes are discarded.
    ///
    /// # Errors
    /// Bounds, a non-group kind, gate rejections or a provider failure.
    pub fn bulk_add(
        &self,
        group_id: &[u8],
        count: usize,
        batch: usize,
    ) -> Result<Staged<'_, K, BulkOutput>, MlsError> {
        if count == 0 || count > MAX_BULK_COUNT || batch == 0 || batch > MAX_BULK_BATCH {
            return Err(MlsError::PolicyRejected(
                "bulk add count or batch is out of bounds".to_owned(),
            ));
        }
        let op = self.begin()?;
        let mut loaded = self.load(&op, group_id)?;
        if loaded.kind != GroupKind::Group {
            return Err(MlsError::PolicyRejected("bulk add is for the group kind only".to_owned()));
        }
        let signer = self.load_signer(&op, &loaded.group)?;
        let started = Instant::now();
        let (mut remaining, mut commits, mut max_commit_bytes, mut max_welcome_bytes) =
            (count, 0_usize, 0_usize, 0_usize);
        while remaining > 0 {
            let step = remaining.min(batch);
            let key_packages = self.synthetic_key_packages(step)?;
            let (commit, welcome) = op.gate(GroupKind::Group).add(
                &mut loaded.group,
                &signer,
                &key_packages,
                loaded.leaf_cap,
            )?;
            max_commit_bytes =
                max_commit_bytes.max(commit.to_bytes().map_err(MlsError::mls)?.len());
            max_welcome_bytes =
                max_welcome_bytes.max(welcome.to_bytes().map_err(MlsError::mls)?.len());
            commits += 1;
            remaining -= step;
        }
        let output = BulkOutput {
            epoch: loaded.group.epoch().as_u64(),
            leaves: crate::group::gate::leaf_count(&loaded.group),
            commits,
            max_commit_bytes,
            max_welcome_bytes,
            total_ms: started.elapsed().as_millis(),
        };
        op.finish(output)
    }
}

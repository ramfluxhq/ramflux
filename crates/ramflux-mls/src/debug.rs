// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Debug-only helpers behind the `itest-mls-debug` feature: an in-memory scratch store that is
//! never flushed, synthetic pseudonym `KeyPackages` for bulk adds (optionally kept, so the
//! synthetic members can act later), synthetic Update commits (tree healing), tamper builders,
//! the pinned roster, blob-file helpers and the process memory reading. None of this is compiled
//! into production builds.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use openmls::prelude::{
    Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey, KeyPackage,
    LeafNodeLifetimePolicy, LeafNodeParameters, MlsGroup, MlsMessageBodyIn, MlsMessageOut,
    ProcessedMessageContent, ProtocolMessage, StagedWelcome,
};
use openmls_traits::OpenMlsProvider as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::credential::{CredentialPolicy, GroupKind, MemberIdentity, pseudonym};
use crate::group::context::{CommitCtx, CommitMeta, WelcomeCtx};
use crate::group::policy::RosterPolicy;
use crate::group::{CommitOutput, KeyPackageOutput, Mls, config, parse_message, unix_now};
use crate::provider::RfMlsProvider;
use crate::signer::LeafSigner;
use crate::storage::kv::{MlsKv, MlsKvError, RowStats, RowStore, Staged, WriteBatch, WriteOp};
use crate::{
    CREDENTIAL_TYPE_DEVICE, CREDENTIAL_TYPE_PSEUDONYM, KEY_PACKAGE_LIFETIME_SECS, LEAF_CAP,
    MAX_MLS_MESSAGE_BYTES, MLS_SUITE, MlsError,
};

/// Largest `count` of one bulk add.
pub const MAX_BULK_COUNT: usize = LEAF_CAP;
/// Largest members-per-commit of a bulk add.
pub const MAX_BULK_BATCH: usize = 2_000;
/// Largest `count` of one synthetic Update commit.
pub const MAX_SYNTHETIC_COMMIT: usize = 2_000;
/// Label of the kept synthetic members and their replay chain (debug builds only). Values are
/// cut into chunks of [`BLOB_CHUNK`] bytes so the account row statistics stay those of the real
/// MLS state.
const LABEL_DEBUG_SYN: &str = "rf/debug_syn";
/// Largest value of a chunked debug row.
const BLOB_CHUNK: usize = 16 * 1024;
/// The suite a `suite` tamper `KeyPackage` claims.
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
        F: for<'a> FnOnce(&mut Self::Tx<'a>) -> Result<(), MlsKvError> + Send + 'static,
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
    fn accept_member(&self, _ctx: &CommitCtx<'_>, member: &MemberIdentity) -> Result<(), MlsError> {
        if self.policy.is_pinned(&identity_key(member)) {
            Ok(())
        } else {
            Err(MlsError::PolicyRejected("member key is not pinned".to_owned()))
        }
    }

    fn accept_successor(
        &self,
        ctx: &CommitCtx<'_>,
        _old: &MemberIdentity,
        new: &MemberIdentity,
    ) -> Result<(), MlsError> {
        self.accept_member(ctx, new)
    }

    fn accept_welcome(
        &self,
        _ctx: &WelcomeCtx<'_>,
        members: &[MemberIdentity],
    ) -> Result<(), MlsError> {
        if members.iter().any(|member| self.policy.is_pinned(&identity_key(member))) {
            Ok(())
        } else {
            Err(MlsError::PolicyRejected("no pinned key is present in the welcome tree".to_owned()))
        }
    }
}

/// How a debug `KeyPackage` is damaged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPackageTamper {
    /// The credential no longer verifies.
    Credential,
    /// A valid credential of this account sits in a leaf with another signature key.
    Transplant,
    /// The `KeyPackage` claims suite 0x0003.
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

/// Result of a synthetic Update commit.
#[derive(Debug)]
pub struct SyntheticOutput {
    /// Epoch after the commit.
    pub epoch: u64,
    /// Update proposals the commit carries (one per synthetic member).
    pub proposals: usize,
    /// Size of the commit in bytes.
    pub commit_bytes: usize,
    /// Wall time in milliseconds.
    pub total_ms: u128,
}

/// In-memory store preloaded with rows, never flushed: the storage of one replayed synthetic
/// member.
struct SeededKv {
    rows: HashMap<(String, Vec<u8>), Zeroizing<Vec<u8>>>,
}

impl MlsKv for SeededKv {
    type Tx<'a> = ();

    fn get(&self, label: &str, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, MlsKvError> {
        Ok(self.rows.get(&(label.to_owned(), key.to_vec())).cloned())
    }

    fn row_stats(&self) -> Result<RowStats, MlsKvError> {
        Ok(RowStats::default())
    }

    fn commit_batch<F>(&self, _batch: WriteBatch, _caller: F) -> Result<(), MlsKvError>
    where
        F: for<'a> FnOnce(&mut Self::Tx<'a>) -> Result<(), MlsKvError> + Send + 'static,
    {
        Err(MlsKvError::Backend("the seeded store is never flushed".to_owned()))
    }
}

/// Replay chain of the kept synthetic members of one group.
#[derive(Debug, Default, Serialize, Deserialize)]
struct SynMeta {
    /// Kept members, indexed `0..members`.
    members: u32,
    /// Next member that has not yet sent its Update.
    cursor: u32,
    /// Welcome batches kept.
    batches: u32,
    /// Epoch of the group when the chain was last extended; the chain is valid only while the
    /// group sits there.
    tip_epoch: u64,
}

/// One kept synthetic member: its leaf secret and the private rows of its `KeyPackage`.
#[derive(Serialize, Deserialize)]
struct SynMember {
    batch: u32,
    secret: Vec<u8>,
    rows: Vec<(String, Vec<u8>, Vec<u8>)>,
}

fn syn_key(group_id: &[u8], tag: u8, a: u64, b: u32) -> Vec<u8> {
    let mut key = group_id.to_vec();
    key.push(tag);
    key.extend_from_slice(&a.to_be_bytes());
    key.extend_from_slice(&b.to_be_bytes());
    key
}

fn syn_meta<K: MlsKv>(
    rows: &RowStore<'_, K>,
    group_id: &[u8],
) -> Result<Option<SynMeta>, MlsError> {
    Ok(rows.read(LABEL_DEBUG_SYN, &syn_key(group_id, b'm', 0, 0))?)
}

fn put_syn_blob<K: MlsKv>(
    rows: &RowStore<'_, K>,
    group_id: &[u8],
    tag: u8,
    id: u64,
    bytes: &[u8],
) -> Result<(), MlsError> {
    let chunks = bytes.chunks(BLOB_CHUNK).collect::<Vec<_>>();
    let count = u32::try_from(chunks.len()).map_err(|_| MlsError::internal("blob too long"))?;
    rows.write(LABEL_DEBUG_SYN, syn_key(group_id, tag, id, u32::MAX), &count)?;
    for (index, chunk) in (0_u32..).zip(chunks) {
        rows.put(
            LABEL_DEBUG_SYN,
            syn_key(group_id, tag, id, index),
            Zeroizing::new(chunk.to_vec()),
        )?;
    }
    Ok(())
}

fn get_syn_blob<K: MlsKv>(
    rows: &RowStore<'_, K>,
    group_id: &[u8],
    tag: u8,
    id: u64,
) -> Result<Vec<u8>, MlsError> {
    find_syn_blob(rows, group_id, tag, id)?
        .ok_or_else(|| MlsError::NotFound("kept synthetic chain row".to_owned()))
}

fn find_syn_blob<K: MlsKv>(
    rows: &RowStore<'_, K>,
    group_id: &[u8],
    tag: u8,
    id: u64,
) -> Result<Option<Vec<u8>>, MlsError> {
    let Some(count): Option<u32> =
        rows.read(LABEL_DEBUG_SYN, &syn_key(group_id, tag, id, u32::MAX))?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    for index in 0..count {
        let chunk = rows
            .get(LABEL_DEBUG_SYN, &syn_key(group_id, tag, id, index))?
            .ok_or_else(|| MlsError::NotFound("kept synthetic chain chunk".to_owned()))?;
        bytes.extend_from_slice(&chunk);
        if bytes.len() > crate::MAX_STORED_VALUE_BYTES {
            return Err(MlsError::TooLarge("kept synthetic chain row".to_owned()));
        }
    }
    Ok(Some(bytes))
}

/// Resident set size of this process in kB (`VmRSS`), when the platform exposes it.
#[must_use]
pub fn rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
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

    /// A `KeyPackage`, optionally damaged on purpose.
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
        let mut credential_with_key = self.credential_for(kind, &credential_signer)?;
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
        Self::store_signer(&op, &leaf_signer)?;
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
        op.provider.mls_storage().own_kp_remember(
            &hash_ref,
            now.saturating_add(KEY_PACKAGE_LIFETIME_SECS),
            leaf_signer.public(),
        )?;
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
        let mut loaded = Self::load(&op, group_id)?;
        let signer = Self::load_signer(&op, &loaded.group)?;
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

    fn synthetic_key_packages(
        &self,
        count: usize,
        keep: bool,
    ) -> Result<Vec<(KeyPackage, Option<SynMember>)>, MlsError> {
        let shared = ScratchKv;
        let shared_provider = RfMlsProvider::new(&self.crypto, &shared);
        let mut key_packages = Vec::new();
        for _ in 0..count {
            let signer = LeafSigner::generate(self.crypto.crypto())?;
            self.creds.pin(signer.public())?;
            let credential_with_key = CredentialWithKey {
                credential: pseudonym::issue(signer.public()),
                signature_key: signer.public().to_vec().into(),
            };
            // A kept member gets a provider of its own so its private rows can be taken.
            let own_scratch = ScratchKv;
            let own_provider = RfMlsProvider::new(&self.crypto, &own_scratch);
            let provider = if keep { &own_provider } else { &shared_provider };
            let bundle = KeyPackage::builder()
                .key_package_lifetime(config::key_package_lifetime())
                .leaf_node_capabilities(config::capabilities())
                .build(MLS_SUITE, provider, &signer, credential_with_key)
                .map_err(MlsError::mls)?;
            let kept = if keep {
                let batch = provider.mls_storage().rows().take_batch()?;
                let rows = batch
                    .ops
                    .into_iter()
                    .filter_map(|op| match op {
                        WriteOp::Put { label, key, value } => Some((label, key, value.to_vec())),
                        WriteOp::Delete { .. } => None,
                    })
                    .collect();
                Some(SynMember { batch: 0, secret: signer.secret().to_vec(), rows })
            } else {
                None
            };
            key_packages.push((bundle.into_key_package(), kept));
        }
        Ok(key_packages)
    }

    /// Add `count` synthetic pseudonym members, `batch` per commit (group kind only). Their keys
    /// are pinned and dropped; the Welcomes are discarded. See [`Self::bulk_add_with`] to keep
    /// them.
    ///
    /// # Errors
    /// Bounds, a non-group kind, gate rejections or a provider failure.
    pub fn bulk_add(
        &self,
        group_id: &[u8],
        count: usize,
        batch: usize,
    ) -> Result<Staged<'_, K, BulkOutput>, MlsError> {
        self.bulk_add_with(group_id, count, batch, false)
    }

    /// [`Self::bulk_add`] with `keep_keys`: the synthetic members' leaf secrets, `KeyPackage`
    /// private rows, Welcomes and the commits that follow are written to the debug rows of the
    /// account store (not held in process memory), so [`Self::synthetic_commit`] can later act as
    /// those members. The chain is valid while the group sits at the epoch the last bulk add or
    /// synthetic commit left it; a bulk add at any other epoch starts a new chain.
    ///
    /// # Errors
    /// As [`Self::bulk_add`], plus storage failures.
    pub fn bulk_add_with(
        &self,
        group_id: &[u8],
        count: usize,
        batch: usize,
        keep_keys: bool,
    ) -> Result<Staged<'_, K, BulkOutput>, MlsError> {
        if count == 0 || count > MAX_BULK_COUNT || batch == 0 || batch > MAX_BULK_BATCH {
            return Err(MlsError::PolicyRejected(
                "bulk add count or batch is out of bounds".to_owned(),
            ));
        }
        let op = self.begin()?;
        let mut loaded = Self::load(&op, group_id)?;
        if loaded.kind != GroupKind::Group {
            return Err(MlsError::PolicyRejected("bulk add is for the group kind only".to_owned()));
        }
        let signer = Self::load_signer(&op, &loaded.group)?;
        let rows = op.provider.mls_storage().rows();
        let mut meta = if keep_keys {
            let epoch = loaded.group.epoch().as_u64();
            Some(match syn_meta(rows, group_id)? {
                Some(meta) if meta.tip_epoch == epoch => meta,
                _ => SynMeta { tip_epoch: epoch, ..SynMeta::default() },
            })
        } else {
            None
        };
        let started = Instant::now();
        let (mut remaining, mut commits, mut max_commit_bytes, mut max_welcome_bytes) =
            (count, 0_usize, 0_usize, 0_usize);
        while remaining > 0 {
            let step = remaining.min(batch);
            let epoch_before = loaded.group.epoch().as_u64();
            let (key_packages, kept): (Vec<_>, Vec<_>) =
                self.synthetic_key_packages(step, keep_keys)?.into_iter().unzip();
            let (commit, welcome) = op.gate(GroupKind::Group).add(
                &mut loaded.group,
                &signer,
                &key_packages,
                loaded.leaf_cap,
                CommitMeta::default(),
            )?;
            let commit_bytes = commit.to_bytes().map_err(MlsError::mls)?;
            let welcome_bytes = welcome.to_bytes().map_err(MlsError::mls)?;
            max_commit_bytes = max_commit_bytes.max(commit_bytes.len());
            max_welcome_bytes = max_welcome_bytes.max(welcome_bytes.len());
            commits += 1;
            remaining -= step;
            if let Some(meta) = meta.as_mut() {
                put_syn_blob(rows, group_id, b'c', epoch_before, &commit_bytes)?;
                put_syn_blob(rows, group_id, b'w', u64::from(meta.batches), &welcome_bytes)?;
                for member in kept.into_iter().flatten() {
                    let member = SynMember { batch: meta.batches, ..member };
                    rows.write(
                        LABEL_DEBUG_SYN,
                        syn_key(group_id, b'k', u64::from(meta.members), 0),
                        &member,
                    )?;
                    meta.members += 1;
                }
                meta.batches += 1;
                meta.tip_epoch = loaded.group.epoch().as_u64();
            }
        }
        if let Some(meta) = &meta {
            rows.write(LABEL_DEBUG_SYN, syn_key(group_id, b'm', 0, 0), meta)?;
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

    /// Rebuild kept synthetic member `index` at the current epoch (join from its Welcome, replay
    /// the kept commits) and let it propose an Update of its own leaf. Returns the proposal.
    fn synthetic_update_proposal(
        &self,
        rows: &RowStore<'_, K>,
        group_id: &[u8],
        meta: &SynMeta,
        index: u32,
    ) -> Result<Vec<u8>, MlsError> {
        let member: SynMember = rows
            .read(LABEL_DEBUG_SYN, &syn_key(group_id, b'k', u64::from(index), 0))?
            .ok_or_else(|| MlsError::NotFound("kept synthetic member".to_owned()))?;
        let signer = LeafSigner::from_secret(&member.secret)?;
        let seeded = SeededKv {
            rows: member
                .rows
                .into_iter()
                .map(|(label, key, value)| ((label, key), Zeroizing::new(value)))
                .collect(),
        };
        let provider = RfMlsProvider::new(&self.crypto, &seeded);
        let welcome_bytes = get_syn_blob(rows, group_id, b'w', u64::from(member.batch))?;
        let MlsMessageBodyIn::Welcome(welcome) =
            parse_message(&welcome_bytes, MAX_MLS_MESSAGE_BYTES)?.extract()
        else {
            return Err(MlsError::internal("kept synthetic Welcome is not a Welcome"));
        };
        let mut group = StagedWelcome::build_from_welcome(
            &provider,
            &config::join_config(GroupKind::Group),
            welcome,
        )
        .map_err(MlsError::mls)?
        .skip_lifetime_validation()
        .build()
        .map_err(MlsError::mls)?
        .into_group(&provider)
        .map_err(MlsError::mls)?;
        loop {
            let epoch = group.epoch().as_u64();
            if epoch >= meta.tip_epoch {
                break;
            }
            // A synthetic heal commit carries its Update proposals by reference.
            if let Some(packed) = find_syn_blob(rows, group_id, b'p', epoch)? {
                let proposals: Vec<Vec<u8>> = crate::storage::kv::decode(&packed)?;
                for proposal in proposals {
                    let MlsMessageBodyIn::PrivateMessage(private) =
                        parse_message(&proposal, MAX_MLS_MESSAGE_BYTES)?.extract()
                    else {
                        return Err(MlsError::internal("kept proposal is not a private message"));
                    };
                    let processed = group
                        .process_message_with_lifetime_policy(
                            &provider,
                            ProtocolMessage::from(private),
                            LeafNodeLifetimePolicy::Skip,
                        )
                        .map_err(MlsError::mls)?;
                    let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content()
                    else {
                        return Err(MlsError::internal("kept proposal is not a proposal"));
                    };
                    group
                        .store_pending_proposal(provider.storage(), *queued)
                        .map_err(MlsError::mls)?;
                }
            }
            let commit = get_syn_blob(rows, group_id, b'c', epoch)?;
            let MlsMessageBodyIn::PrivateMessage(private) =
                parse_message(&commit, MAX_MLS_MESSAGE_BYTES)?.extract()
            else {
                return Err(MlsError::internal("kept synthetic commit is not a private message"));
            };
            let processed = group
                .process_message_with_lifetime_policy(
                    &provider,
                    ProtocolMessage::from(private),
                    LeafNodeLifetimePolicy::Skip,
                )
                .map_err(MlsError::mls)?;
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                return Err(MlsError::internal("kept synthetic commit is not a commit"));
            };
            group.merge_staged_commit(&provider, *staged).map_err(MlsError::mls)?;
            if group.epoch().as_u64() <= epoch {
                return Err(MlsError::internal("kept synthetic member did not advance"));
            }
        }
        Self::propose_update(&mut group, &provider, &signer)
    }

    fn propose_update(
        group: &mut MlsGroup,
        provider: &RfMlsProvider<'_, SeededKv>,
        signer: &LeafSigner,
    ) -> Result<Vec<u8>, MlsError> {
        let (proposal, _reference) = group
            .propose_self_update(provider, signer, LeafNodeParameters::default())
            .map_err(MlsError::mls)?;
        proposal.to_bytes().map_err(MlsError::mls)
    }

    /// `count` kept synthetic members (from [`Self::bulk_add_with`] with `keep_keys`, each acts
    /// once) propose an Update of their own leaf, and the own device commits them in one commit
    /// (tree healing). The members are replayed one after another from their kept Welcomes and
    /// commits, so a call costs about `count` joins.
    ///
    /// # Errors
    /// Bounds, a non-group kind, no kept members, a stale chain (the group left the epoch the
    /// chain ended at), too few unused members, gate rejections or a provider failure.
    pub fn synthetic_commit(
        &self,
        group_id: &[u8],
        count: usize,
    ) -> Result<Staged<'_, K, SyntheticOutput>, MlsError> {
        if count == 0 || count > MAX_SYNTHETIC_COMMIT {
            return Err(MlsError::PolicyRejected(
                "synthetic commit count is out of bounds".to_owned(),
            ));
        }
        let wanted = u32::try_from(count)
            .map_err(|_| MlsError::PolicyRejected("synthetic commit count".to_owned()))?;
        let op = self.begin()?;
        let mut loaded = Self::load(&op, group_id)?;
        if loaded.kind != GroupKind::Group {
            return Err(MlsError::PolicyRejected(
                "synthetic commit is for the group kind only".to_owned(),
            ));
        }
        let signer = Self::load_signer(&op, &loaded.group)?;
        let rows = op.provider.mls_storage().rows();
        let mut meta = syn_meta(rows, group_id)?
            .ok_or_else(|| MlsError::NotFound("kept synthetic members".to_owned()))?;
        let epoch_before = loaded.group.epoch().as_u64();
        if meta.tip_epoch != epoch_before {
            return Err(MlsError::PolicyRejected(
                "the kept synthetic members are stale: the group moved since the last bulk add"
                    .to_owned(),
            ));
        }
        let end = meta.cursor.checked_add(wanted).filter(|end| *end <= meta.members).ok_or_else(
            || MlsError::PolicyRejected("too few unused synthetic members".to_owned()),
        )?;
        let started = Instant::now();
        let gate = op.gate(GroupKind::Group);
        let mut proposals = Vec::new();
        for index in meta.cursor..end {
            let member: SynMember = rows
                .read(LABEL_DEBUG_SYN, &syn_key(group_id, b'k', u64::from(index), 0))?
                .ok_or_else(|| MlsError::NotFound("kept synthetic member".to_owned()))?;
            self.creds.pin(LeafSigner::from_secret(&member.secret)?.public())?;
            let proposal = self.synthetic_update_proposal(rows, group_id, &meta, index)?;
            let MlsMessageBodyIn::PrivateMessage(private) =
                parse_message(&proposal, MAX_MLS_MESSAGE_BYTES)?.extract()
            else {
                return Err(MlsError::internal("synthetic proposal is not a private message"));
            };
            gate.process(&mut loaded.group, ProtocolMessage::from(private), loaded.leaf_cap)?;
            proposals.push(proposal);
        }
        let commit = gate.commit_pending(&mut loaded.group, &signer, CommitMeta::default())?;
        let commit_bytes = commit.to_bytes().map_err(MlsError::mls)?;
        put_syn_blob(rows, group_id, b'c', epoch_before, &commit_bytes)?;
        put_syn_blob(rows, group_id, b'p', epoch_before, &crate::storage::kv::encode(&proposals)?)?;
        meta.cursor = end;
        meta.tip_epoch = loaded.group.epoch().as_u64();
        rows.write(LABEL_DEBUG_SYN, syn_key(group_id, b'm', 0, 0), &meta)?;
        let output = SyntheticOutput {
            epoch: meta.tip_epoch,
            proposals: count,
            commit_bytes: commit_bytes.len(),
            total_ms: started.elapsed().as_millis(),
        };
        op.finish(output)
    }
}

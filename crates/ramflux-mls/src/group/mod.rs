// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The MLS facade: create, KeyPackage, add, join, send, receive, update, leave, commit pending,
//! remove, export and status.
//!
//! Every state-changing operation loads the group, operates, and returns a [`Staged`] output. The
//! output is released only by `Staged::commit`, which writes the MLS rows and the caller's rows in
//! one transaction. The [`Staged`] also holds the account's operation lock, so no group stays in
//! memory between calls and operations never interleave.

pub mod config;
pub(crate) mod gate;
pub mod policy;

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use openmls::prelude::{
    CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, LeafNodeIndex, MlsGroup,
    MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolMessage, ProtocolVersion,
};
use openmls_traits::OpenMlsProvider as _;
use openmls_traits::random::OpenMlsRand as _;
use tls_codec::Deserialize as _;
use zeroize::Zeroizing;

use self::gate::{Gate, JoinedGroup};
use self::policy::{CommitPolicy, PermissiveCommitPolicy, RosterPolicy};
use crate::credential::{
    self, CredentialPolicy, DeviceIdentity, GroupKind, MemberIdentity, device, device_sets,
    pseudonym,
};
use crate::provider::{CryptoHandle, RfMlsProvider};
use crate::signer::LeafSigner;
use crate::storage::kv::{MlsKv, RowStats, Staged};
use crate::{
    ABSOLUTE_LEAF_CAP, GROUP_ID_BYTES, KEY_PACKAGE_LIFETIME_SECS, LEAF_CAP_TIER_1000,
    LEAF_CAP_TIER_5000, MAX_KEY_PACKAGE_BYTES, MAX_MLS_MESSAGE_BYTES, MLS_SUITE, MlsError,
    RF_LABEL_GROUP_KIND, RF_LABEL_GROUP_TIER, RF_LABEL_LEAF_SIG,
};

/// Number of members `status` lists before truncating.
pub const STATUS_MEMBER_LIMIT: usize = 50;

/// Capacity tier of a `group`, chosen at creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Up to 1 000 members (leaf cap 3 000).
    Members1000,
    /// Up to 5 000 members (leaf cap 15 000).
    Members5000,
}

impl Tier {
    /// Parse the member count (`1000` or `5000`).
    #[must_use]
    pub fn from_members(members: u32) -> Option<Self> {
        match members {
            1000 => Some(Self::Members1000),
            5000 => Some(Self::Members5000),
            _ => None,
        }
    }

    /// Member count of the tier.
    #[must_use]
    pub fn members(self) -> u32 {
        match self {
            Self::Members1000 => 1000,
            Self::Members5000 => 5000,
        }
    }

    /// Leaf cap of the tier.
    #[must_use]
    pub fn leaf_cap(self) -> usize {
        match self {
            Self::Members1000 => LEAF_CAP_TIER_1000,
            Self::Members5000 => LEAF_CAP_TIER_5000,
        }
    }
}

/// A fresh KeyPackage.
#[derive(Debug)]
pub struct KeyPackageOutput {
    /// TLS-encoded `MLSMessage` carrying the KeyPackage.
    pub bytes: Vec<u8>,
    /// The leaf signature public key.
    pub leaf_sig_pk: [u8; 32],
    /// Size of the credential in bytes.
    pub credential_bytes: usize,
}

/// A created group.
#[derive(Debug)]
pub struct CreateOutput {
    /// Group id.
    pub group_id: Vec<u8>,
    /// Epoch (0).
    pub epoch: u64,
    /// Leaf cap of the group for own adds.
    pub leaf_cap: usize,
}

/// Result of adding members.
#[derive(Debug)]
pub struct AddOutput {
    /// New epoch.
    pub epoch: u64,
    /// TLS-encoded commit.
    pub commit: Vec<u8>,
    /// TLS-encoded Welcome.
    pub welcome: Vec<u8>,
}

/// One member in a status or join listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberSummary {
    /// Leaf index.
    pub leaf: u32,
    /// Root commitment (device credentials).
    pub root_commitment: Option<String>,
    /// Device id (device credentials).
    pub device_id: Option<String>,
    /// True when the highest accepted device set lists the device as revoked.
    pub revoked: bool,
}

/// A joined group.
#[derive(Debug)]
pub struct JoinOutput {
    /// Group id.
    pub group_id: Vec<u8>,
    /// Kind derived from the Welcome's GroupContext.
    pub kind: GroupKind,
    /// Epoch.
    pub epoch: u64,
    /// Number of leaves.
    pub leaves: usize,
    /// Members, truncated to [`STATUS_MEMBER_LIMIT`].
    pub members: Vec<MemberSummary>,
}

/// An application message to send.
#[derive(Debug)]
pub struct SendOutput {
    /// TLS-encoded private message.
    pub message: Vec<u8>,
    /// Epoch it was sent in.
    pub epoch: u64,
}

/// A handshake message produced by an own operation.
#[derive(Debug)]
pub struct CommitOutput {
    /// New epoch (the commit is merged at once; there is no orderer in MLS-0).
    pub epoch: u64,
    /// TLS-encoded message.
    pub message: Vec<u8>,
}

/// Group status.
#[derive(Debug)]
pub struct StatusOutput {
    /// Epoch.
    pub epoch: u64,
    /// Kind.
    pub kind: GroupKind,
    /// Tier (groups created here).
    pub tier: Option<Tier>,
    /// Leaf cap applied to own adds.
    pub leaf_cap: usize,
    /// Own leaf index.
    pub own_leaf: u32,
    /// Number of leaves.
    pub leaves: usize,
    /// Members, truncated to [`STATUS_MEMBER_LIMIT`].
    pub members: Vec<MemberSummary>,
    /// Row statistics of the whole account store.
    pub rows: RowStats,
}

/// A processed incoming message.
#[derive(Debug)]
pub enum ReceivedMessage {
    /// An application message.
    Application {
        /// Plaintext.
        plaintext: Zeroizing<Vec<u8>>,
        /// Authenticated data.
        aad: Vec<u8>,
        /// Sender leaf index.
        sender_leaf: u32,
        /// Epoch of the message.
        epoch: u64,
    },
    /// A commit that was merged.
    Commit {
        /// New epoch.
        epoch: u64,
        /// True when the commit removed this member.
        removed: bool,
    },
    /// A proposal that was stored.
    Proposal {
        /// Sender leaf index.
        sender_leaf: u32,
        /// Epoch of the message.
        epoch: u64,
    },
    /// An echo of an own message.
    Own {
        /// Epoch of the message.
        epoch: u64,
    },
}

pub(crate) struct Loaded {
    pub(crate) group: MlsGroup,
    pub(crate) kind: GroupKind,
    pub(crate) leaf_cap: usize,
}

/// The MLS runtime of one account.
pub struct Mls<K: MlsKv> {
    pub(crate) kv: K,
    pub(crate) crypto: CryptoHandle,
    identity: Option<DeviceIdentity>,
    pub(crate) creds: Arc<CredentialPolicy>,
    pub(crate) commit_policy: Box<dyn CommitPolicy>,
    pub(crate) roster: Box<dyn RosterPolicy>,
    op_lock: Mutex<()>,
}

/// One operation: its provider (with the overlay) and the account lock.
pub(crate) struct Op<'a, K: MlsKv> {
    pub(crate) mls: &'a Mls<K>,
    pub(crate) provider: RfMlsProvider<'a, K>,
    guard: MutexGuard<'a, ()>,
}

impl<'a, K: MlsKv> Op<'a, K> {
    pub(crate) fn gate(&self, kind: GroupKind) -> Gate<'_, 'a, K> {
        Gate {
            provider: &self.provider,
            creds: &self.mls.creds,
            commit_policy: &*self.mls.commit_policy,
            roster: &*self.mls.roster,
            kind,
        }
    }

    /// Hand the buffered rows to a [`Staged`] together with the output.
    pub(crate) fn finish<T>(self, output: T) -> Result<Staged<'a, K, T>, MlsError> {
        let batch = self.provider.mls_storage().rows().take_batch()?;
        Ok(Staged::new(&self.mls.kv, batch, output, self.guard))
    }
}

pub(crate) fn unix_now() -> Result<u64, MlsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| MlsError::internal("system clock is before 1970"))
}

fn parse_message(bytes: &[u8], max: usize) -> Result<MlsMessageIn, MlsError> {
    if bytes.len() > max {
        return Err(MlsError::TooLarge(format!("{} bytes, limit {max}", bytes.len())));
    }
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| MlsError::Mls("malformed MLS message".to_owned()))
}

/// Parse and validate a KeyPackage message (size, signature, lifetime).
pub(crate) fn parse_key_package(
    bytes: &[u8],
    crypto: &CryptoHandle,
) -> Result<KeyPackage, MlsError> {
    match parse_message(bytes, MAX_KEY_PACKAGE_BYTES)?.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => validate_key_package(key_package, crypto),
        _ => Err(MlsError::PolicyRejected("message is not a KeyPackage".to_owned())),
    }
}

fn validate_key_package(
    key_package: KeyPackageIn,
    crypto: &CryptoHandle,
) -> Result<KeyPackage, MlsError> {
    key_package.validate(crypto.crypto(), ProtocolVersion::Mls10).map_err(MlsError::mls)
}

impl<K: MlsKv> Mls<K> {
    /// A runtime over `kv` with the MLS-0 default policies (everyone may commit, no roster).
    #[must_use]
    pub fn new(kv: K, crypto: CryptoHandle) -> Self {
        Self {
            kv,
            crypto,
            identity: None,
            creds: Arc::new(CredentialPolicy::new()),
            commit_policy: Box::new(PermissiveCommitPolicy),
            roster: Box::new(policy::DenyAllRoster),
            op_lock: Mutex::new(()),
        }
    }

    /// Install the own device identity (needed for `dm` KeyPackages and groups).
    #[must_use]
    pub fn with_device_identity(mut self, identity: DeviceIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Install the commit-rights hook.
    #[must_use]
    pub fn with_commit_policy(mut self, commit_policy: Box<dyn CommitPolicy>) -> Self {
        self.commit_policy = commit_policy;
        self
    }

    /// Install the roster hook.
    #[must_use]
    pub fn with_roster(mut self, roster: Box<dyn RosterPolicy>) -> Self {
        self.roster = roster;
        self
    }

    /// The backend.
    #[must_use]
    pub fn kv(&self) -> &K {
        &self.kv
    }

    /// The credential policy (debug pins).
    #[must_use]
    pub fn credential_policy(&self) -> &CredentialPolicy {
        &self.creds
    }

    pub(crate) fn begin(&self) -> Result<Op<'_, K>, MlsError> {
        let guard =
            self.op_lock.lock().map_err(|_| MlsError::internal("operation lock poisoned"))?;
        Ok(Op { mls: self, provider: RfMlsProvider::new(&self.crypto, &self.kv), guard })
    }

    pub(crate) fn credential_for(
        &self,
        op: &Op<'_, K>,
        kind: GroupKind,
        signer: &LeafSigner,
    ) -> Result<CredentialWithKey, MlsError> {
        let credential = match kind {
            GroupKind::Dm => {
                let identity = self
                    .identity
                    .as_ref()
                    .ok_or_else(|| MlsError::NotFound("own device identity".to_owned()))?;
                device_sets::seed_own(op.provider.mls_storage(), &identity.device_set_record)?;
                device::issue(identity, signer.public())?
            }
            GroupKind::Group => pseudonym::issue(signer.public()),
        };
        Ok(CredentialWithKey { credential, signature_key: signer.public().to_vec().into() })
    }

    pub(crate) fn store_signer(&self, op: &Op<'_, K>, signer: &LeafSigner) -> Result<(), MlsError> {
        Ok(op.provider.mls_storage().rf_put(RF_LABEL_LEAF_SIG, signer.public(), signer.secret())?)
    }

    pub(crate) fn load_signer(
        &self,
        op: &Op<'_, K>,
        group: &MlsGroup,
    ) -> Result<LeafSigner, MlsError> {
        let leaf =
            group.own_leaf_node().ok_or_else(|| MlsError::internal("own leaf is missing"))?;
        let secret = op
            .provider
            .mls_storage()
            .rf_get(RF_LABEL_LEAF_SIG, leaf.signature_key().as_slice())?
            .ok_or_else(|| MlsError::NotFound("leaf signing key".to_owned()))?;
        LeafSigner::from_secret(&secret)
    }

    pub(crate) fn load(&self, op: &Op<'_, K>, group_id: &[u8]) -> Result<Loaded, MlsError> {
        let storage = op.provider.mls_storage();
        let group = MlsGroup::load(op.provider.storage(), &GroupId::from_slice(group_id))?
            .ok_or_else(|| MlsError::NotFound("group".to_owned()))?;
        let kind = storage
            .rf_get(RF_LABEL_GROUP_KIND, group_id)?
            .and_then(|raw| std::str::from_utf8(&raw).ok().and_then(GroupKind::parse))
            .ok_or_else(|| MlsError::NotFound("group kind".to_owned()))?;
        if group.ciphersuite() != MLS_SUITE {
            return Err(MlsError::PolicyRejected(
                "loaded group ciphersuite is not 0x0001".to_owned(),
            ));
        }
        // A joiner cannot authenticate the tier yet and applies the absolute cap.
        let leaf_cap = storage
            .rf_get(RF_LABEL_GROUP_TIER, group_id)?
            .and_then(|raw| {
                std::str::from_utf8(&raw).ok().and_then(|text| text.parse::<u32>().ok())
            })
            .and_then(Tier::from_members)
            .map_or(ABSOLUTE_LEAF_CAP, Tier::leaf_cap);
        Ok(Loaded { group, kind, leaf_cap })
    }

    fn summarize(
        &self,
        op: &Op<'_, K>,
        kind: GroupKind,
        group: &MlsGroup,
    ) -> Result<Vec<MemberSummary>, MlsError> {
        let storage = op.provider.mls_storage();
        let mut members = Vec::new();
        for member in group.members().take(STATUS_MEMBER_LIMIT) {
            let identity = credential::describe(kind, &member.credential, &member.signature_key)?;
            let (root_commitment, device_id, revoked) = match &identity {
                MemberIdentity::Device(device) => (
                    Some(device.root_commitment.clone()),
                    Some(device.device_id.clone()),
                    device_sets::is_revoked(storage, &device.root_commitment, &device.device_id)?,
                ),
                _ => (None, None, false),
            };
            members.push(MemberSummary {
                leaf: member.index.u32(),
                root_commitment,
                device_id,
                revoked,
            });
        }
        Ok(members)
    }

    /// A fresh KeyPackage of `kind`. Expired own KeyPackages are deleted first (bounded rows).
    ///
    /// # Errors
    /// Missing device identity (`dm`), `device_set_too_large`, provider or storage failure.
    pub fn key_package(
        &self,
        kind: GroupKind,
    ) -> Result<Staged<'_, K, KeyPackageOutput>, MlsError> {
        let op = self.begin()?;
        let now = unix_now()?;
        op.provider.mls_storage().own_kp_purge_expired(now)?;
        let signer = LeafSigner::generate(self.crypto.crypto())?;
        let credential_with_key = self.credential_for(&op, kind, &signer)?;
        let credential_bytes = credential_with_key.credential.serialized_content().len();
        self.store_signer(&op, &signer)?;
        let bundle = KeyPackage::builder()
            .key_package_lifetime(config::key_package_lifetime())
            .leaf_node_capabilities(config::capabilities())
            .build(MLS_SUITE, &op.provider, &signer, credential_with_key)
            .map_err(MlsError::mls)?;
        let hash_ref =
            bundle.key_package().hash_ref(self.crypto.crypto()).map_err(MlsError::mls)?;
        op.provider
            .mls_storage()
            .own_kp_remember(&hash_ref, now.saturating_add(KEY_PACKAGE_LIFETIME_SECS))?;
        let bytes = MlsMessageOut::from(bundle).to_bytes().map_err(MlsError::mls)?;
        op.finish(KeyPackageOutput { bytes, leaf_sig_pk: *signer.public(), credential_bytes })
    }

    /// Create a group. `dm` takes no tier, `group` requires one.
    ///
    /// # Errors
    /// Policy errors for a wrong tier, a missing device identity, provider or storage failure.
    pub fn create(
        &self,
        kind: GroupKind,
        tier: Option<Tier>,
    ) -> Result<Staged<'_, K, CreateOutput>, MlsError> {
        let leaf_cap = match (kind, tier) {
            (GroupKind::Dm, None) => ABSOLUTE_LEAF_CAP,
            (GroupKind::Group, Some(tier)) => tier.leaf_cap(),
            (GroupKind::Dm, Some(_)) => {
                return Err(MlsError::PolicyRejected("a dm has no tier".to_owned()));
            }
            (GroupKind::Group, None) => {
                return Err(MlsError::PolicyRejected("a group requires a tier".to_owned()));
            }
        };
        let op = self.begin()?;
        unix_now()?;
        let signer = LeafSigner::generate(self.crypto.crypto())?;
        let credential_with_key = self.credential_for(&op, kind, &signer)?;
        self.store_signer(&op, &signer)?;
        let group_id = self.crypto.crypto().random_vec(GROUP_ID_BYTES).map_err(MlsError::mls)?;
        let group = MlsGroup::new_with_group_id(
            &op.provider,
            &signer,
            &config::create_config(kind)?,
            GroupId::from_slice(&group_id),
            credential_with_key,
        )
        .map_err(MlsError::mls)?;
        let storage = op.provider.mls_storage();
        storage.rf_put(RF_LABEL_GROUP_KIND, &group_id, kind.as_str().as_bytes())?;
        if let Some(tier) = tier {
            storage.rf_put(
                RF_LABEL_GROUP_TIER,
                &group_id,
                tier.members().to_string().as_bytes(),
            )?;
        }
        let epoch = group.epoch().as_u64();
        op.finish(CreateOutput { group_id, epoch, leaf_cap })
    }

    /// Add the members behind the KeyPackage messages: verify, stage, check, merge.
    ///
    /// # Errors
    /// `too_large`, `credential_rejected`, `policy_rejected`, `not_found` or a provider failure.
    pub fn add(
        &self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<Staged<'_, K, AddOutput>, MlsError> {
        let op = self.begin()?;
        let key_packages = key_packages
            .iter()
            .map(|bytes| parse_key_package(bytes, &self.crypto))
            .collect::<Result<Vec<_>, _>>()?;
        self.add_parsed(op, group_id, &key_packages)
    }

    /// Add already parsed KeyPackages (also used by the debug bulk path).
    pub(crate) fn add_parsed<'a>(
        &'a self,
        op: Op<'a, K>,
        group_id: &[u8],
        key_packages: &[KeyPackage],
    ) -> Result<Staged<'a, K, AddOutput>, MlsError> {
        let mut loaded = self.load(&op, group_id)?;
        let signer = self.load_signer(&op, &loaded.group)?;
        let (commit, welcome) =
            op.gate(loaded.kind).add(&mut loaded.group, &signer, key_packages, loaded.leaf_cap)?;
        let output = AddOutput {
            epoch: loaded.group.epoch().as_u64(),
            commit: commit.to_bytes().map_err(MlsError::mls)?,
            welcome: welcome.to_bytes().map_err(MlsError::mls)?,
        };
        op.finish(output)
    }

    /// Join the group a Welcome describes.
    ///
    /// # Errors
    /// `too_large`, `policy_rejected`, `credential_rejected` or a provider failure.
    pub fn join(&self, welcome: &[u8]) -> Result<Staged<'_, K, JoinOutput>, MlsError> {
        let message = parse_message(welcome, MAX_MLS_MESSAGE_BYTES)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(MlsError::PolicyRejected("message is not a Welcome".to_owned()));
        };
        let op = self.begin()?;
        let JoinedGroup { group, kind } = // A join derives the kind from the Welcome; the gate starts with a placeholder.
        op.gate(GroupKind::Dm).join(welcome)?;
        let group_id = group.group_id().to_vec();
        op.provider.mls_storage().rf_put(
            RF_LABEL_GROUP_KIND,
            &group_id,
            kind.as_str().as_bytes(),
        )?;
        let members = self.summarize(&op, kind, &group)?;
        let output = JoinOutput {
            group_id,
            kind,
            epoch: group.epoch().as_u64(),
            leaves: gate::leaf_count(&group),
            members,
        };
        op.finish(output)
    }

    /// Encrypt an application message.
    ///
    /// # Errors
    /// `not_found`, or an openmls failure (for example a pending proposal).
    pub fn send(
        &self,
        group_id: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Staged<'_, K, SendOutput>, MlsError> {
        let op = self.begin()?;
        let mut loaded = self.load(&op, group_id)?;
        let signer = self.load_signer(&op, &loaded.group)?;
        loaded.group.set_aad(aad.to_vec());
        let message =
            loaded.group.create_message(&op.provider, &signer, plaintext).map_err(MlsError::mls)?;
        let output = SendOutput {
            message: message.to_bytes().map_err(MlsError::mls)?,
            epoch: loaded.group.epoch().as_u64(),
        };
        op.finish(output)
    }

    /// Process an incoming handshake or application message. Plaintext is released only after the
    /// state is persisted.
    ///
    /// # Errors
    /// `too_large`, `wrong_epoch`, `decrypt_failed`, `policy_rejected`, `credential_rejected`,
    /// `not_found`.
    pub fn receive(&self, message: &[u8]) -> Result<Staged<'_, K, ReceivedMessage>, MlsError> {
        let protocol = match parse_message(message, MAX_MLS_MESSAGE_BYTES)?.extract() {
            MlsMessageBodyIn::PrivateMessage(private) => ProtocolMessage::from(private),
            MlsMessageBodyIn::PublicMessage(_) => {
                return Err(MlsError::PolicyRejected(
                    "public messages are refused (pure ciphertext)".to_owned(),
                ));
            }
            _ => return Err(MlsError::PolicyRejected("message is not a group message".to_owned())),
        };
        let group_id = protocol.group_id().to_vec();
        let op = self.begin()?;
        let mut loaded = self.load(&op, &group_id)?;
        let received = op.gate(loaded.kind).process(&mut loaded.group, protocol)?;
        op.finish(received)
    }

    /// Rotate the own leaf keys with an update commit (merged at once).
    ///
    /// # Errors
    /// `not_found`, gate rejections or a provider failure.
    pub fn update(&self, group_id: &[u8]) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        self.own_commit(group_id, |gate, group, signer| gate.update(group, signer))
    }

    /// Commit to the stored proposals (second half of a leave).
    ///
    /// # Errors
    /// `not_found`, gate rejections or a provider failure.
    pub fn commit_pending(&self, group_id: &[u8]) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        self.own_commit(group_id, |gate, group, signer| gate.commit_pending(group, signer))
    }

    /// Remove the member at `leaf`.
    ///
    /// # Errors
    /// `not_found`, gate rejections or a provider failure.
    pub fn remove(
        &self,
        group_id: &[u8],
        leaf: u32,
    ) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        self.own_commit(group_id, move |gate, group, signer| {
            gate.remove(group, signer, LeafNodeIndex::new(leaf))
        })
    }

    fn own_commit<F>(
        &self,
        group_id: &[u8],
        run: F,
    ) -> Result<Staged<'_, K, CommitOutput>, MlsError>
    where
        F: for<'g, 'k> FnOnce(
            &Gate<'g, 'k, K>,
            &mut MlsGroup,
            &LeafSigner,
        ) -> Result<MlsMessageOut, MlsError>,
    {
        let op = self.begin()?;
        let mut loaded = self.load(&op, group_id)?;
        let signer = self.load_signer(&op, &loaded.group)?;
        let message = run(&op.gate(loaded.kind), &mut loaded.group, &signer)?;
        let output = CommitOutput {
            epoch: loaded.group.epoch().as_u64(),
            message: message.to_bytes().map_err(MlsError::mls)?,
        };
        op.finish(output)
    }

    /// Announce leaving: a Remove proposal by reference. Another member commits it.
    ///
    /// # Errors
    /// `not_found` or a provider failure.
    pub fn leave(&self, group_id: &[u8]) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        let op = self.begin()?;
        let mut loaded = self.load(&op, group_id)?;
        let signer = self.load_signer(&op, &loaded.group)?;
        let message = loaded.group.leave_group(&op.provider, &signer).map_err(MlsError::mls)?;
        let output = CommitOutput {
            epoch: loaded.group.epoch().as_u64(),
            message: message.to_bytes().map_err(MlsError::mls)?,
        };
        op.finish(output)
    }

    /// Export a secret of the current epoch (RFC 9420 8.5).
    ///
    /// # Errors
    /// `not_found` or a provider failure.
    pub fn export(
        &self,
        group_id: &[u8],
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, MlsError> {
        let op = self.begin()?;
        let loaded = self.load(&op, group_id)?;
        let secret = loaded
            .group
            .export_secret(self.crypto.crypto(), label, context, len)
            .map_err(MlsError::mls)?;
        Ok(Zeroizing::new(secret.as_slice().to_vec()))
    }

    /// Status of a group, plus the account row statistics.
    ///
    /// # Errors
    /// `not_found` or a storage failure.
    pub fn status(&self, group_id: &[u8]) -> Result<StatusOutput, MlsError> {
        let op = self.begin()?;
        let loaded = self.load(&op, group_id)?;
        let tier = op
            .provider
            .mls_storage()
            .rf_get(RF_LABEL_GROUP_TIER, group_id)?
            .and_then(|raw| {
                std::str::from_utf8(&raw).ok().and_then(|text| text.parse::<u32>().ok())
            })
            .and_then(Tier::from_members);
        Ok(StatusOutput {
            epoch: loaded.group.epoch().as_u64(),
            kind: loaded.kind,
            tier,
            leaf_cap: loaded.leaf_cap,
            own_leaf: loaded.group.own_leaf_index().u32(),
            leaves: gate::leaf_count(&loaded.group),
            members: self.summarize(&op, loaded.kind, &loaded.group)?,
            rows: self.kv.row_stats()?,
        })
    }

    /// Row statistics of the account store (no group needed).
    ///
    /// # Errors
    /// Storage failure.
    pub fn row_stats(&self) -> Result<RowStats, MlsError> {
        Ok(self.kv.row_stats()?)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The MLS facade: create, `KeyPackage`, add, join, send, receive, update, leave, commit pending,
//! remove, export and status.
//!
//! Every state-changing operation loads the group, operates, and returns a [`Staged`] output. The
//! output is released only by `Staged::commit`, which writes the MLS rows and the caller's rows in
//! one transaction. The [`Staged`] also holds the account's operation lock, so no group stays in
//! memory between calls and operations never interleave.

pub mod config;
pub mod context;
pub mod conversation;
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

use self::context::CommitMeta;
use self::conversation::{ConversationRole, ExpectedPrincipals, RfConversation};
use self::gate::{Gate, JoinedGroup};
use self::policy::{CommitPolicy, PermissiveCommitPolicy, RosterPolicy};
use crate::credential::authority::NoAuthority;
use crate::credential::{
    self, CredentialPolicy, DeviceAuthority, DeviceIdentity, GroupKind, MemberIdentity, device,
    pseudonym,
};
use crate::provider::{CryptoHandle, RfMlsProvider};
use crate::signer::LeafSigner;
use crate::storage::kv::{MlsKv, RowStats, Staged};
use crate::{
    GROUP_ID_BYTES, KEY_PACKAGE_LIFETIME_SECS, LEAF_CAP, MAX_KEY_PACKAGE_BYTES,
    MAX_MLS_MESSAGE_BYTES, MLS_SUITE, MlsError, RF_LABEL_GROUP_KIND, RF_LABEL_GROUP_TIER,
    RF_LABEL_LEAF_SIG,
};
use ramflux_crypto::large_group::TIER_1000;

/// Number of members `status` lists before truncating.
pub const STATUS_MEMBER_LIMIT: usize = 50;

/// Capacity tier of a `group`, chosen at creation. The beta has one tier; a 5 000 member tier is
/// refused until it is measured (owner O5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Up to 1 000 members (leaf cap 3 000).
    Members1000,
}

impl Tier {
    /// Parse the member count (`1000` only).
    #[must_use]
    pub fn from_members(members: u32) -> Option<Self> {
        (members == TIER_1000).then_some(Self::Members1000)
    }

    /// Member count of the tier.
    #[must_use]
    pub fn members(self) -> u32 {
        match self {
            Self::Members1000 => TIER_1000,
        }
    }

    /// Leaf cap of the tier.
    #[must_use]
    pub fn leaf_cap(self) -> usize {
        match self {
            Self::Members1000 => LEAF_CAP,
        }
    }
}

/// A fresh `KeyPackage`.
#[derive(Debug)]
pub struct KeyPackageOutput {
    /// TLS-encoded `MLSMessage` carrying the `KeyPackage`.
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
    /// Signature public key of the creator's own leaf (a joiner of a pseudonym group pins it).
    pub leaf_sig_pk: [u8; 32],
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
    /// True when the directory's current record of the account shows the device revoked.
    pub revoked: bool,
}

/// A joined group.
#[derive(Debug)]
pub struct JoinOutput {
    /// Group id.
    pub group_id: Vec<u8>,
    /// Kind derived from the Welcome's `GroupContext`.
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
    /// Signature public key of the own leaf.
    pub own_sig_pk: Vec<u8>,
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

/// The own commit operations the facade routes through the gate.
#[derive(Clone, Copy)]
enum OwnOp {
    Update,
    CommitPending,
    Remove(u32),
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
    pub(crate) authority: Arc<dyn DeviceAuthority>,
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
            authority: &*self.mls.authority,
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

pub(crate) fn parse_message(bytes: &[u8], max: usize) -> Result<MlsMessageIn, MlsError> {
    if bytes.len() > max {
        return Err(MlsError::TooLarge(format!("{} bytes, limit {max}", bytes.len())));
    }
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| MlsError::Mls("malformed MLS message".to_owned()))
}

/// Parse and validate a `KeyPackage` message (size, signature, lifetime).
pub(crate) fn parse_key_package(
    bytes: &[u8],
    crypto: &CryptoHandle,
) -> Result<KeyPackage, MlsError> {
    match parse_message(bytes, MAX_KEY_PACKAGE_BYTES)?.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => validate_key_package(key_package, crypto),
        _ => Err(MlsError::PolicyRejected("message is not a KeyPackage".to_owned())),
    }
}

/// The leaf signature key (the pseudonym `P` of a group joiner) of a TLS-encoded `MLSMessage`
/// carrying a `KeyPackage`, read without verifying signatures or lifetime: the node host only needs
/// the key to tie a join request to a commit's added pseudonyms, and only the adding member
/// validates the `KeyPackage` (rule V). The message is parsed with the openmls types; the eight
/// fixed bytes (MLS 1.0, `mls_key_package`, MLS 1.0, the ramflux suite) must match.
///
/// # Errors
/// [`MlsError::TooLarge`] over the `KeyPackage` bound, [`MlsError::Mls`] for a malformed message,
/// [`MlsError::PolicyRejected`] for another version, wire format, suite or key length.
pub fn key_package_signature_key(bytes: &[u8]) -> Result<[u8; 32], MlsError> {
    const FIXED: [u8; 8] = [0, 1, 0, 5, 0, 1, 0, 1];
    if bytes.get(..FIXED.len()) != Some(&FIXED[..]) {
        return Err(MlsError::PolicyRejected("not an MLS 1.0 KeyPackage message".to_owned()));
    }
    match parse_message(bytes, MAX_KEY_PACKAGE_BYTES)?.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => {
            key_package.unverified_credential().signature_key.as_slice().try_into().map_err(|_| {
                MlsError::PolicyRejected("leaf signature key is not 32 bytes".to_owned())
            })
        }
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
            authority: Arc::new(NoAuthority),
            commit_policy: Box::new(PermissiveCommitPolicy),
            roster: Box::new(policy::DenyAllRoster),
            op_lock: Mutex::new(()),
        }
    }

    /// Install the own device identity (needed for `dm` `KeyPackages` and groups).
    #[must_use]
    pub fn with_device_identity(mut self, identity: DeviceIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Install the directory-path device authority (without one every device credential answers
    /// `authority_needed`).
    #[must_use]
    pub fn with_authority(mut self, authority: Arc<dyn DeviceAuthority>) -> Self {
        self.authority = authority;
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
        kind: GroupKind,
        signer: &LeafSigner,
    ) -> Result<CredentialWithKey, MlsError> {
        let credential = if kind.is_device_kind() {
            let identity = self
                .identity
                .as_ref()
                .ok_or_else(|| MlsError::NotFound("own device identity".to_owned()))?;
            device::issue(identity, signer.public())?
        } else {
            pseudonym::issue(signer.public())
        };
        Ok(CredentialWithKey { credential, signature_key: signer.public().to_vec().into() })
    }

    pub(crate) fn store_signer(op: &Op<'_, K>, signer: &LeafSigner) -> Result<(), MlsError> {
        Ok(op.provider.mls_storage().rf_put(RF_LABEL_LEAF_SIG, signer.public(), signer.secret())?)
    }

    pub(crate) fn load_signer(op: &Op<'_, K>, group: &MlsGroup) -> Result<LeafSigner, MlsError> {
        let leaf =
            group.own_leaf_node().ok_or_else(|| MlsError::internal("own leaf is missing"))?;
        let secret = op
            .provider
            .mls_storage()
            .rf_get(RF_LABEL_LEAF_SIG, leaf.signature_key().as_slice())?
            .ok_or_else(|| MlsError::NotFound("leaf signing key".to_owned()))?;
        LeafSigner::from_secret(&secret)
    }

    pub(crate) fn load(op: &Op<'_, K>, group_id: &[u8]) -> Result<Loaded, MlsError> {
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
        // The tier row is written on create and on join (from the genesis); a group without one
        // (dm, self) applies the single leaf cap.
        let leaf_cap = storage
            .rf_get(RF_LABEL_GROUP_TIER, group_id)?
            .and_then(|raw| {
                std::str::from_utf8(&raw).ok().and_then(|text| text.parse::<u32>().ok())
            })
            .and_then(Tier::from_members)
            .map_or(LEAF_CAP, Tier::leaf_cap);
        Ok(Loaded { group, kind, leaf_cap })
    }

    fn summarize(
        op: &Op<'_, K>,
        kind: GroupKind,
        group: &MlsGroup,
    ) -> Result<Vec<MemberSummary>, MlsError> {
        let mut members = Vec::new();
        for member in group.members().take(STATUS_MEMBER_LIMIT) {
            let identity = credential::describe(kind, &member.credential, &member.signature_key)?;
            let (root_commitment, device_id, revoked) = match &identity {
                MemberIdentity::Device(device) => (
                    Some(device.root_commitment.clone()),
                    Some(device.device_id.clone()),
                    op.mls
                        .authority
                        .current(device.root_commitment.as_bytes())
                        .is_some_and(|record| record.revoked_ids().contains(&device.device_id)),
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

    /// A fresh `KeyPackage` of `kind`. Expired own `KeyPackages` are deleted first (bounded rows).
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
        let credential_with_key = self.credential_for(kind, &signer)?;
        let credential_bytes = credential_with_key.credential.serialized_content().len();
        Self::store_signer(&op, &signer)?;
        let bundle = KeyPackage::builder()
            .key_package_lifetime(config::key_package_lifetime())
            .leaf_node_capabilities(config::capabilities())
            .build(MLS_SUITE, &op.provider, &signer, credential_with_key)
            .map_err(MlsError::mls)?;
        let hash_ref =
            bundle.key_package().hash_ref(self.crypto.crypto()).map_err(MlsError::mls)?;
        op.provider.mls_storage().own_kp_remember(
            &hash_ref,
            now.saturating_add(KEY_PACKAGE_LIFETIME_SECS),
            signer.public(),
        )?;
        let bytes = MlsMessageOut::from(bundle).to_bytes().map_err(MlsError::mls)?;
        op.finish(KeyPackageOutput { bytes, leaf_sig_pk: *signer.public(), credential_bytes })
    }

    /// Create a group. `dm` and `self` take no tier, `group` requires one. A `dm` or `self`
    /// group gets a synthetic `rf_conversation` binding (debug and interop use; the product path
    /// is [`Self::create_with`]).
    ///
    /// # Errors
    /// Policy errors for a wrong tier, a missing device identity, provider or storage failure.
    pub fn create(
        &self,
        kind: GroupKind,
        tier: Option<Tier>,
    ) -> Result<Staged<'_, K, CreateOutput>, MlsError> {
        let binding = if kind.is_device_kind() {
            let role =
                if kind == GroupKind::Own { ConversationRole::Own } else { ConversationRole::Dm };
            let mut id = [0_u8; 32];
            let random = self.crypto.crypto().random_vec(id.len()).map_err(MlsError::mls)?;
            id.copy_from_slice(&random);
            Some(RfConversation::synthetic(role, id))
        } else {
            None
        };
        self.create_with(kind, tier, binding.as_ref(), None)
    }

    /// Create a group with an explicit conversation binding (`dm`, `self`) and, optionally, a
    /// caller-derived group id (the orderer recomputes derived ids, so the engine must not pick a
    /// random one).
    ///
    /// # Errors
    /// Policy errors for a wrong tier or binding, a missing device identity, provider or storage
    /// failure.
    pub fn create_with(
        &self,
        kind: GroupKind,
        tier: Option<Tier>,
        binding: Option<&RfConversation>,
        group_id: Option<[u8; GROUP_ID_BYTES]>,
    ) -> Result<Staged<'_, K, CreateOutput>, MlsError> {
        let leaf_cap = match (kind.is_device_kind(), tier) {
            (true, None) => LEAF_CAP,
            (false, Some(tier)) => tier.leaf_cap(),
            (true, Some(_)) => {
                return Err(MlsError::PolicyRejected("a dm or self group has no tier".to_owned()));
            }
            (false, None) => {
                return Err(MlsError::PolicyRejected("a group requires a tier".to_owned()));
            }
        };
        let op = self.begin()?;
        let signer = LeafSigner::generate(self.crypto.crypto())?;
        let credential_with_key = self.credential_for(kind, &signer)?;
        Self::store_signer(&op, &signer)?;
        let group_id = match group_id {
            Some(id) => id.to_vec(),
            None => self.crypto.crypto().random_vec(GROUP_ID_BYTES).map_err(MlsError::mls)?,
        };
        let group = MlsGroup::new_with_group_id(
            &op.provider,
            &signer,
            &config::create_config(kind, binding)?,
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
        op.finish(CreateOutput { group_id, epoch, leaf_cap, leaf_sig_pk: *signer.public() })
    }

    /// Add the members behind the `KeyPackage` messages: verify, stage, check, merge.
    ///
    /// # Errors
    /// `too_large`, `credential_rejected`, `policy_rejected`, `not_found` or a provider failure.
    pub fn add(
        &self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<Staged<'_, K, AddOutput>, MlsError> {
        self.add_with(group_id, key_packages, CommitMeta::default())
    }

    /// [`Self::add`] with the commit authenticated data the policies see.
    ///
    /// # Errors
    /// As [`Self::add`].
    pub fn add_with(
        &self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
        meta: CommitMeta<'_>,
    ) -> Result<Staged<'_, K, AddOutput>, MlsError> {
        let op = self.begin()?;
        let key_packages = key_packages
            .iter()
            .map(|bytes| parse_key_package(bytes, &self.crypto))
            .collect::<Result<Vec<_>, _>>()?;
        Self::add_parsed(op, group_id, &key_packages, meta)
    }

    /// Add already parsed `KeyPackages` (also used by the debug bulk path).
    pub(crate) fn add_parsed<'a>(
        op: Op<'a, K>,
        group_id: &[u8],
        key_packages: &[KeyPackage],
        meta: CommitMeta<'_>,
    ) -> Result<Staged<'a, K, AddOutput>, MlsError> {
        let mut loaded = Self::load(&op, group_id)?;
        let signer = Self::load_signer(&op, &loaded.group)?;
        let (commit, welcome) = op.gate(loaded.kind).add(
            &mut loaded.group,
            &signer,
            key_packages,
            loaded.leaf_cap,
            meta,
        )?;
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
        self.join_checked(welcome, None, None)
    }

    /// Join the `group` a Welcome describes. `genesis` is the canonical genesis of the group
    /// (`rf.lg.genesis.v2`): its hash must equal the Welcome's group id and its tier gives the
    /// leaf cap for the joined tree and for every later received commit.
    ///
    /// # Errors
    /// As [`Self::join`], plus `policy_rejected` for a genesis that does not decode, does not
    /// match the group id or names an unavailable tier.
    pub fn join_group(
        &self,
        welcome: &[u8],
        genesis: &[u8],
    ) -> Result<Staged<'_, K, JoinOutput>, MlsError> {
        self.join_checked(welcome, None, Some(genesis))
    }

    /// Join the group a Welcome describes, requiring the conversation binding and the principals
    /// to be the expected ones (`policy_rejected` otherwise).
    ///
    /// # Errors
    /// As [`Self::join`], plus the expected-binding and expected-principal refusals.
    pub fn join_expecting(
        &self,
        welcome: &[u8],
        expected: &ExpectedPrincipals,
    ) -> Result<Staged<'_, K, JoinOutput>, MlsError> {
        self.join_checked(welcome, Some(expected), None)
    }

    fn join_checked(
        &self,
        welcome: &[u8],
        expected: Option<&ExpectedPrincipals>,
        genesis: Option<&[u8]>,
    ) -> Result<Staged<'_, K, JoinOutput>, MlsError> {
        let message = parse_message(welcome, MAX_MLS_MESSAGE_BYTES)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(MlsError::PolicyRejected("message is not a Welcome".to_owned()));
        };
        let op = self.begin()?;
        // A join derives the kind from the Welcome; the gate starts with a placeholder.
        let JoinedGroup { group, kind, tier } =
            op.gate(GroupKind::Dm).join(welcome, expected, genesis)?;
        let group_id = group.group_id().to_vec();
        op.provider.mls_storage().rf_put(
            RF_LABEL_GROUP_KIND,
            &group_id,
            kind.as_str().as_bytes(),
        )?;
        if let Some(tier) = tier {
            op.provider.mls_storage().rf_put(
                RF_LABEL_GROUP_TIER,
                &group_id,
                tier.members().to_string().as_bytes(),
            )?;
        }
        let members = Self::summarize(&op, kind, &group)?;
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
        let mut loaded = Self::load(&op, group_id)?;
        let signer = Self::load_signer(&op, &loaded.group)?;
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
        let mut loaded = Self::load(&op, &group_id)?;
        let received =
            op.gate(loaded.kind).process(&mut loaded.group, protocol, loaded.leaf_cap)?;
        op.finish(received)
    }

    /// Directory-path freshness of the member at `leaf` (rule V: local knowledge, may read the
    /// clock): the sender's pre-seal check of its own leaf and the receiver's check of an
    /// application message's sender. Never used to accept or reject a received commit or Welcome.
    ///
    /// # Errors
    /// `not_found`, `authority_needed`, `credential_rejected` (revoked, lease, key mismatch).
    pub fn check_leaf_directory(
        &self,
        group_id: &[u8],
        leaf: u32,
    ) -> Result<MemberIdentity, MlsError> {
        let op = self.begin()?;
        let loaded = Self::load(&op, group_id)?;
        op.gate(loaded.kind).check_leaf_directory(&loaded.group, LeafNodeIndex::new(leaf))
    }

    /// Rotate the own leaf keys with an update commit (merged at once).
    ///
    /// # Errors
    /// `not_found`, gate rejections or a provider failure.
    pub fn update(&self, group_id: &[u8]) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        self.own_commit(group_id, OwnOp::Update, CommitMeta::default())
    }

    /// [`Self::update`] with the commit authenticated data.
    ///
    /// # Errors
    /// As [`Self::update`].
    pub fn update_with(
        &self,
        group_id: &[u8],
        meta: CommitMeta<'_>,
    ) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        self.own_commit(group_id, OwnOp::Update, meta)
    }

    /// Commit to the stored proposals (second half of a leave).
    ///
    /// # Errors
    /// `not_found`, gate rejections or a provider failure.
    pub fn commit_pending(&self, group_id: &[u8]) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        self.own_commit(group_id, OwnOp::CommitPending, CommitMeta::default())
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
        self.own_commit(group_id, OwnOp::Remove(leaf), CommitMeta::default())
    }

    /// [`Self::remove`] with the commit authenticated data.
    ///
    /// # Errors
    /// As [`Self::remove`].
    pub fn remove_with(
        &self,
        group_id: &[u8],
        leaf: u32,
        meta: CommitMeta<'_>,
    ) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        self.own_commit(group_id, OwnOp::Remove(leaf), meta)
    }

    fn own_commit(
        &self,
        group_id: &[u8],
        operation: OwnOp,
        meta: CommitMeta<'_>,
    ) -> Result<Staged<'_, K, CommitOutput>, MlsError> {
        let op = self.begin()?;
        let mut loaded = Self::load(&op, group_id)?;
        let signer = Self::load_signer(&op, &loaded.group)?;
        let gate = op.gate(loaded.kind);
        let message = match operation {
            OwnOp::Update => gate.update(&mut loaded.group, &signer, meta)?,
            OwnOp::CommitPending => gate.commit_pending(&mut loaded.group, &signer, meta)?,
            OwnOp::Remove(leaf) => {
                gate.remove(&mut loaded.group, &signer, LeafNodeIndex::new(leaf), meta)?
            }
        };
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
        let mut loaded = Self::load(&op, group_id)?;
        let signer = Self::load_signer(&op, &loaded.group)?;
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
        let loaded = Self::load(&op, group_id)?;
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
        let loaded = Self::load(&op, group_id)?;
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
            own_sig_pk: loaded
                .group
                .own_leaf_node()
                .map(|leaf| leaf.signature_key().as_slice().to_vec())
                .unwrap_or_default(),
            leaves: gate::leaf_count(&loaded.group),
            members: Self::summarize(&op, loaded.kind, &loaded.group)?,
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

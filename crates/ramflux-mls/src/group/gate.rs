// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The gate: the only place that merges commits, joins by Welcome, stores proposals or adds
//! members.
//!
//! Every decision is made on (credential, leaf signature key) pairs, never on a credential alone.
//! Check order, so rejections are unambiguous: input size (before parsing, in the facade), suite,
//! credential type against the group kind, the pair (pure V1 device chain only: received commits
//! and Welcomes read no clock and no directory, and openmls leaf-node lifetime validation is
//! skipped), successor and one-leaf-per-device, proposal and sender allowlist, kind limits, then
//! [`CommitPolicy`] and [`RosterPolicy`]. The directory-path freshness check runs only where rule
//! V allows it: the adding device's own `KeyPackage` check and [`Gate::check_leaf_directory`].
//! A rejected commit, Welcome or proposal is discarded: nothing is flushed and the epoch stays.

use std::collections::{BTreeMap, BTreeSet};

use openmls::prelude::Extensions;
use openmls::prelude::{
    CredentialType, KeyPackage, LeafNodeIndex, LeafNodeLifetimePolicy, LeafNodeParameters, Member,
    MlsGroup, MlsMessageOut, ProcessMessageError, ProcessedMessageContent, ProtocolMessage, Sender,
    StagedCommit, StagedWelcome, ValidationError, Welcome,
};
use openmls_traits::OpenMlsProvider as _;
use zeroize::Zeroizing;

use super::context::{CommitCtx, CommitMeta, WelcomeCtx};
use super::conversation::{ConversationRole, ExpectedPrincipals, RfConversation};
use super::policy::{CommitPolicy, RosterPolicy, check_proposal_type, check_sender};
use super::{ReceivedMessage, config};
use crate::credential::{self, CredentialPolicy, DeviceAuthority, GroupKind, MemberIdentity};
use crate::provider::RfMlsProvider;
use crate::signer::LeafSigner;
use crate::storage::kv::{MlsKv, MlsKvError};
use crate::{
    ABSOLUTE_LEAF_CAP, CREDENTIAL_TYPE_DEVICE, CREDENTIAL_TYPE_PSEUDONYM, MLS_SUITE, MlsError,
};

/// What a successful Welcome produced.
pub(crate) struct JoinedGroup {
    pub(crate) group: MlsGroup,
    pub(crate) kind: GroupKind,
}

/// Bundle of the references the checks need. Copyable so a join can swap the kind it derived.
pub(crate) struct Gate<'a, 'k, K: MlsKv> {
    pub(crate) provider: &'a RfMlsProvider<'k, K>,
    pub(crate) creds: &'a CredentialPolicy,
    pub(crate) authority: &'a dyn DeviceAuthority,
    pub(crate) commit_policy: &'a dyn CommitPolicy,
    pub(crate) roster: &'a dyn RosterPolicy,
    pub(crate) kind: GroupKind,
}

impl<K: MlsKv> Clone for Gate<'_, '_, K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: MlsKv> Copy for Gate<'_, '_, K> {}

fn policy(what: &str) -> MlsError {
    MlsError::PolicyRejected(what.to_owned())
}

fn credential_rejected(what: &str) -> MlsError {
    MlsError::CredentialRejected(what.to_owned())
}

/// Map an openmls processing error to a typed one.
fn map_process_error(error: ProcessMessageError<MlsKvError>) -> MlsError {
    match error {
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch) => MlsError::WrongEpoch,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(_)) => {
            MlsError::DecryptFailed
        }
        ProcessMessageError::StorageError(error) => MlsError::Storage(error),
        other => MlsError::mls(other),
    }
}

/// Number of occupied leaves of the group's tree.
pub(crate) fn leaf_count(group: &MlsGroup) -> usize {
    group.treesync().full_leaves().count()
}

impl<'k, K: MlsKv> Gate<'_, 'k, K> {
    /// Pure pair check (V1): no clock, no directory. Used for every received commit and Welcome.
    fn verify(
        &self,
        credential: &openmls::prelude::Credential,
        signature_key: &[u8],
    ) -> Result<MemberIdentity, MlsError> {
        self.creds.verify_pair(None, self.kind, credential, signature_key)
    }

    /// Pair check plus the directory path (clock, lease, revocation): local freshness only.
    fn verify_directory(
        &self,
        credential: &openmls::prelude::Credential,
        signature_key: &[u8],
    ) -> Result<MemberIdentity, MlsError> {
        self.creds.verify_pair(Some(self.authority), self.kind, credential, signature_key)
    }

    /// Directory-path freshness of the member at `index` (the sender's pre-seal check on its own
    /// leaf, the receiver's check of an application message's sender).
    pub(crate) fn check_leaf_directory(
        &self,
        group: &MlsGroup,
        index: LeafNodeIndex,
    ) -> Result<MemberIdentity, MlsError> {
        let member = group.member_at(index).ok_or_else(|| MlsError::NotFound("leaf".to_owned()))?;
        let mut identity = self.verify_directory(&member.credential, &member.signature_key)?;
        if let MemberIdentity::Device(device) = &mut identity {
            device.leaf_index = Some(member.index.u32());
        }
        Ok(identity)
    }

    fn describe(&self, member: &Member) -> Result<MemberIdentity, MlsError> {
        let mut identity =
            credential::describe(self.kind, &member.credential, &member.signature_key)?;
        if let MemberIdentity::Device(device) = &mut identity {
            device.leaf_index = Some(member.index.u32());
        }
        Ok(identity)
    }

    fn describe_at(
        &self,
        group: &MlsGroup,
        index: LeafNodeIndex,
    ) -> Result<MemberIdentity, MlsError> {
        let member =
            group.member_at(index).ok_or_else(|| MlsError::internal("leaf index has no member"))?;
        self.describe(&member)
    }

    /// (a) A `KeyPackage` before it may be added: suite, credential type and pair. `directory`
    /// adds the directory path (the adding device's own check before it commits); a received
    /// commit passes `false` (V1 only).
    pub(crate) fn check_key_package(
        &self,
        key_package: &KeyPackage,
        directory: bool,
    ) -> Result<MemberIdentity, MlsError> {
        if key_package.ciphersuite() != MLS_SUITE {
            return Err(policy("key package ciphersuite is not 0x0001"));
        }
        let leaf = key_package.leaf_node();
        let mut identity = if directory {
            self.verify_directory(leaf.credential(), leaf.signature_key().as_slice())?
        } else {
            self.verify(leaf.credential(), leaf.signature_key().as_slice())?
        };
        if let MemberIdentity::Device(device) = &mut identity {
            let hash = key_package.hash_ref(self.provider.crypto()).map_err(MlsError::mls)?;
            device.kp_hash = hash.as_slice().try_into().ok();
        }
        Ok(identity)
    }

    /// (c) Every staged commit before it is merged, received or own: suite, pairs of every
    /// credential it introduces, successor and one-leaf-per-device, proposal and sender
    /// allowlist, kind limits, commit rights and roster.
    fn check_commit(
        &self,
        group: &MlsGroup,
        staged: &StagedCommit,
        committer: LeafNodeIndex,
        leaf_cap: usize,
        ctx: &CommitCtx<'_>,
    ) -> Result<(), MlsError> {
        if staged.group_context().ciphersuite() != MLS_SUITE || group.ciphersuite() != MLS_SUITE {
            return Err(policy("group ciphersuite is not 0x0001"));
        }
        let current = leaf_count(group);
        let adds = staged.add_proposals().count();
        // Cheap reject of oversized commits before any pair verification.
        if self.kind == GroupKind::Group
            && current.saturating_add(adds)
                > leaf_cap.saturating_add(staged.remove_proposals().count())
        {
            return Err(policy("commit exceeds the leaf cap"));
        }

        let mut added = Vec::new();
        for add in staged.add_proposals() {
            added.push(self.check_key_package(add.add_proposal().key_package(), false)?);
        }
        let mut replaced: BTreeMap<u32, MemberIdentity> = BTreeMap::new();
        for update in staged.update_proposals() {
            let Sender::Member(index) = update.sender() else {
                return Err(policy("update proposal from a non-member"));
            };
            let leaf = update.update_proposal().leaf_node();
            let identity = self.verify(leaf.credential(), leaf.signature_key().as_slice())?;
            replaced.insert(index.u32(), identity);
        }
        if let Some(leaf) = staged.update_path_leaf_node() {
            let identity = self.verify(leaf.credential(), leaf.signature_key().as_slice())?;
            replaced.insert(committer.u32(), identity);
        }

        // (e) successor rule.
        for (index, new) in &replaced {
            let old = self.describe_at(group, LeafNodeIndex::new(*index))?;
            self.check_successor(ctx, &old, new)?;
        }

        // (f) one leaf per device (dm) over the resulting tree.
        let removed: BTreeSet<u32> = staged
            .remove_proposals()
            .map(|remove| remove.remove_proposal().removed().u32())
            .collect();
        let resulting = if self.kind.is_device_kind() {
            Some(self.resulting_dm_tree(group, &removed, &replaced, &added)?)
        } else {
            None
        };

        // (d) proposal and sender allowlist.
        for queued in staged.queued_proposals() {
            check_proposal_type(queued.proposal())?;
            check_sender(queued.sender())?;
        }

        // (h) kind limits.
        if let Some(tree) = &resulting {
            let principals: BTreeSet<String> =
                tree.iter().filter_map(MemberIdentity::principal).collect();
            if principals.len() > self.kind.max_principals() {
                return Err(policy("the group holds more principals than its kind allows"));
            }
        } else {
            let after = current.saturating_sub(removed.len()).saturating_add(adds);
            if after > leaf_cap {
                return Err(policy("commit exceeds the leaf cap"));
            }
        }

        // (g) commit rights and roster.
        let committer_identity = self.describe_at(group, committer)?;
        for identity in &added {
            self.commit_policy.may_add(ctx, &committer_identity, identity)?;
            if self.kind == GroupKind::Group {
                self.roster.accept_member(ctx, identity)?;
            }
        }
        let mut removed_identities = Vec::new();
        for queued in staged.remove_proposals() {
            let index = queued.remove_proposal().removed();
            let identity = self.describe_at(group, index)?;
            let proposer = match queued.sender() {
                Sender::Member(proposer) => self.describe_at(group, *proposer)?,
                other => return Err(policy(&format!("remove proposal sender {other:?}"))),
            };
            self.commit_policy.may_remove(ctx, &committer_identity, &proposer, &identity)?;
            removed_identities.push(identity);
        }
        self.commit_policy.check_delta(ctx, &committer_identity, &added, &removed_identities)
    }

    fn check_successor(
        &self,
        ctx: &CommitCtx<'_>,
        old: &MemberIdentity,
        new: &MemberIdentity,
    ) -> Result<(), MlsError> {
        match self.kind {
            GroupKind::Dm | GroupKind::Own => {
                if old.device_key() == new.device_key() {
                    Ok(())
                } else {
                    Err(credential_rejected("an update must keep the same device"))
                }
            }
            GroupKind::Group => {
                let same_key = matches!(
                    (old, new),
                    (MemberIdentity::Pseudonym { pseudonym_pk: a }, MemberIdentity::Pseudonym { pseudonym_pk: b }) if a == b
                );
                if same_key { Ok(()) } else { self.roster.accept_successor(ctx, old, new) }
            }
        }
    }

    /// The tree a dm would have after the commit, with the duplicate-device check.
    fn resulting_dm_tree(
        &self,
        group: &MlsGroup,
        removed: &BTreeSet<u32>,
        replaced: &BTreeMap<u32, MemberIdentity>,
        added: &[MemberIdentity],
    ) -> Result<Vec<MemberIdentity>, MlsError> {
        let mut tree = Vec::new();
        for member in group.members() {
            let index = member.index.u32();
            if removed.contains(&index) {
                continue;
            }
            match replaced.get(&index) {
                Some(identity) => tree.push(identity.clone()),
                None => tree.push(self.describe(&member)?),
            }
        }
        tree.extend(added.iter().cloned());
        let mut devices = BTreeSet::new();
        for identity in &tree {
            if let Some((root, device)) = identity.device_key()
                && !devices.insert((root.to_owned(), device.to_owned()))
            {
                return Err(credential_rejected("a device may hold only one leaf"));
            }
        }
        Ok(tree)
    }

    fn merge_own(
        &self,
        group: &mut MlsGroup,
        leaf_cap: usize,
        meta: CommitMeta<'_>,
    ) -> Result<(), MlsError> {
        let own = group.own_leaf_index();
        {
            let pending = group
                .pending_commit()
                .ok_or_else(|| MlsError::internal("no pending commit to merge"))?;
            let group_id = group.group_id().to_vec();
            let ctx =
                CommitCtx { group_id: &group_id, epoch: group.epoch().as_u64(), meta: meta.aad };
            self.check_commit(group, pending, own, leaf_cap, &ctx)?;
        }
        group.merge_pending_commit(self.provider).map_err(MlsError::mls)
    }

    /// Add members: every `KeyPackage` is verified, the own cap (tier) is applied, then the commit
    /// is staged, checked as a whole and merged (debug mode: no orderer).
    pub(crate) fn add(
        &self,
        group: &mut MlsGroup,
        signer: &LeafSigner,
        key_packages: &[KeyPackage],
        own_leaf_cap: usize,
        meta: CommitMeta<'_>,
    ) -> Result<(MlsMessageOut, MlsMessageOut), MlsError> {
        if self.kind == GroupKind::Group
            && leaf_count(group).saturating_add(key_packages.len()) > own_leaf_cap
        {
            return Err(policy("add exceeds the group tier leaf cap"));
        }
        let own = self.describe_at(group, group.own_leaf_index())?;
        {
            // Pre-check each KeyPackage on its own (the adding device's directory path); the
            // staged commit is judged as a whole in `merge_own` (V1 only).
            let group_id = group.group_id().to_vec();
            let ctx =
                CommitCtx { group_id: &group_id, epoch: group.epoch().as_u64(), meta: meta.aad };
            for key_package in key_packages {
                let added = self.check_key_package(key_package, true)?;
                self.commit_policy.may_add(&ctx, &own, &added)?;
            }
        }
        group.set_aad(meta.aad.to_vec());
        let (commit, welcome, _group_info) =
            group.add_members(self.provider, signer, key_packages).map_err(MlsError::mls)?;
        self.merge_own(group, own_leaf_cap, meta)?;
        Ok((commit, welcome))
    }

    /// Remove one member.
    pub(crate) fn remove(
        &self,
        group: &mut MlsGroup,
        signer: &LeafSigner,
        leaf: LeafNodeIndex,
        meta: CommitMeta<'_>,
    ) -> Result<MlsMessageOut, MlsError> {
        group.set_aad(meta.aad.to_vec());
        let (commit, _welcome, _group_info) =
            group.remove_members(self.provider, signer, &[leaf]).map_err(MlsError::mls)?;
        self.merge_own(group, ABSOLUTE_LEAF_CAP, meta)?;
        Ok(commit)
    }

    /// Commit to the stored proposals (the second half of a leave).
    pub(crate) fn commit_pending(
        &self,
        group: &mut MlsGroup,
        signer: &LeafSigner,
        meta: CommitMeta<'_>,
    ) -> Result<MlsMessageOut, MlsError> {
        group.set_aad(meta.aad.to_vec());
        let (commit, _welcome, _group_info) =
            group.commit_to_pending_proposals(self.provider, signer).map_err(MlsError::mls)?;
        self.merge_own(group, ABSOLUTE_LEAF_CAP, meta)?;
        Ok(commit)
    }

    /// Rotate the own leaf keys.
    pub(crate) fn update(
        &self,
        group: &mut MlsGroup,
        signer: &LeafSigner,
        meta: CommitMeta<'_>,
    ) -> Result<MlsMessageOut, MlsError> {
        group.set_aad(meta.aad.to_vec());
        let bundle = group
            .self_update(self.provider, signer, LeafNodeParameters::default())
            .map_err(MlsError::mls)?;
        let (commit, _welcome, _group_info) = bundle.into_contents();
        self.merge_own(group, ABSOLUTE_LEAF_CAP, meta)?;
        Ok(commit)
    }

    /// (b) Join by Welcome: suite, kind from the authenticated `GroupContext`, the `rf_conversation`
    /// binding of a `dm`/`self` group (role must match the kind, id and principals must match
    /// `expected` when the caller has one), no replacement of an existing group, the absolute leaf
    /// cap, every member as a pair, the kind limits and the roster (one call for the whole tree).
    pub(crate) fn join(
        &self,
        welcome: Welcome,
        expected: Option<&ExpectedPrincipals>,
    ) -> Result<JoinedGroup, MlsError> {
        // Rule V (W2): leaf-node lifetime validation is skipped; members are checked by V1 only.
        let staged = StagedWelcome::build_from_welcome(
            self.provider,
            &config::join_config(self.kind),
            welcome,
        )
        .map_err(MlsError::mls)?
        .skip_lifetime_validation()
        .build()
        .map_err(MlsError::mls)?;
        let context = staged.group_context();
        if context.ciphersuite() != MLS_SUITE {
            return Err(policy("welcome ciphersuite is not 0x0001"));
        }
        let binding = RfConversation::from_extensions(context.extensions())?;
        let kind = kind_from_context(context.extensions(), binding.as_ref())?;
        let gate = Self { kind, ..*self };
        if let Some(expected) = expected {
            expected.check_binding(kind, binding.as_ref())?;
        }
        if MlsGroup::load(gate.provider.storage(), context.group_id())
            .map_err(MlsError::Storage)?
            .is_some()
        {
            return Err(policy("a welcome for an existing group id is refused"));
        }
        if staged.members().count() > ABSOLUTE_LEAF_CAP {
            return Err(policy("welcome exceeds the absolute leaf cap"));
        }
        let mut identities = Vec::new();
        for member in staged.members() {
            let mut identity = gate.verify(&member.credential, &member.signature_key)?;
            if let MemberIdentity::Device(device) = &mut identity {
                device.leaf_index = Some(member.index.u32());
            }
            identities.push(identity);
        }
        let mut devices = BTreeSet::new();
        for identity in &identities {
            if let Some((root, device)) = identity.device_key()
                && !devices.insert((root.to_owned(), device.to_owned()))
            {
                return Err(credential_rejected("a device may hold only one leaf"));
            }
        }
        if kind.is_device_kind() {
            let principals: BTreeSet<String> =
                identities.iter().filter_map(MemberIdentity::principal).collect();
            if principals.len() > kind.max_principals() {
                return Err(policy("the group holds more principals than its kind allows"));
            }
            if let Some(expected) = expected {
                expected.check_members(&identities)?;
            }
        } else {
            let welcome_ctx = WelcomeCtx {
                group_id: context.group_id().as_slice(),
                expected_group_id: None,
                leaf_cap: ABSOLUTE_LEAF_CAP,
            };
            gate.roster.accept_welcome(&welcome_ctx, &identities)?;
        }
        let mut group = staged.into_group(gate.provider).map_err(MlsError::mls)?;
        // The join configuration was chosen before the kind was known; apply the kind's now.
        group
            .set_configuration(gate.provider.storage(), &config::join_config(kind))
            .map_err(MlsError::Storage)?;
        Ok(JoinedGroup { group, kind })
    }

    /// Process one protocol message: decrypt, check the sender type, and for commits and
    /// proposals run the gate before anything is merged or stored.
    pub(crate) fn process(
        &self,
        group: &mut MlsGroup,
        message: ProtocolMessage,
    ) -> Result<ReceivedMessage, MlsError> {
        if group.ciphersuite() != MLS_SUITE {
            return Err(policy("group ciphersuite is not 0x0001"));
        }
        // Rule V (W1): no wall clock in commit validity, so the lifetime check is skipped.
        let processed = group
            .process_message_with_lifetime_policy(
                self.provider,
                message,
                LeafNodeLifetimePolicy::Skip,
            )
            .map_err(map_process_error)?;
        let sender = check_sender(processed.sender())?;
        let epoch = processed.epoch().as_u64();
        let aad = processed.aad().to_vec();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                Ok(ReceivedMessage::Application {
                    plaintext: Zeroizing::new(message.into_bytes()),
                    aad: aad.clone(),
                    sender_leaf: sender.u32(),
                    epoch,
                })
            }
            ProcessedMessageContent::ProposalMessage(queued) => {
                check_proposal_type(queued.proposal())?;
                check_sender(queued.sender())?;
                group
                    .store_pending_proposal(self.provider.storage(), *queued)
                    .map_err(MlsError::Storage)?;
                Ok(ReceivedMessage::Proposal { sender_leaf: sender.u32(), epoch })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let group_id = group.group_id().to_vec();
                let ctx = CommitCtx { group_id: &group_id, epoch, meta: &aad };
                self.check_commit(group, &staged, sender, ABSOLUTE_LEAF_CAP, &ctx)?;
                let removed = staged.self_removed();
                group.merge_staged_commit(self.provider, *staged).map_err(MlsError::mls)?;
                Ok(ReceivedMessage::Commit { epoch: group.epoch().as_u64(), removed })
            }
            ProcessedMessageContent::OwnPrivateMessage
            | ProcessedMessageContent::OwnPendingCommit => Ok(ReceivedMessage::Own { epoch }),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(policy("external join proposals are not allowed"))
            }
        }
    }
}

/// The group kind from the authenticated `GroupContext`: `required_capabilities` must list exactly
/// one rf credential type. The device type is shared by `dm` and `self`; their
/// `rf_conversation` binding names the role, and a device-type group without a binding is
/// refused.
fn kind_from_context(
    extensions: &Extensions<openmls::prelude::GroupContext>,
    binding: Option<&RfConversation>,
) -> Result<GroupKind, MlsError> {
    let required = extensions
        .required_capabilities()
        .ok_or_else(|| policy("group context lacks required capabilities"))?;
    let rf_types: Vec<u16> = required
        .credential_types()
        .iter()
        .filter_map(|credential_type| match credential_type {
            CredentialType::Other(code)
                if *code == CREDENTIAL_TYPE_DEVICE || *code == CREDENTIAL_TYPE_PSEUDONYM =>
            {
                Some(*code)
            }
            _ => None,
        })
        .collect();
    match rf_types.as_slice() {
        [code] if required.credential_types().len() == 1 => {
            let kind = GroupKind::from_credential_type(*code)
                .ok_or_else(|| policy("unknown group kind"))?;
            match (kind.is_device_kind(), binding) {
                (true, Some(binding)) => Ok(match binding.role {
                    ConversationRole::Dm => GroupKind::Dm,
                    ConversationRole::Own => GroupKind::Own,
                }),
                (true, None) => Err(policy("a dm or self group must carry rf_conversation")),
                (false, None) => Ok(kind),
                (false, Some(_)) => Err(policy("a group must not carry rf_conversation")),
            }
        }
        _ => Err(policy("group context must list exactly one rf credential type")),
    }
}

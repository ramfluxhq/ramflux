// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The openmls `StorageProvider` over [`MlsKv`], with the write overlay in front.
//!
//! Every method maps to a labelled row of `mls_kv`. The labels equal the labels of the reference
//! in-memory storage so exported state stays comparable; own rows use the `rf/` prefix.

pub mod kv;

use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use self::kv::{MlsKv, MlsKvError, RowStore, decode, encode};

pub(crate) const LABEL_KEY_PACKAGE: &str = "KeyPackage";
pub(crate) const LABEL_PSK: &str = "Psk";
pub(crate) const LABEL_ENCRYPTION_KEY_PAIR: &str = "EncryptionKeyPair";
pub(crate) const LABEL_SIGNATURE_KEY_PAIR: &str = "SignatureKeyPair";
pub(crate) const LABEL_EPOCH_KEY_PAIRS: &str = "EpochKeyPairs";
pub(crate) const LABEL_TREE: &str = "Tree";
pub(crate) const LABEL_GROUP_CONTEXT: &str = "GroupContext";
pub(crate) const LABEL_INTERIM_TRANSCRIPT_HASH: &str = "InterimTranscriptHash";
pub(crate) const LABEL_CONFIRMATION_TAG: &str = "ConfirmationTag";
pub(crate) const LABEL_JOIN_CONFIG: &str = "MlsGroupJoinConfig";
pub(crate) const LABEL_OWN_LEAF_NODES: &str = "OwnLeafNodes";
pub(crate) const LABEL_GROUP_STATE: &str = "GroupState";
pub(crate) const LABEL_QUEUED_PROPOSAL: &str = "QueuedProposal";
pub(crate) const LABEL_PROPOSAL_QUEUE_REFS: &str = "ProposalQueueRefs";
pub(crate) const LABEL_OWN_LEAF_INDEX: &str = "OwnLeafNodeIndex";
pub(crate) const LABEL_EPOCH_SECRETS: &str = "EpochSecrets";
pub(crate) const LABEL_RESUMPTION_PSK_STORE: &str = "ResumptionPsk";
pub(crate) const LABEL_MESSAGE_SECRETS: &str = "MessageSecrets";

/// Upper bound for list pre-allocation (never sized from stored input).
const MAX_LIST_PREALLOC: usize = 1024;
/// Key of the own-KeyPackage expiry index row.
const OWN_KP_INDEX_KEY: &[u8] = b"index";

/// One own KeyPackage in the expiry index.
#[derive(Serialize, Deserialize)]
struct OwnKeyPackageEntry {
    /// Row key of the KeyPackage (its serialized hash reference).
    reference_key: Vec<u8>,
    /// Unix seconds after which the KeyPackage is deleted.
    not_after: u64,
}

/// openmls storage: overlay in front of an [`MlsKv`] backend.
pub struct MlsStorage<'k, K: MlsKv> {
    rows: RowStore<'k, K>,
}

fn key_of<V: Serialize + ?Sized>(value: &V) -> Result<Vec<u8>, MlsKvError> {
    Ok(serde_json::to_vec(value)?)
}

fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, MlsKvError> {
    let mut key = key_of(group_id)?;
    key.extend_from_slice(&key_of(epoch)?);
    key.extend_from_slice(&key_of(&leaf_index)?);
    Ok(key)
}

impl<'k, K: MlsKv> MlsStorage<'k, K> {
    /// A storage whose overlay is empty.
    #[must_use]
    pub fn new(kv: &'k K) -> Self {
        Self { rows: RowStore::new(kv) }
    }

    /// The raw row layer (own `rf/` rows, flush).
    #[must_use]
    pub fn rows(&self) -> &RowStore<'k, K> {
        &self.rows
    }

    /// Read an own row.
    ///
    /// # Errors
    /// Backend failure.
    pub fn rf_get(
        &self,
        label: &str,
        key: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, MlsKvError> {
        self.rows.get(label, key)
    }

    /// Buffer an own row.
    ///
    /// # Errors
    /// Poisoned overlay.
    pub fn rf_put(&self, label: &str, key: &[u8], value: &[u8]) -> Result<(), MlsKvError> {
        self.rows.put(label, key.to_vec(), Zeroizing::new(value.to_vec()))
    }

    /// Buffer the deletion of an own row.
    ///
    /// # Errors
    /// Poisoned overlay.
    pub fn rf_delete(&self, label: &str, key: &[u8]) -> Result<(), MlsKvError> {
        self.rows.delete(label, key.to_vec())
    }

    /// Record an own KeyPackage with its expiry.
    pub(crate) fn own_kp_remember<R: Serialize + ?Sized>(
        &self,
        hash_ref: &R,
        not_after: u64,
    ) -> Result<(), MlsKvError> {
        let mut entries = self.own_kp_entries()?;
        entries.push(OwnKeyPackageEntry { reference_key: key_of(hash_ref)?, not_after });
        self.own_kp_store(&entries)
    }

    fn own_kp_forget(&self, reference_key: &[u8]) -> Result<(), MlsKvError> {
        let mut entries = self.own_kp_entries()?;
        let before = entries.len();
        entries.retain(|entry| entry.reference_key != reference_key);
        if entries.len() == before {
            return Ok(());
        }
        self.own_kp_store(&entries)
    }

    /// Delete every own KeyPackage whose expiry passed, with its keys. Returns the count.
    pub(crate) fn own_kp_purge_expired(&self, now: u64) -> Result<usize, MlsKvError> {
        let entries = self.own_kp_entries()?;
        let (expired, live): (Vec<_>, Vec<_>) =
            entries.into_iter().partition(|entry| entry.not_after <= now);
        for entry in &expired {
            self.rows.delete(LABEL_KEY_PACKAGE, entry.reference_key.clone())?;
        }
        if !expired.is_empty() {
            self.own_kp_store(&live)?;
        }
        Ok(expired.len())
    }

    fn own_kp_entries(&self) -> Result<Vec<OwnKeyPackageEntry>, MlsKvError> {
        match self.rows.get(crate::RF_LABEL_OWN_KP, OWN_KP_INDEX_KEY)? {
            Some(raw) => decode(&raw),
            None => Ok(Vec::new()),
        }
    }

    fn own_kp_store(&self, entries: &[OwnKeyPackageEntry]) -> Result<(), MlsKvError> {
        self.rows.put(crate::RF_LABEL_OWN_KP, OWN_KP_INDEX_KEY.to_vec(), encode(entries)?)
    }
}

#[openmls_traits::maybe_async(AFIT)]
impl<K: MlsKv> StorageProvider<CURRENT_VERSION> for MlsStorage<'_, K> {
    type Error = MlsKvError;

    async fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_JOIN_CONFIG, key_of(group_id)?, config)
    }

    async fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_TREE, key_of(group_id)?, tree)
    }

    async fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_INTERIM_TRANSCRIPT_HASH, key_of(group_id)?, interim_transcript_hash)
    }

    async fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_GROUP_CONTEXT, key_of(group_id)?, group_context)
    }

    async fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_CONFIRMATION_TAG, key_of(group_id)?, confirmation_tag)
    }

    async fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_MESSAGE_SECRETS, key_of(group_id)?, message_secrets)
    }

    async fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_RESUMPTION_PSK_STORE, key_of(group_id)?, resumption_psk_store)
    }

    async fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_OWN_LEAF_INDEX, key_of(group_id)?, own_leaf_index)
    }

    async fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_EPOCH_SECRETS, key_of(group_id)?, group_epoch_secrets)
    }

    async fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_GROUP_STATE, key_of(group_id)?, group_state)
    }

    async fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.rows.append(LABEL_OWN_LEAF_NODES, &key_of(group_id)?, leaf_node)
    }

    async fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_QUEUED_PROPOSAL, key_of(&(group_id, proposal_ref))?, proposal)?;
        self.rows.append(LABEL_PROPOSAL_QUEUE_REFS, &key_of(group_id)?, proposal_ref)
    }

    async fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        self.rows.write(
            LABEL_EPOCH_KEY_PAIRS,
            epoch_key_pairs_id(group_id, epoch, leaf_index)?,
            key_pairs,
        )
    }

    async fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_SIGNATURE_KEY_PAIR, key_of(public_key)?, signature_key_pair)
    }

    async fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_ENCRYPTION_KEY_PAIR, key_of(public_key)?, key_pair)
    }

    async fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_KEY_PACKAGE, key_of(hash_ref)?, key_package)
    }

    async fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.rows.write(LABEL_PSK, key_of(psk_id)?, psk)
    }

    async fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.rows.read(LABEL_JOIN_CONFIG, &key_of(group_id)?)
    }

    async fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.rows.read(LABEL_TREE, &key_of(group_id)?)
    }

    async fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.rows.read(LABEL_GROUP_CONTEXT, &key_of(group_id)?)
    }

    async fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.rows.read(LABEL_INTERIM_TRANSCRIPT_HASH, &key_of(group_id)?)
    }

    async fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.rows.read(LABEL_CONFIRMATION_TAG, &key_of(group_id)?)
    }

    async fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.rows.read(LABEL_MESSAGE_SECRETS, &key_of(group_id)?)
    }

    async fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.rows.read(LABEL_RESUMPTION_PSK_STORE, &key_of(group_id)?)
    }

    async fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.rows.read(LABEL_OWN_LEAF_INDEX, &key_of(group_id)?)
    }

    async fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.rows.read(LABEL_EPOCH_SECRETS, &key_of(group_id)?)
    }

    async fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.rows.read(LABEL_GROUP_STATE, &key_of(group_id)?)
    }

    async fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.rows.read_list(LABEL_OWN_LEAF_NODES, &key_of(group_id)?)
    }

    async fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.rows.read_list(LABEL_PROPOSAL_QUEUE_REFS, &key_of(group_id)?)
    }

    async fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> =
            self.rows.read_list(LABEL_PROPOSAL_QUEUE_REFS, &key_of(group_id)?)?;
        let mut proposals = Vec::with_capacity(refs.len().min(MAX_LIST_PREALLOC));
        for proposal_ref in refs {
            let proposal = self
                .rows
                .read(LABEL_QUEUED_PROPOSAL, &key_of(&(group_id, &proposal_ref))?)?
                .ok_or_else(|| MlsKvError::Codec("queued proposal row missing".to_owned()))?;
            proposals.push((proposal_ref, proposal));
        }
        Ok(proposals)
    }

    async fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        Ok(self
            .rows
            .read(LABEL_EPOCH_KEY_PAIRS, &epoch_key_pairs_id(group_id, epoch, leaf_index)?)?
            .unwrap_or_default())
    }

    async fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.rows.read(LABEL_SIGNATURE_KEY_PAIR, &key_of(public_key)?)
    }

    async fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.rows.read(LABEL_ENCRYPTION_KEY_PAIR, &key_of(public_key)?)
    }

    async fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.rows.read(LABEL_KEY_PACKAGE, &key_of(hash_ref)?)
    }

    async fn psk<
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
        PskId: traits::PskId<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.rows.read(LABEL_PSK, &key_of(psk_id)?)
    }

    async fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_OWN_LEAF_NODES, key_of(group_id)?)
    }

    async fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_JOIN_CONFIG, key_of(group_id)?)
    }

    async fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_TREE, key_of(group_id)?)
    }

    async fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_CONFIRMATION_TAG, key_of(group_id)?)
    }

    async fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_GROUP_STATE, key_of(group_id)?)
    }

    async fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_GROUP_CONTEXT, key_of(group_id)?)
    }

    async fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_INTERIM_TRANSCRIPT_HASH, key_of(group_id)?)
    }

    async fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_MESSAGE_SECRETS, key_of(group_id)?)
    }

    async fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_RESUMPTION_PSK_STORE, key_of(group_id)?)
    }

    async fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_OWN_LEAF_INDEX, key_of(group_id)?)
    }

    async fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_EPOCH_SECRETS, key_of(group_id)?)
    }

    async fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.rows.remove_item(LABEL_PROPOSAL_QUEUE_REFS, &key_of(group_id)?, proposal_ref)?;
        self.rows.delete(LABEL_QUEUED_PROPOSAL, key_of(&(group_id, proposal_ref))?)
    }

    async fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let key = key_of(group_id)?;
        let refs: Vec<ProposalRef> = self.rows.read_list(LABEL_PROPOSAL_QUEUE_REFS, &key)?;
        for proposal_ref in refs {
            self.rows.delete(LABEL_QUEUED_PROPOSAL, key_of(&(group_id, &proposal_ref))?)?;
        }
        self.rows.delete(LABEL_PROPOSAL_QUEUE_REFS, key)
    }

    async fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_EPOCH_KEY_PAIRS, epoch_key_pairs_id(group_id, epoch, leaf_index)?)
    }

    async fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        let key = key_of(hash_ref)?;
        self.own_kp_forget(&key)?;
        self.rows.delete(LABEL_KEY_PACKAGE, key)
    }

    async fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_PSK, key_of(psk_id)?)
    }

    async fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_SIGNATURE_KEY_PAIR, key_of(public_key)?)
    }

    async fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.rows.delete(LABEL_ENCRYPTION_KEY_PAIR, key_of(public_key)?)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify actual G1 operands against the closed SDK G2 record before shared selection.
use super::{FullPreparedReceiverDatabase, FullTransferStage, StorageError, wrong};
use ramflux_protocol::{
    canonical_json_bytes, custody::pairing::full_transfer::U64, encode_base64url, parse_i_json,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    local_account_id: String,
    account_anchor: String,
    origin: String,
    operation_id: String,
    record_hash: String,
    full_transfer: Full,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Full {
    chain_hash: String,
    db_relative_path: String,
    object_relative_path: String,
    stage_id: String,
    generation_nonce: String,
    expected_prior_generation: Prior,
    expected_prior_privacy_epoch: U64,
    initial_union_root: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prior {
    db_relative_path: String,
    object_relative_path: String,
}
impl FullPreparedReceiverDatabase {
    /// Select this exact verified G1 using the existing shared generation/index owner.
    /// Caller MUST own the SDK generation lease, independently verified acknowledged
    /// native publication and local vault operands, and keep admission closed through G3.
    /// This data primitive grants no publication, primary authority or ordinary admission.
    /// # Errors
    /// Refuses changed B/prepared bytes/objects/adoption, foreign metadata, paths or wrapping.
    /// Possible index outcomes are resolved by the underlying original-writer G2 primitive.
    pub fn commit_index_selection(
        &self,
        stage: &FullTransferStage<'_>,
        install: &crate::BackupIndexInstall<'_>,
        now: u64,
    ) -> Result<(), StorageError> {
        self.require_attested(stage)?;
        self.check_selection(stage, install, now)?;
        self.0.copy.observation.commit_prepared_generation(stage.db, install)
    }
    fn check_selection(
        &self,
        stage: &FullTransferStage<'_>,
        install: &crate::BackupIndexInstall<'_>,
        now: u64,
    ) -> Result<(), StorageError> {
        if install.manifest_json.len() > 4096 {
            return Err(wrong());
        }
        let marker: Selection = parse_i_json(install.manifest_json)?;
        if canonical_json_bytes(&marker)?.as_slice() != install.manifest_json {
            return Err(wrong());
        }
        let full = &marker.full_transfer;
        let own = &self.0.adoption;
        let old = &self.0.copy.observation;
        let union = self.0.copy.union.as_ref().ok_or_else(wrong)?;
        let root = stage.db.account_index.root();
        let duplex = stage.verified_duplex(now)?;
        if marker.schema != "ramflux.local.native_data_generation.v1"
            || marker.origin != "full_transfer"
            || marker.local_account_id != own.account_id
            || marker.account_anchor != stage.db.principal_commitment
            || marker.operation_id != own.operation_id
            || marker.record_hash != own.record_hash
            || install.account_id != own.account_id
            || install.principal_commitment != marker.account_anchor
            || install.db_relative_path != full.db_relative_path
            || install.object_relative_path != full.object_relative_path
            || root.join(&full.db_relative_path) != self.0.path
            || root.join(&full.object_relative_path)
                != self.0.path.parent().ok_or_else(wrong)?.join("objects")
            || full.stage_id != stage.reference().stage_id
            || full.generation_nonce != encode_base64url(union.generation_nonce)
            || full.initial_union_root != encode_base64url(union.chunks_root)
            || full.chain_hash != duplex.manifest_chain_hash()
            || full.expected_prior_generation.db_relative_path != old.prior_db_relative_path()
            || full.expected_prior_generation.object_relative_path
                != old.prior_object_relative_path()
            || full.expected_prior_privacy_epoch.0 != old.privacy_epoch()
        {
            return Err(wrong());
        }
        Ok(())
    }
}

/// Memory-only handback after this exact G2. It carries B's own key internally,
/// and the original root cancellation fence remains one-way across writer replacement.
/// It supplies no native authority, installed-file agreement or network admission.
pub struct FullSelectedReceiverGeneration {
    materialization: Materialization,
    index: std::sync::Arc<crate::AccountIndex>,
    marker: zeroize::Zeroizing<Vec<u8>>,
}
mod recovery;
pub use recovery::{FullGenerationRecoveryDraft, FullGenerationRecoveryWork};
enum Materialization {
    Prepared(Box<FullPreparedReceiverDatabase>),
    Recovered(Box<recovery::Recovered>),
}
struct SelectedDatabase<'a> {
    path: &'a std::path::Path,
    key: &'a crate::AccountDbKey,
    adoption: &'a crate::AdoptionRow,
    cancelled: &'a std::sync::atomic::AtomicBool,
}
impl FullPreparedReceiverDatabase {
    /// Select the verified G1 and issue a data-only owner for the exact new generation.
    /// Caller owns the same SDK/native/G3 obligations as `commit_index_selection`.
    /// # Errors
    /// Refuses changed prepared/current operands. An unknown G2 outcome remains fenced.
    pub fn select(
        self,
        stage: &FullTransferStage<'_>,
        install: &crate::BackupIndexInstall<'_>,
        now: u64,
    ) -> Result<FullSelectedReceiverGeneration, StorageError> {
        self.select_preserving(stage, install, now).map_err(|(_, error)| error)
    }
    /// Keep the exact unselected attempt available when optimistic B observation changes.
    /// # Errors
    /// Returns the original owner with the selection error; uncertain G2 stays fenced.
    pub fn select_preserving(
        self,
        stage: &FullTransferStage<'_>,
        install: &crate::BackupIndexInstall<'_>,
        now: u64,
    ) -> Result<FullSelectedReceiverGeneration, (Box<Self>, StorageError)> {
        let index = stage.db.account_index.clone();
        if let Err(error) = self.commit_index_selection(stage, install, now) {
            return Err((Box::new(self), error));
        }
        Ok(FullSelectedReceiverGeneration {
            materialization: Materialization::Prepared(Box::new(self)),
            index,
            marker: zeroize::Zeroizing::new(install.manifest_json.to_vec()),
        })
    }
}
impl FullSelectedReceiverGeneration {
    fn database(&self) -> SelectedDatabase<'_> {
        match &self.materialization {
            Materialization::Prepared(prepared) => SelectedDatabase {
                path: &prepared.0.path,
                key: &prepared.0.key,
                adoption: &prepared.0.adoption,
                cancelled: &prepared.0.cancelled,
            },
            Materialization::Recovered(recovered) => SelectedDatabase {
                path: &recovered.path,
                key: &recovered.key,
                adoption: &recovered.adoption,
                cancelled: &recovered.cancelled,
            },
        }
    }
    fn require_selected(&self) -> Result<(), StorageError> {
        if let Materialization::Recovered(recovered) = &self.materialization {
            recovered.unlock.require_unlocked()?;
        }
        let data = self.database();
        if data.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(StorageError::AuthorizationRejected);
        }
        let selected = self.index.account_generation_selection(&data.adoption.account_id)?;
        if selected.account.account_state != "active"
            || self.index.root().join(&selected.account.db_relative_path) != data.path
            || self.index.root().join(&selected.account.object_dir_relative_path)
                != data.path.parent().ok_or_else(wrong)?.join("objects")
            || selected.manifest_json.as_deref() != Some(self.marker.as_slice())
        {
            return Err(StorageError::PairingField("InstallPending"));
        }
        Ok(())
    }
    /// Reopen only the committed G2 using B's existing key and current epoch.
    /// Ordinary SDK admission MUST stay closed until G3 and all native/key owners agree.
    /// # Errors
    /// Refuses root lock/cancel, changed selection/marker, wrong adoption or key/schema errors.
    pub fn open(&self) -> Result<crate::AccountDb, StorageError> {
        self.require_selected()?;
        let data = self.database();
        let db = crate::AccountDb::open(&self.index, &data.adoption.account_id, data.key)?;
        self.require_database(&db)?;
        Ok(db)
    }
    /// Recheck a caller's current selected writer before its G3 handback.
    /// # Errors
    /// Refuses lock, stale/replaced writers, foreign path/key or changed adoption metadata.
    pub fn require_database(&self, db: &crate::AccountDb) -> Result<(), StorageError> {
        self.require_selected()?;
        let data = self.database();
        if db.path != data.path
            || db.local_account_id != data.adoption.account_id
            || db.pairing_adoption()?.as_ref() != Some(data.adoption)
        {
            return Err(wrong());
        }
        db.verify_key(data.key)?;
        db.full_local_unlock_guard()?.require_unlocked()?;
        self.require_selected()
    }
}

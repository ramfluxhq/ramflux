// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Positive G2 recovery revalidates encrypted retained provenance against selected bytes.
use super::{FullSelectedReceiverGeneration, Materialization, Selection, wrong};
use crate::{AccountDbKey, AdoptionRow, BackupDatabase, FullRecipientInstallStage, StorageError};
use ramflux_protocol::{canonical_json_bytes, encode_base64url, parse_i_json};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
use zeroize::Zeroizing;
pub(super) struct Recovered {
    pub(super) path: PathBuf,
    pub(super) key: AccountDbKey,
    pub(super) adoption: AdoptionRow,
    pub(super) cancelled: Arc<AtomicBool>,
    pub(super) unlock: crate::FullLocalUnlockGuard,
}
struct Retained {
    nonce: [u8; 32],
    digest: [u8; 32],
    workspace: String,
    key: Zeroizing<[u8; 32]>,
    root: [u8; 32],
    records: u64,
    bytes: u64,
}
impl FullRecipientInstallStage<'_> {
    /// Recover only an already selected G2 whose actual portable bytes match its
    /// encrypted retained qualified ledger. This restores no epoch or human approval.
    /// SDK must hold the generation owner and supply its own exact native acknowledgement.
    /// # Errors
    /// Refuses another selection/adoption/receipt, active private owner, corruption or lock.
    pub fn recover_selected_generation(
        &self,
        marker: &[u8],
        adoption: &AdoptionRow,
    ) -> Result<FullSelectedReceiverGeneration, StorageError> {
        if marker.len() > 4096 {
            return Err(wrong());
        }
        let value: Selection = parse_i_json(marker)?;
        if canonical_json_bytes(&value)?.as_slice() != marker {
            return Err(wrong());
        }
        let db = self.stage.db;
        let selected = db.account_index.account_generation_selection(&db.local_account_id)?;
        let record = self.stage.resume_record()?;
        let saved = retained(&self.stage)?;
        let full = &value.full_transfer;
        let duplex = self.verified_duplex()?;
        if saved.digest != record.stage_digest()?
            || value.schema != "ramflux.local.native_data_generation.v1"
            || value.origin != "full_transfer"
            || value.local_account_id != db.local_account_id
            || value.account_anchor != db.principal_commitment
            || value.operation_id != adoption.operation_id
            || value.record_hash != adoption.record_hash
            || adoption.account_id != db.local_account_id
            || adoption.local_role != "primary"
            || adoption.local_ref != canonical_json_bytes(&record.grant.destination_ref)?
            || adoption.full_generation_nonce.as_deref()
                != Some(encode_base64url(saved.nonce).as_str())
            || adoption.full_initial_union_root.as_deref()
                != Some(encode_base64url(saved.root).as_str())
            || db.pairing_adoption()?.as_ref() != Some(adoption)
            || full.generation_nonce != encode_base64url(saved.nonce)
            || full.initial_union_root != encode_base64url(saved.root)
            || full.stage_id != self.reference().stage_id
            || full.chain_hash != duplex.manifest_chain_hash()
            || selected.manifest_json.as_deref() != Some(marker)
            || selected.account.db_relative_path != full.db_relative_path
            || selected.account.object_dir_relative_path != full.object_relative_path
            || db.account_index.root().join(&full.db_relative_path) != db.path
        {
            return Err(wrong());
        }
        verify_selected(self, saved)?;
        let proof = FullSelectedReceiverGeneration {
            materialization: Materialization::Recovered(Box::new(Recovered {
                path: db.path.clone(),
                key: db.current_key.clone(),
                adoption: adoption.clone(),
                cancelled: self.stage.source_cancelled.clone(),
                unlock: db.full_local_unlock_guard()?,
            })),
            index: db.account_index.clone(),
            marker: Zeroizing::new(marker.to_vec()),
        };
        proof.require_database(db)?;
        Ok(proof)
    }
}
fn retained(stage: &crate::FullTransferStage<'_>) -> Result<Retained, StorageError> {
    Ok(stage.connection.query_row("SELECT g.generation_nonce,g.stage_digest,g.workspace,g.private_key,g.union_root,g.records,g.encoded_bytes FROM receiver_generation g JOIN receiver_receipt r ON g.manifest_hash=r.manifest_hash AND g.generation_nonce=r.generation_nonce WHERE g.singleton=1", [], |row| Ok(Retained {
        nonce: row.get(0)?, digest: row.get(1)?, workspace: row.get(2)?, key: Zeroizing::new(row.get(3)?),
        root: row.get(4)?, records: row.get(5)?, bytes: row.get(6)?,
    }))?)
}
fn verify_selected(
    stage: &FullRecipientInstallStage<'_>,
    saved: Retained,
) -> Result<(), StorageError> {
    let input = &stage.stage;
    input.verify_retained_receiver_application(stage.historical_time)?;
    let scratch = crate::account_db::full_transfer::receiver_scratch::Scratch::reopen_retained(
        &input.directory,
        &saved.workspace,
    )?;
    let key = AccountDbKey::from_bytes(*saved.key);
    let selected = BackupDatabase::open_full_receiver_copy(&input.db.path, &input.db.current_key)?;
    super::super::objects::verify(&input.db.path)?;
    let record = input.resume_record()?;
    let owners = [
        crate::account_db::mac_subkeys::full::source_key(&record.grant.source_ref)?,
        crate::account_db::mac_subkeys::full::source_key(&record.grant.destination_ref)?,
    ];
    let encoding = crate::FullUnionEncoding {
        generation_nonce: saved.nonce,
        records: saved.records,
        total_bytes: saved.bytes,
        chunks_root: saved.root,
    };
    crate::account_db::full_transfer::receiver_materialization::Verification {
        directory: &scratch.path,
        key: &key,
        encoding: &encoding,
        owners: &owners,
        private: &selected,
        private_key: &input.db.current_key,
        stage: input,
    }
    .run()?;
    Ok(())
}

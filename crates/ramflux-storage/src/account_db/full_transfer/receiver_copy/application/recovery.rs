// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reopen only the encrypted, source-qualified application ledger; never recapture B.
use super::*;
use crate::{AccountDbKey, BackupDatabase, FullUnionEncoding};
impl FullTransferStage<'_> {
    /// Revalidate the retained private application after its former owner has dropped.
    /// This checks durable private bytes and provenance, not current live bytes after
    /// later B writes, and restores no consent, publication, selection or tail grant.
    /// # Errors
    /// Refuses wrong scope/key/root/receipt, active owner, changed private rows or lost unlock.
    pub fn verify_retained_receiver_application(
        &self,
        now: u64,
    ) -> Result<FullUnionEncoding, StorageError> {
        self.require_io()?;
        self.verified_duplex(now)?;
        let record = self.resume_record()?;
        if record.role != ramflux_crypto::custody::pairing::PairingRole::Responder {
            return Err(wrong());
        }
        let metadata = self.connection.query_row(
            "SELECT g.generation_nonce,g.stage_digest,g.workspace,g.private_key,g.union_root,g.records,g.encoded_bytes FROM receiver_generation g JOIN receiver_receipt r ON g.manifest_hash=r.manifest_hash AND g.generation_nonce=r.generation_nonce WHERE singleton=1", [],
            |row| Ok((row.get::<_,[u8;32]>(0)?,row.get::<_,[u8;32]>(1)?,row.get::<_,String>(2)?,Zeroizing::new(row.get::<_,[u8;32]>(3)?),row.get::<_,[u8;32]>(4)?,row.get::<_,u64>(5)?,row.get::<_,u64>(6)?)),
        )?;
        let (nonce, digest, workspace, key, root, records, total_bytes) = metadata;
        if digest != record.stage_digest()? {
            return Err(wrong());
        }
        let scratch = super::super::super::receiver_scratch::Scratch::reopen_retained(
            &self.directory,
            &workspace,
        )?;
        let key = AccountDbKey::from_bytes(*key);
        let private =
            BackupDatabase::open_full_receiver_copy(&scratch.path.join("private.db"), &key)?;
        let encoding =
            FullUnionEncoding { generation_nonce: nonce, records, total_bytes, chunks_root: root };
        let owners = [
            crate::account_db::mac_subkeys::full::source_key(&record.grant.source_ref)?,
            crate::account_db::mac_subkeys::full::source_key(&record.grant.destination_ref)?,
        ];
        super::super::super::receiver_materialization::Verification {
            directory: &scratch.path,
            key: &key,
            encoding: &encoding,
            owners: &owners,
            private: &private,
            private_key: &key,
            stage: self,
        }
        .run()?;
        self.require_io()?;
        Ok(encoding)
    }
}

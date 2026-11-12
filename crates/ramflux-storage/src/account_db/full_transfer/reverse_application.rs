// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original A applies the new target's neutral reverse input before signing its DV.
use super::{FullAppliedDataReceipt, FullTransferStage};
use crate::StorageError;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::{
    custody::pairing::{
        PairingWire,
        context_v3::TranscriptV3,
        full_transfer::{ChainHasher, DataPacket, SourceManifest, manifest_hash},
    },
    encode_base64url,
};
use rusqlite::{OptionalExtension as _, params};

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS reverse_application(manifest_hash TEXT PRIMARY KEY,stage_digest BLOB NOT NULL,db_path TEXT NOT NULL,object_path TEXT NOT NULL,receipt BLOB);
CREATE TABLE IF NOT EXISTS reverse_source_receipt(manifest_hash TEXT PRIMARY KEY,bytes BLOB NOT NULL);";
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl FullTransferStage<'_> {
    pub(super) fn reverse_receipt(&self, now: u64) -> Result<FullAppliedDataReceipt, StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        let context = TranscriptV3::from_wire_bytes(&record.transcript).map_err(|_| wrong())?;
        if context.initiator.common.recipient_mode != "new" {
            return Err(StorageError::PairingField("UnsupportedRecord"));
        }
        let bytes: Vec<u8> = self.connection.query_row(
            "SELECT bytes FROM manifest WHERE direction=1 AND cut=0",
            [],
            |r| r.get(0),
        )?;
        let reverse = SourceManifest::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        let body = &reverse.manifest;
        if body.total_bytes.0 != 0
            || body.chunk_count.0 != 0
            || body.source_ref != record.grant.destination_ref
            || body.destination_ref != record.grant.source_ref
        {
            return Err(wrong());
        }
        let catalog = super::full_transfer_catalog()
            .iter()
            .map(super::FamilyRule::manifest_family)
            .collect::<Result<Vec<_>, _>>()?;
        body.validate_catalog(&catalog, true).map_err(|_| wrong())?;
        ramflux_crypto::verify_canonical_signature(
            &body.signing_bytes().map_err(|_| wrong())?,
            &reverse.source_signature,
            &record.grant.branch_keys.destination,
        )
        .map_err(|_| wrong())?;
        let root = super::stage::raw32(&body.chunks_root)?;
        if ramflux_protocol::custody::pairing::full_transfer::RootHasher::new(0)
            .map_err(|_| wrong())?
            .finish()
            .map_err(|_| wrong())?
            != root
        {
            return Err(wrong());
        }
        let hash = manifest_hash(&reverse).map_err(|_| wrong())?;
        let mut chain = ChainHasher::new(1).map_err(|_| wrong())?;
        chain.push(0, &hash, &root).map_err(|_| wrong())?;
        let expires_at = record.grant.expires_at.min(self.reference().lease_expires_at.0);
        if now >= expires_at {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        let digest = record.stage_digest()?;
        Ok(FullAppliedDataReceipt {
            role: PairingRole::Initiator,
            packet: DataPacket::DataVerified {
                manifest_hash: encode_base64url(hash),
                chunks_root: body.chunks_root.clone(),
                total_bytes: body.total_bytes,
                census_hash: body.census_hash.clone(),
                destination_ref: record.grant.source_ref,
                manifest_chain_hash: encode_base64url(chain.finish().map_err(|_| wrong())?),
                signature: encode_base64url([0; 64]),
            },
            nonce: [0; 32],
            applied_root: root,
            digest,
            branch_key: record.grant.branch_keys.source,
            expires_at,
        })
    }
    /// Commit the empty new-B restrictive input through A's actual current writer.
    /// A durable stage record follows the account transaction. A crash between them
    /// repeats the harmless application; it cannot create a signature or approval.
    /// # Errors
    /// Refuses another role, nonempty/foreign reverse, changed generation or failed commit.
    pub fn apply_empty_reverse(
        &mut self,
        now: u64,
    ) -> Result<FullAppliedDataReceipt, StorageError> {
        if self.resume_record()?.role != PairingRole::Initiator {
            return Err(wrong());
        }
        let proof = self.reverse_receipt(now)?;
        self.db.require_selected_transfer_source()?;
        self.db.connection.call(|raw| {
            let tx = raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // Neutral input must not erase or lower any existing A restriction/max.
            if tx.execute(
                "UPDATE account_erasure_generation SET generation=generation WHERE singleton=1",
                [],
            )? != 1
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            tx.commit()
        })?;
        self.db.require_selected_transfer_source()?;
        let selected = self.db.account_index.account(&self.db.local_account_id)?;
        let DataPacket::DataVerified { manifest_hash, .. } = proof.packet() else {
            return Err(wrong());
        };
        self.connection.execute("INSERT INTO reverse_application(manifest_hash,stage_digest,db_path,object_path) VALUES(?1,?2,?3,?4) ON CONFLICT(manifest_hash) DO UPDATE SET stage_digest=excluded.stage_digest,db_path=excluded.db_path,object_path=excluded.object_path", params![manifest_hash,proof.digest.as_slice(),selected.db_relative_path,selected.object_dir_relative_path])?;
        super::stage::sync_stage(&self.directory)?;
        self.require_io()?;
        Ok(proof)
    }
    /// Persist A's exact signed application receipt before it is sent to B.
    /// # Errors
    /// Refuses foreign signer/body, missing application, expired scope or changed selection.
    pub fn record_reverse_application_receipt(
        &mut self,
        proof: &FullAppliedDataReceipt,
        packet: &DataPacket,
        now: u64,
    ) -> Result<(), StorageError> {
        if self.resume_record()?.role != PairingRole::Initiator
            || proof.expected_role() != PairingRole::Initiator
            || proof.digest != self.resume_record()?.stage_digest()?
            || now >= proof.expires_at()
        {
            return Err(wrong());
        }
        let DataPacket::DataVerified { manifest_hash, signature, .. } = packet else {
            return Err(wrong());
        };
        let bytes = packet.encode_secret().map_err(|_| wrong())?;
        if proof.signed_packet(signature.clone())?.encode_secret().map_err(|_| wrong())?.as_slice()
            != bytes.as_slice()
        {
            return Err(wrong());
        }
        self.db.require_selected_transfer_source()?;
        let selected = self.db.account_index.account(&self.db.local_account_id)?;
        let hash = manifest_hash.clone();
        let digest = proof.digest;
        self.connection.call(move |raw| {
            let tx=raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if tx.execute("UPDATE reverse_application SET receipt=?1 WHERE manifest_hash=?2 AND stage_digest=?3 AND db_path=?4 AND object_path=?5 AND (receipt IS NULL OR receipt=?1)",params![bytes.as_slice(),hash,digest.as_slice(),selected.db_relative_path,selected.object_dir_relative_path])? != 1 { return Err(rusqlite::Error::InvalidQuery); }
            if tx.execute("UPDATE manifest SET verified=1,root_verified=1 WHERE direction=1 AND manifest_hash=?1",params![hash])? != 1 { return Err(rusqlite::Error::InvalidQuery); }
            tx.commit()
        })?;
        super::stage::sync_stage(&self.directory)?;
        self.require_io()
    }
    /// B independently verifies and durably retains original A's reverse DV.
    /// This gives no native publication, candidate or ordinary admission permission.
    /// # Errors
    /// Refuses a peer boolean, wrong body/key, expiry or changed exact retries.
    pub fn record_reverse_source_receipt(
        &mut self,
        packet: &DataPacket,
        now: u64,
    ) -> Result<(), StorageError> {
        if self.resume_record()?.role != PairingRole::Responder {
            return Err(wrong());
        }
        let expected = self.reverse_receipt(now)?;
        let DataPacket::DataVerified { manifest_hash, signature, .. } = packet else {
            return Err(wrong());
        };
        let bytes = packet.encode_secret().map_err(|_| wrong())?;
        if expected
            .signed_packet(signature.clone())?
            .encode_secret()
            .map_err(|_| wrong())?
            .as_slice()
            != bytes.as_slice()
        {
            return Err(wrong());
        }
        let hash = manifest_hash.clone();
        self.connection.call(move |raw| {
            let tx=raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let old:Option<Vec<u8>>=tx.query_row("SELECT bytes FROM reverse_source_receipt WHERE manifest_hash=?1",params![hash],|r|r.get(0)).optional()?;
            if old.is_some_and(|old| old.as_slice()!=bytes.as_slice()) {return Err(rusqlite::Error::InvalidQuery);}
            tx.execute("INSERT INTO reverse_source_receipt VALUES(?1,?2) ON CONFLICT(manifest_hash) DO NOTHING",params![hash,bytes.as_slice()])?;
            tx.commit()
        })?;
        super::stage::sync_stage(&self.directory)?;
        self.require_io()
    }
}

#[cfg(test)]
mod tests {
    use super::super::receiver_projection::tests::{db, input, seed};
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn stages<'a>(
        a: &'a crate::AccountDb,
        b: &'a crate::AccountDb,
    ) -> Result<
        (FullTransferStage<'a>, FullTransferStage<'a>, SourceManifest),
        Box<dyn std::error::Error>,
    > {
        let (record, forward, _) = input(a)?;
        let source_record = ramflux_crypto::custody::pairing::FullResumeRecord {
            role: PairingRole::Initiator,
            transcript: record.transcript.clone(),
            th: record.th,
            grant: record.grant.clone(),
            lease: record.lease.clone(),
            transfer_id: record.transfer_id.clone(),
            base_manifest_hash: record.base_manifest_hash.clone(),
            base_record_hash: record.base_record_hash.clone(),
        };
        let catalog = super::super::full_transfer_catalog()
            .iter()
            .map(super::super::FamilyRule::manifest_family)
            .collect::<Result<Vec<_>, _>>()?;
        let mut target = b.create_full_stage_for_test(record, 604_900)?;
        let mut source = a.create_full_stage_for_test(source_record, 604_900)?;
        target.retain_forward_manifest(&forward, &catalog)?;
        source.retain_manifest_for_role(&forward, &catalog, PairingRole::Initiator)?;
        let body = target.prepare_empty_reverse_manifest()?;
        let reverse = SourceManifest {
            source_signature: ramflux_crypto::sign_canonical_bytes_with_seed(
                &body.signing_bytes()?,
                [8; 32],
            ),
            manifest: body,
        };
        target.retain_reverse_manifest(&reverse, &catalog)?;
        source.retain_reverse_manifest(&reverse, &catalog)?;
        Ok((source, target, forward))
    }

    #[test]
    fn pairing_full_empty_reverse_application_requires_current_a_commit_before_exact_signed_dv()
    -> TestResult {
        let (initial, _, _) = super::super::stage_tests::fixture()?;
        let (aroot, a) = db("reverse-apply-a", &initial.grant.source_ref.account_anchor)?;
        let (broot, b) = db("reverse-apply-b", &initial.grant.destination_ref.account_anchor)?;
        seed(&a, 21, 9)?;
        let (mut source, mut target, forward) = stages(&a, &b)?;
        // Application must touch the ACTUAL A generation, not merely encrypted stage SQL.
        a.connection.execute_batch("CREATE TRIGGER fail_reverse_application BEFORE UPDATE ON account_erasure_generation BEGIN SELECT RAISE(ABORT,'refuse reverse application'); END;")?;
        assert!(
            source.apply_empty_reverse(1000).is_err(),
            "stage metadata bypassed the actual A commit"
        );
        assert_eq!(
            source
                .connection
                .query_row("SELECT count(*) FROM reverse_application", [], |r| r
                    .get::<_, u64>(0))?,
            0
        );
        a.connection.execute_batch("DROP TRIGGER fail_reverse_application")?;
        let proof = source.apply_empty_reverse(1000)?;
        assert!(
            proof
                .signed_packet(ramflux_crypto::sign_canonical_bytes_with_seed(
                    &proof.packet().data_verified_signing_bytes()?,
                    [8; 32]
                ))
                .is_err(),
            "B signed its own reverse application"
        );
        let packet = proof.signed_packet(ramflux_crypto::sign_canonical_bytes_with_seed(
            &proof.packet().data_verified_signing_bytes()?,
            [7; 32],
        ))?;
        source.connection.execute("DELETE FROM reverse_application", [])?;
        assert!(
            source.record_reverse_application_receipt(&proof, &packet, 1000).is_err(),
            "missing durable application accepted"
        );
        let proof = source.apply_empty_reverse(1000)?;
        source.record_reverse_application_receipt(&proof, &packet, 1000)?;
        target.record_reverse_source_receipt(&packet, 1000)?;
        target.record_reverse_source_receipt(&packet, 1000)?;
        let DataPacket::DataVerified { destination_ref, .. } = &packet else {
            return Err("DV arm".into());
        };
        assert_eq!(destination_ref, &forward.manifest.source_ref);
        assert_eq!(
            a.connection.query_row(
                "SELECT generation FROM account_erasure_generation",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            9,
            "empty reverse lowered A's veto maximum"
        );
        assert_eq!(
            a.connection.query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r
                .get::<_, u64>(0))?,
            1
        );
        assert_eq!(
            source.connection.query_row(
                "SELECT verified FROM manifest WHERE direction=1",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            1
        );
        assert_eq!(
            target.connection.query_row(
                "SELECT count(*) FROM reverse_source_receipt",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            1
        );
        // Forward data has not been received or applied merely because reverse completed.
        assert_eq!(
            target.connection.query_row(
                "SELECT verified FROM manifest WHERE direction=0",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        drop(source);
        drop(target);
        drop(a);
        drop(b);
        std::fs::remove_dir_all(aroot)?;
        std::fs::remove_dir_all(broot)?;
        Ok(())
    }
}

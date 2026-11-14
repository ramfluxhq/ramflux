// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! OVP-23 reverse metadata admission, not a reverse application/DV owner.
use super::FullTransferStage;
use crate::StorageError;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    context_v3::TranscriptV3,
    full_transfer::{Family, ManifestKind, RootHasher, SourceManifest, manifest_hash},
};
use rusqlite::{OptionalExtension as _, params};
use zeroize::Zeroizing;

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
impl FullTransferStage<'_> {
    /// Reuse the exact once-only reverse metadata after data-only reconnect.
    /// # Errors
    /// Refuses corrupt original signatures, foreign context or stale local unlock.
    pub fn retained_reverse_manifest(&self) -> Result<Option<SourceManifest>, StorageError> {
        self.require_io()?;
        let hash: Option<String> = self
            .connection
            .query_row(
                "SELECT manifest_hash FROM manifest WHERE direction=1 AND cut=0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        hash.map(|hash| self.reverse_manifest(&hash)).transpose()
    }
    /// Prepare the new recipient's empty reverse manifest from its OWN consistent cut,
    /// only after the forward base was retained. No raw snapshot file/key is returned.
    /// Every actual nonempty owner must be declared, and no restrictive family may be
    /// omitted by claiming a peer-supplied zero count. The signer must durably retain the
    /// signed object with `retain_reverse_manifest` before sending; that freezes it once.
    /// This creates neither a signature nor an applied/DV marker.
    /// # Errors
    /// Refuses another role/mode, unsupported or non-neutral restrictive state, a foreign
    /// census, missing forward base, a stale/locked cut or failed local reads.
    pub fn prepare_empty_reverse_manifest(
        &self,
    ) -> Result<ramflux_protocol::custody::pairing::full_transfer::Manifest, StorageError> {
        use ramflux_crypto::custody::pairing::PairingRole;
        use ramflux_protocol::custody::pairing::full_transfer::{CHUNK_BYTES, Manifest, U64};
        self.require_io()?;
        let record = self.resume_record()?;
        let context = TranscriptV3::from_wire_bytes(&record.transcript).map_err(|_| mismatch())?;
        if record.role != PairingRole::Responder || context.initiator.common.recipient_mode != "new"
        {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let forward = self.forward_manifest(&record.base_manifest_hash)?;
        let existing = self
            .connection
            .query_row("SELECT bytes FROM manifest WHERE direction=1 AND cut=0", [], |row| {
                Ok(Zeroizing::new(row.get::<_, Vec<u8>>(0)?))
            })
            .optional()?;
        if let Some(bytes) = existing {
            let saved = SourceManifest::from_wire_bytes(&bytes).map_err(|_| mismatch())?;
            self.require_io()?;
            return Ok(saved.manifest);
        }
        let cut = self.db.pin_full_transfer_cut()?;
        let (schema, storage_generation, erasure_generation) = cut.inspect_full_profile_cut()?;
        schema.require_typed_owners(super::full_transfer_catalog())?;
        // Fresh stores contain the zero erasure-generation singleton and a local MAC
        // verifier bundle. Zero does not advance a max-generation floor; verifier keys
        // alone express no veto when EVERY other restrictive owner is empty. Preserve
        // their actual source_rows in metadata, but emit no reverse records (OVP-23).
        if erasure_generation != 0
            || schema.families.iter().any(|family| {
                family.restrictive
                    && family.source_rows.0 > 0
                    && match family.id.as_str() {
                        "sql/account_erasure_generation" => family.source_rows.0 != 1,
                        "sql/account_mac_bundle/portable" => false,
                        _ => true,
                    }
            })
        {
            return Err(StorageError::PairingField("UnsupportedRecord"));
        }
        if ramflux_protocol::encode_base64url(schema.census_hash) != forward.manifest.census_hash {
            return Err(StorageError::PairingField("SchemaMismatch"));
        }
        let families = schema.families.into_iter().filter(|family| family.restrictive).collect();
        let manifest = Manifest {
            schema: "ramflux.pairing.full_transfer.manifest.v1".into(),
            version: 1,
            transfer_id: record.transfer_id,
            account_anchor: forward.manifest.account_anchor,
            source_ref: record.grant.destination_ref,
            destination_ref: record.grant.source_ref,
            base_record_hash: record.base_record_hash,
            snapshot_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            snapshot_cut: U64(0),
            previous_cut: None,
            parent_manifest_hash: None,
            kind: ManifestKind::Base,
            source_erasure_generation: U64(erasure_generation),
            storage_generation: U64(storage_generation),
            census_hash: forward.manifest.census_hash,
            families,
            total_bytes: U64(0),
            chunk_bytes: U64(u64::from(CHUNK_BYTES)),
            chunk_count: U64(0),
            chunks_root: ramflux_protocol::encode_base64url(
                RootHasher::new(0).map_err(|_| mismatch())?.finish().map_err(|_| mismatch())?,
            ),
            attachment_policy: "remote_ciphertext".into(),
        };
        manifest.validate().map_err(|_| mismatch())?;
        self.require_io()?;
        Ok(manifest)
    }
    /// Retain B's one original-branch-signed reverse base, with references inverted from
    /// this endpoint's OWN saved forward base. The catalog comes from the local owner.
    /// Exact retries are idempotent; a different reverse object never replaces the first.
    /// This validates metadata/signature only and sets neither root nor semantic verified.
    /// Native freshness, actual B snapshot completeness, receipt durability and restrictive
    /// application before a signed reverse `DataVerified` remain separate endpoint gates.
    /// # Errors
    /// Refuses foreign scope/key/catalog, non-base/recut objects, nonempty new-B streams,
    /// changed retries, missing forward base, cancellation or failed durable storage.
    pub fn retain_reverse_manifest(
        &mut self,
        manifest: &SourceManifest,
        catalog: &[Family],
    ) -> Result<(), StorageError> {
        self.require_io()?;
        manifest.validate().map_err(|_| mismatch())?;
        manifest
            .manifest
            .validate_catalog(catalog, true)
            .map_err(|_| StorageError::PairingField("SchemaMismatch"))?;
        let record = self.resume_record()?;
        let forward =
            self.forward_manifest(&record.base_manifest_hash).map_err(|error| match error {
                StorageError::Sqlite(rusqlite::Error::QueryReturnedNoRows) => mismatch(),
                other => other,
            })?;
        let base = &forward.manifest;
        let body = &manifest.manifest;
        if base.kind != ManifestKind::Base
            || body.kind != ManifestKind::Base
            || body.source_ref != record.grant.destination_ref
            || body.destination_ref != record.grant.source_ref
            || body.transfer_id != record.transfer_id
            || body.account_anchor != base.account_anchor
            || body.base_record_hash != base.base_record_hash
            || body.census_hash != base.census_hash
        {
            return Err(mismatch());
        }
        let context = TranscriptV3::from_wire_bytes(&record.transcript).map_err(|_| mismatch())?;
        if context.initiator.common.recipient_mode == "new"
            && (body.total_bytes.0 != 0
                || body
                    .families
                    .iter()
                    .any(|family| family.portable_records.0 != 0 || family.encoded_bytes.0 != 0)
                || body.chunks_root
                    != ramflux_protocol::encode_base64url(
                        RootHasher::new(0)
                            .map_err(|_| mismatch())?
                            .finish()
                            .map_err(|_| mismatch())?,
                    ))
        {
            return Err(mismatch());
        }
        ramflux_crypto::verify_canonical_signature(
            &body.signing_bytes().map_err(|_| mismatch())?,
            &manifest.source_signature,
            &record.grant.branch_keys.destination,
        )
        .map_err(|_| mismatch())?;
        let bytes = Zeroizing::new(manifest.to_wire_bytes().map_err(|_| mismatch())?);
        let existing = self
            .connection
            .query_row("SELECT bytes FROM manifest WHERE direction=1 AND cut=0", [], |row| {
                Ok(Zeroizing::new(row.get::<_, Vec<u8>>(0)?))
            })
            .optional()?;
        if let Some(existing) = existing {
            self.require_io()?;
            return if existing.as_slice() == bytes.as_slice() { Ok(()) } else { Err(mismatch()) };
        }
        let hash =
            ramflux_protocol::encode_base64url(manifest_hash(manifest).map_err(|_| mismatch())?);
        self.require_io()?;
        self.connection.execute("INSERT INTO manifest(direction,cut,manifest_hash,kind,bytes,chunks_root,verified) VALUES(1,0,?1,'base',?2,?3,0)",params![hash,bytes.as_slice(),body.chunks_root])?;
        super::stage::sync_stage(&self.directory)?;
        self.require_io()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_protocol::{
        custody::pairing::full_transfer::{CHUNK_BYTES, U64},
        encode_base64url,
    };
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn sign(manifest: &mut SourceManifest, seed: u8) -> Result<(), Box<dyn std::error::Error>> {
        manifest.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &manifest.manifest.signing_bytes()?,
            [seed; 32],
        );
        Ok(())
    }
    #[test]
    fn pairing_full_empty_reverse_uses_own_pinned_cut_and_keeps_first_snapshot() -> TestResult {
        let (_root, db) = crate::tests::test_db("reverse-empty-own-cut")?;
        let (mut record, mut forward, _) = super::super::stage_tests::fixture()?;
        let rules = super::super::full_transfer_catalog();
        let catalog = rules
            .iter()
            .map(super::super::FamilyRule::manifest_family)
            .collect::<Result<Vec<_>, _>>()?;
        forward.manifest.families = catalog.clone();
        forward.manifest.census_hash = encode_base64url(super::super::full_census_hash(rules)?);
        forward.manifest.total_bytes = U64(0);
        forward.manifest.chunk_count = U64(0);
        forward.manifest.chunks_root = encode_base64url(RootHasher::new(0)?.finish()?);
        sign(&mut forward, 7)?;
        record.base_manifest_hash = encode_base64url(manifest_hash(&forward)?);
        let mut stage = db.create_full_stage_for_test(record, 604_900)?;
        stage.retain_forward_manifest(&forward, &catalog)?;
        let commitment =
            ramflux_crypto::object_erasure_commitment("root", "reverse-veto", "manifest");
        db.connection
            .execute("INSERT INTO object_identity_replacement VALUES(?1)", params![&commitment])?;
        assert!(
            matches!(
                stage.prepare_empty_reverse_manifest(),
                Err(StorageError::PairingField("UnsupportedRecord"))
            ),
            "new B's own restrictive row was silently omitted"
        );
        // Reset only the row introduced by this negative, before the first cut is emitted.
        db.connection.execute(
            "DELETE FROM object_identity_replacement WHERE commitment=?1",
            params![&commitment],
        )?;
        db.connection
            .execute("UPDATE account_erasure_generation SET generation=1 WHERE singleton=1", [])?;
        assert!(
            matches!(
                stage.prepare_empty_reverse_manifest(),
                Err(StorageError::PairingField("UnsupportedRecord"))
            ),
            "nonzero privacy generation was treated as an empty reverse"
        );
        db.connection
            .execute("UPDATE account_erasure_generation SET generation=0 WHERE singleton=1", [])?;
        let body = stage.prepare_empty_reverse_manifest()?;
        assert_eq!(body.total_bytes.0, 0);
        let verifier = body
            .families
            .iter()
            .find(|family| family.id == "sql/account_mac_bundle/portable")
            .ok_or("reverse verifier family")?;
        assert!(verifier.source_rows.0 > 0, "metadata hid initialized verifier rows");
        assert_eq!(verifier.portable_records.0, 0, "unused verifier became a restrictive record");
        assert_eq!(body.source_ref, forward.manifest.destination_ref);
        assert_eq!(body.destination_ref, forward.manifest.source_ref);
        let mut reverse = SourceManifest { manifest: body, source_signature: String::new() };
        sign(&mut reverse, 8)?;
        stage.retain_reverse_manifest(&reverse, &catalog)?;
        db.connection
            .execute("INSERT INTO object_identity_replacement VALUES(?1)", params![&commitment])?;
        assert_eq!(
            stage.prepare_empty_reverse_manifest()?,
            reverse.manifest,
            "later B writes recut the frozen reverse"
        );
        assert_eq!(
            stage.connection.query_row(
                "SELECT verified FROM manifest WHERE direction=1",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            0,
            "preparation granted semantic verification"
        );
        Ok(())
    }
    #[test]
    fn pairing_full_reverse_manifest_is_sas_pinned_inverted_and_never_recut() -> TestResult {
        let (_root, db) = crate::tests::test_db("reverse-admission")?;
        let (mut record, mut forward, _) = super::super::stage_tests::fixture()?;
        forward.manifest.families[0].restrictive = true;
        sign(&mut forward, 7)?;
        record.base_manifest_hash = encode_base64url(manifest_hash(&forward)?);
        let mut stage = db.create_full_stage_for_test(record, 604_900)?;
        let catalog = forward.manifest.families.clone();
        let mut reverse = forward.clone();
        std::mem::swap(&mut reverse.manifest.source_ref, &mut reverse.manifest.destination_ref);
        reverse.manifest.snapshot_id = encode_base64url([66; 32]);
        reverse.manifest.total_bytes = U64(0);
        reverse.manifest.chunk_count = U64(0);
        reverse.manifest.chunks_root = encode_base64url(RootHasher::new(0)?.finish()?);
        for family in &mut reverse.manifest.families {
            family.source_rows = U64(0);
            family.portable_records = U64(0);
            family.encoded_bytes = U64(0);
        }
        sign(&mut reverse, 8)?;
        assert!(
            stage.retain_reverse_manifest(&reverse, &catalog).is_err(),
            "reverse admitted without own forward base"
        );
        stage.retain_forward_manifest(&forward, &catalog)?;
        let mut wrong = reverse.clone();
        sign(&mut wrong, 7)?;
        assert!(
            stage.retain_reverse_manifest(&wrong, &catalog).is_err(),
            "A key impersonated B reverse signer"
        );
        wrong = reverse.clone();
        std::mem::swap(&mut wrong.manifest.source_ref, &mut wrong.manifest.destination_ref);
        sign(&mut wrong, 8)?;
        assert!(
            stage.retain_reverse_manifest(&wrong, &catalog).is_err(),
            "forward refs admitted as reverse"
        );
        wrong = reverse.clone();
        wrong.manifest.census_hash = encode_base64url([99; 32]);
        sign(&mut wrong, 8)?;
        assert!(
            stage.retain_reverse_manifest(&wrong, &catalog).is_err(),
            "foreign census admitted"
        );
        wrong = forward.clone();
        std::mem::swap(&mut wrong.manifest.source_ref, &mut wrong.manifest.destination_ref);
        sign(&mut wrong, 8)?;
        assert!(
            stage.retain_reverse_manifest(&wrong, &catalog).is_err(),
            "new B admitted a nonempty reverse stream"
        );
        stage.retain_reverse_manifest(&reverse, &catalog)?;
        stage.retain_reverse_manifest(&reverse, &catalog)?;
        wrong = reverse.clone();
        wrong.manifest.snapshot_id = encode_base64url([67; 32]);
        sign(&mut wrong, 8)?;
        assert!(
            stage.retain_reverse_manifest(&wrong, &catalog).is_err(),
            "reverse recut replaced frozen snapshot"
        );
        let (count, root, verified): (u64, u64, u64) = stage.connection.query_row(
            "SELECT count(*),sum(root_verified),sum(verified) FROM manifest WHERE direction=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(
            (count, root, verified),
            (1, 0, 0),
            "metadata admission granted application/root verification"
        );
        assert_eq!(reverse.manifest.chunk_bytes, U64(u64::from(CHUNK_BYTES)));
        Ok(())
    }
}

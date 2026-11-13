// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::account_db::full_transfer::receiver_projection::tests::{input, seed};
    use crate::{AccountDb, AccountDbKey, AccountIndex};
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn open(root: &std::path::Path, anchor: &str) -> Result<AccountDb, StorageError> {
        let index = AccountIndex::open(root)?;
        index.create_account("acct", anchor)?;
        AccountDb::open(
            &index,
            "acct",
            &AccountDbKey::derive("acct", b"test-private-file-incarnation"),
        )
    }
    #[test]
    fn pairing_full_dv_refuses_replaced_private_files_after_off_loan_validation() -> TestResult {
        let left = tempfile::TempDir::new()?;
        let right = tempfile::TempDir::new()?;
        let (initial, _, _) = crate::account_db::full_transfer::stage_tests::fixture()?;
        let a = open(left.path(), &initial.grant.source_ref.account_anchor)?;
        let b = open(right.path(), &initial.grant.destination_ref.account_anchor)?;
        seed(&a, 11, 8)?;
        seed(&b, 21, 9)?;
        let (record, manifest, bytes) = input(&a)?;
        let hash = record.base_manifest_hash.clone();
        let mut stage = b.create_full_stage_for_test(record, 604_900)?;
        stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
        for (index, chunk) in bytes
            .chunks(ramflux_protocol::custody::pairing::full_transfer::CHUNK_BYTES as usize)
            .enumerate()
        {
            stage.retain_forward_chunk(&hash, u64::try_from(index)?, chunk)?;
        }
        let mut copy = stage.pin_receiver_base(&hash)?.copy()?;
        copy.project(&stage)?;
        let private = copy.scratch.path.join("private.db");
        let replacement = copy.scratch.path.join("replacement.db");
        std::fs::copy(&private, &replacement)?;
        std::fs::rename(&replacement, &private)?;
        assert!(
            copy.commit_application(&mut stage, 1000).is_err(),
            "test: a replaced private file reused stale physical verification"
        );
        assert_eq!(
            stage
                .connection
                .query_row("SELECT count(*) FROM receiver_generation", [], |row| row
                    .get::<_, u64>(0))?,
            0,
            "test: refused file replacement retained an application key"
        );
        // A fresh actual byte/root check may establish a new data-only observation.
        copy.verify_materialization(&stage)?;
        let proof = copy.commit_application(&mut stage, 1000)?;
        let signed = proof.signed_packet(ramflux_crypto::sign_canonical_bytes_with_seed(
            &proof.packet().data_verified_signing_bytes()?,
            [8; 32],
        ))?;
        copy.record_data_verified(&mut stage, &proof, &signed, 1000)?;
        assert_eq!(
            stage.connection.query_row(
                "SELECT count(*) FROM manifest WHERE verified=1",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            1,
            "test: fresh verified bytes could not commit the original B DV"
        );
        Ok(())
    }
}

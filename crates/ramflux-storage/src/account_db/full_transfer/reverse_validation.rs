// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete restrictive input validation before any actual A merge or signed semantic receipt.
use super::{FullTransferStage, copy_full_scalar_record, full_census_hash, full_transfer_catalog};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{RecordOp, read_record_header};
use zeroize::{Zeroize as _, Zeroizing};
fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
struct Header(ramflux_protocol::custody::pairing::full_transfer::RecordHeader);
impl Drop for Header {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}
impl FullTransferStage<'_> {
    /// Verify the whole B-signed reverse input against locally compiled restrictive owners.
    /// Root, sorted unique keys, exact put-only cells and complete family counts/lengths
    /// are rechecked. No row is applied and no DV/application marker is written here.
    /// # Errors
    /// Refuses nonrestrictive/unknown owners, malformed records, wrong counts or lost unlock.
    pub fn validate_reverse_fixed_records(&self, hash: &str) -> Result<(), StorageError> {
        self.require_io()?;
        let manifest = self.reverse_manifest(hash)?;
        let mut reader = self.reverse_reader(hash)?;
        let guard =
            super::source_scalar::SourceGuard::new(self.db, Some(self.source_cancelled.clone()));
        validate_input(&mut reader, &manifest, &guard)?;
        self.require_io()
    }
}
fn validate_input(
    reader: &mut (impl std::io::Read + std::io::Seek),
    manifest: &ramflux_protocol::custody::pairing::full_transfer::SourceManifest,
    guard: &super::source_scalar::SourceGuard,
) -> Result<(), StorageError> {
    let body = &manifest.manifest;
    let rules = full_transfer_catalog();
    let catalog =
        rules.iter().map(super::FamilyRule::manifest_family).collect::<Result<Vec<_>, _>>()?;
    body.validate_catalog(&catalog, true).map_err(|_| mismatch())?;
    if body.census_hash != ramflux_protocol::encode_base64url(full_census_hash(rules)?) {
        return Err(StorageError::PairingField("SchemaMismatch"));
    }
    let mut counts = vec![(0_u64, 0_u64); rules.len()];
    let mut previous: Option<(usize, Zeroizing<String>)> = None;

    loop {
        let start = reader.stream_position()?;
        let Some(header) = read_record_header(reader).map_err(|_| mismatch())? else {
            break;
        };
        let header = Header(header);
        guard.require()?;
        let index = rules
            .binary_search_by_key(&header.0.family.as_str(), |rule| rule.id)
            .map_err(|_| StorageError::PairingField("UnsupportedRecord"))?;
        let rule = rules.get(index).ok_or_else(mismatch)?;
        if !rule.restrictive
            || header.0.op != RecordOp::Put
            || previous.as_ref().is_some_and(|(old, key)| {
                *old > index || (*old == index && key.as_str() >= header.0.key.as_str())
            })
        {
            return Err(mismatch());
        }
        let family =
            body.families.iter().find(|family| family.id == rule.id).ok_or_else(mismatch)?;
        copy_full_scalar_record(rule, &header.0, reader, &mut std::io::sink())?;
        let encoded = reader.stream_position()?.checked_sub(start).ok_or_else(mismatch)?;
        let count = counts.get_mut(index).ok_or_else(mismatch)?;
        count.0 = count.0.checked_add(1).ok_or_else(mismatch)?;
        count.1 = count.1.checked_add(encoded).ok_or_else(mismatch)?;
        if count.0 > family.portable_records.0 || count.1 > family.encoded_bytes.0 {
            return Err(mismatch());
        }
        previous = Some((index, Zeroizing::new(header.0.key.clone())));
    }
    for family in &body.families {
        let index = rules
            .binary_search_by_key(&family.id.as_str(), |rule| rule.id)
            .map_err(|_| mismatch())?;
        if counts.get(index) != Some(&(family.portable_records.0, family.encoded_bytes.0)) {
            return Err(mismatch());
        }
    }
    if reader.stream_position()? != body.total_bytes.0 {
        return Err(mismatch());
    }
    guard.require()
}
mod work;
pub use work::{FullReverseValidationWork, FullValidatedReverseInput};

#[cfg(test)]
mod tests;

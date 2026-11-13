// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Input validation only. Semantic merge/application must precede durable `DataVerified`.
use super::{FamilyRule, FullTransferStage, copy_full_scalar_record, full_census_hash};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{
    Disposition, ManifestKind, RecordHeader, RecordOp, StreamError, read_record_header,
};
use std::io::Seek as _;
use zeroize::{Zeroize as _, Zeroizing};

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
fn stream_error(error: StreamError) -> StorageError {
    match error {
        StreamError::Io(error) => StorageError::Io(error),
        _ => mismatch(),
    }
}
struct PrivateHeader(RecordHeader);
impl Drop for PrivateHeader {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}
impl FullTransferStage<'_> {
    /// Validate the complete retained scalar stream against locally compiled declarations.
    /// This verifies logical input, not native documents, application/union or attachments;
    /// it deliberately never sets `verified` or authorizes a signed `DataVerified`.
    /// # Errors
    /// Refuses unknown/non-scalar owners, catalog/census mismatch, malformed records,
    /// duplicate/reordered keys, base absences, incorrect counts/bytes or corrupt slots.
    pub fn validate_forward_scalar_records(
        &self,
        hash: &str,
        rules: &[FamilyRule],
    ) -> Result<(), StorageError> {
        self.visit_forward_scalar_records(hash, rules, |_, _, _| Ok(()))
    }

    pub(super) fn visit_forward_scalar_records(
        &self,
        hash: &str,
        rules: &[FamilyRule],
        visit: impl FnMut(&RecordHeader, u64, u64) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        visit_input(self, hash, rules, visit)
    }
}
pub(super) fn visit_input(
    stage: &impl super::receiver_read::ReceiverInput,
    hash: &str,
    rules: &[FamilyRule],
    mut visit: impl FnMut(&RecordHeader, u64, u64) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let manifest = stage.forward_manifest(hash)?;
    let body = &manifest.manifest;
    let catalog = rules.iter().map(FamilyRule::manifest_family).collect::<Result<Vec<_>, _>>()?;
    body.validate_catalog(&catalog, false).map_err(|_| mismatch())?;
    if body.census_hash != ramflux_protocol::encode_base64url(full_census_hash(rules)?) {
        return Err(StorageError::PairingField("SchemaMismatch"));
    }
    for (family, rule) in body.families.iter().zip(rules) {
        if family.source_rows.0 > 0 && family.disposition == Disposition::Transfer {
            rule.require_typed_codec()?;
        }
    }
    let mut reader = stage.forward_reader(hash)?;
    let mut counts = vec![(0_u64, 0_u64); rules.len()];
    let mut previous: Option<(usize, Zeroizing<String>)> = None;
    loop {
        let start = reader.stream_position()?;
        let Some(header) = read_record_header(&mut reader).map_err(stream_error)? else {
            break;
        };
        let header = PrivateHeader(header);
        let index = rules
            .binary_search_by_key(&header.0.family.as_str(), |rule| rule.id)
            .map_err(|_| StorageError::PairingField("UnsupportedRecord"))?;
        if previous.as_ref().is_some_and(|(old_index, key)| {
            *old_index > index || (*old_index == index && key.as_str() >= header.0.key.as_str())
        }) || (body.kind == ManifestKind::Base && header.0.op != RecordOp::Put)
        {
            return Err(mismatch());
        }
        let rule = rules.get(index).ok_or_else(mismatch)?;
        copy_full_scalar_record(rule, &header.0, &mut reader, &mut std::io::sink())?;
        let encoded = reader.stream_position()?.checked_sub(start).ok_or_else(mismatch)?;
        let count = counts.get_mut(index).ok_or_else(mismatch)?;
        count.0 = count.0.checked_add(1).ok_or_else(mismatch)?;
        count.1 = count.1.checked_add(encoded).ok_or_else(mismatch)?;
        let family = body.families.get(index).ok_or_else(mismatch)?;
        if count.0 > family.portable_records.0 || count.1 > family.encoded_bytes.0 {
            return Err(mismatch());
        }
        visit(&header.0, start, encoded)?;
        previous = Some((index, Zeroizing::new(header.0.key.clone())));
    }
    if reader.stream_position()? != body.total_bytes.0
        || counts.iter().zip(&body.families).any(|((records, bytes), family)| {
            *records != family.portable_records.0 || *bytes != family.encoded_bytes.0
        })
    {
        return Err(mismatch());
    }
    stage.require_io()?;
    Ok(())
}

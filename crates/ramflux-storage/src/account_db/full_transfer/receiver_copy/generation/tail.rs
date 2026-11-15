// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Seed original A/B dependency provenance in B's private G1, never from merged row equality.
use super::super::FullReceiverBaseCopy;
use crate::{AdoptionRow, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::{RecordHeader, read_record_header};
use rusqlite::{Connection, params};
use zeroize::{Zeroize as _, Zeroizing};
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
struct Header(RecordHeader);
impl Drop for Header {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

pub(super) fn seed(
    target: &Connection,
    copy: &FullReceiverBaseCopy,
    adoption: &AdoptionRow,
    live: impl Fn() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    live()?;
    if target.is_autocommit() {
        return Err(wrong());
    }
    let nonce = adoption.full_generation_nonce.as_deref().ok_or_else(wrong)?;
    if nonce != ramflux_protocol::encode_base64url(copy.contributions.nonce) {
        return Err(wrong());
    }
    let source = copy.contributions.owners.first().ok_or_else(wrong)?;
    let local = copy.contributions.owners.get(1).ok_or_else(wrong)?;
    target.execute("INSERT INTO pairing_full_tail_apply(operation_id,generation_nonce,stage_digest,source_owner) VALUES(?1,?2,?3,?4)",
        params![adoption.operation_id,nonce,copy.stage_digest.as_slice(),source])?;
    let input = super::super::super::receiver_contributions::open(
        &copy.scratch.path.join("contributions.db"),
        &copy.key,
    )?;
    let mut query = input.prepare("SELECT owner,record FROM full_union_record WHERE generation_nonce=?1 AND family='sql/object_payload_dependency' ORDER BY owner,key")?;
    let mut rows = query.query(params![copy.contributions.nonce.as_slice()])?;
    let rule = super::super::super::source_scalar::compiled("sql/object_payload_dependency")?;
    while let Some(row) = rows.next()? {
        live()?;
        let owner = match row.get_ref(0)?.as_str().map_err(|_| wrong())? {
            value if value == source => 0,
            value if value == local => 1,
            _ => return Err(wrong()),
        };
        let record = row.get_ref(1)?.as_blob().map_err(|_| wrong())?;
        if record.len() > 16_384 {
            return Err(wrong());
        }
        let record = Zeroizing::new(record.to_vec());
        let mut bytes = record.as_slice();
        let header =
            Header(read_record_header(&mut bytes).map_err(|_| wrong())?.ok_or_else(wrong)?);
        if header.0.family != rule.id {
            return Err(wrong());
        }
        let cells = super::super::super::fixed_union::Cells::read(rule, &header.0, &mut bytes)?;
        if !bytes.is_empty() {
            return Err(wrong());
        }
        target.execute(
            "INSERT INTO pairing_full_tail_dependency VALUES(?1,?2,?3,?4)",
            params![adoption.operation_id, owner, cells.text(0)?, cells.text(1)?],
        )?;
    }
    live()
}

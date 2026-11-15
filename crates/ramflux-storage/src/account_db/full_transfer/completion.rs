// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent local terminal evidence survives erasure of encrypted stage keys and files.
use super::{FullInstalledTailScope, FullTransferStage};
use crate::{AccountDb, StorageError};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::{
    PairingWire as _,
    full_transfer::{DataPacket, SourceManifest, lease::DataGrant},
};
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
const LIMIT: usize = 16_384;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Completion {
    version: u8,
    account: String,
    operation: String,
    generation: u64,
    role: String,
    stage: String,
    digest: String,
    nonce: Option<String>,
    native_hash: String,
    grant: DataGrant,
    expires: u64,
    total: u64,
    cut: u64,
    outcome: String,
    data_verified: Option<DataPacket>,
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl Completion {
    pub(super) fn stage_id(&self) -> &str {
        &self.stage
    }
    pub(super) fn outcome(&self) -> &str {
        &self.outcome
    }
    pub(super) const fn expires_at(&self) -> u64 {
        self.expires
    }

    pub(super) fn from_stage(
        stage: &FullTransferStage<'_>,
        operation: &str,
        outcome: &str,
        packet: Option<&DataPacket>,
    ) -> Result<Self, StorageError> {
        stage.require_io()?;
        if !matches!(outcome, "merged" | "abandoned" | "expired") {
            return Err(wrong());
        }
        let live = stage
            .db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        let record = stage.resume_record()?;
        let adoption = stage.db.pairing_adoption()?.ok_or_else(wrong)?;
        let native_hash = if record.role == PairingRole::Initiator {
            stage.db.connection.query_row("SELECT record_hash FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3", params![stage.db.local_account_id, operation, stage.reference().stage_id], |row| row.get(0))?
        } else {
            adoption.record_hash
        };
        let bytes: Vec<u8> = stage.connection.query_row(
            "SELECT bytes FROM manifest WHERE direction=0 AND (?1 OR kind!='tail') AND length(bytes)<=1048576 ORDER BY cut DESC LIMIT 1",
            params![outcome == "merged"], |row| row.get(0),
        )?;
        let manifest = SourceManifest::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        let value = Self {
            version: 1,
            account: stage.db.local_account_id.clone(),
            operation: operation.into(),
            generation: live.generation,
            role: record.role.as_str().into(),
            stage: stage.reference().stage_id.clone(),
            digest: ramflux_protocol::encode_base64url(record.stage_digest()?),
            nonce: if record.role == PairingRole::Responder {
                adoption.full_generation_nonce
            } else {
                None
            },
            native_hash,
            expires: stage.reference().lease_expires_at.0,
            total: manifest.manifest.total_bytes.0,
            cut: manifest.manifest.snapshot_cut.0,
            grant: record.grant,
            outcome: outcome.into(),
            data_verified: packet.cloned(),
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), StorageError> {
        self.grant.validate().map_err(|_| wrong())?;
        for value in [&self.operation, &self.stage, &self.digest, &self.native_hash] {
            super::stage::raw32(value)?;
        }
        if self.version != 1
            || self.account.is_empty()
            || self.account.len() > 128
            || self.stage != self.grant.transfer_id
            || self.generation == 0
            || self.generation > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || self.total > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || self.cut > 9
            || self.expires > self.grant.expires_at
            || !matches!(self.role.as_str(), "initiator" | "responder")
            || !matches!(self.outcome.as_str(), "merged" | "abandoned" | "expired")
            || (self.role == "responder") != self.nonce.is_some()
        {
            return Err(wrong());
        }
        if let Some(nonce) = &self.nonce {
            super::stage::raw32(nonce)?;
        }
        match (&self.data_verified, self.outcome.as_str()) {
            (Some(packet @ DataPacket::DataVerified { signature, .. }), "merged") => {
                packet.validate().map_err(|_| wrong())?;
                ramflux_crypto::verify_canonical_signature(
                    &packet.data_verified_signing_bytes().map_err(|_| wrong())?,
                    signature,
                    &self.grant.branch_keys.destination,
                )
                .map_err(|_| wrong())?;
            }
            (None, "abandoned" | "expired") => {}
            _ => return Err(wrong()),
        }
        Ok(())
    }
    pub(super) fn scope(&self) -> FullInstalledTailScope {
        FullInstalledTailScope {
            grant: self.grant.clone(),
            lease_expires_at: self.expires,
            bytes_total: self.total,
            cut: self.cut,
            merged: self.outcome == "merged",
            abandoned: self.outcome == "abandoned",
        }
    }
}
impl AccountDb {
    /// Call within the transaction that commits the exact terminal data status.
    pub(super) fn retain_full_completion(
        &self,
        value: &Completion,
        now: u64,
    ) -> Result<(), StorageError> {
        value.validate()?;
        if value.account != self.local_account_id {
            return Err(wrong());
        }
        let bytes = ramflux_protocol::canonical_json_bytes(value)?;
        if bytes.len() > LIMIT {
            return Err(wrong());
        }
        let prior: Option<Option<Vec<u8>>> = self.connection.query_row(
            "SELECT CASE WHEN length(receipt)<=16384 THEN receipt END FROM pairing_full_completion WHERE operation_id=?1",
            params![value.operation], |row| row.get(0),
        ).optional()?;
        if let Some(prior) = prior {
            return if prior.as_deref() == Some(bytes.as_slice()) { Ok(()) } else { Err(wrong()) };
        }
        self.connection.execute("DELETE FROM pairing_full_completion WHERE cleanup_state='done' AND operation_id IN(SELECT operation_id FROM pairing_full_completion WHERE cleanup_state='done' ORDER BY finished_at,operation_id LIMIT max(0,(SELECT count(*) FROM pairing_full_completion)-127))", [])?;
        let count: u64 = self.connection.query_row(
            "SELECT count(*) FROM pairing_full_completion",
            [],
            |row| row.get(0),
        )?;
        if count >= 128 {
            return Err(StorageError::PairingField("Busy"));
        }
        self.connection.execute("INSERT INTO pairing_full_completion(operation_id,generation,role,stage_id,receipt,finished_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![value.operation, value.generation, value.role, value.stage, bytes, now])?;
        Ok(())
    }
    pub(super) fn full_completion(
        &self,
        operation: &str,
        generation: u64,
        role: &str,
        now: u64,
    ) -> Result<Option<Completion>, StorageError> {
        let saved: Option<(u64,String,String,Option<Vec<u8>>)> = self.connection.query_row(
            "SELECT generation,role,stage_id,CASE WHEN length(receipt)<=16384 THEN receipt END FROM pairing_full_completion WHERE operation_id=?1",
            params![operation], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional()?;
        let Some((saved_generation, saved_role, stage, bytes)) = saved else {
            return Ok(None);
        };
        if saved_generation != generation {
            return Err(wrong());
        }
        if saved_role != role {
            return Ok(None);
        }
        let bytes = bytes.ok_or_else(wrong)?;
        let value: Completion = ramflux_protocol::parse_i_json(&bytes)?;
        value.validate()?;
        if value.account != self.local_account_id
            || value.operation != operation
            || value.generation != generation
            || saved_generation != generation
            || value.role != role
            || saved_role != role
            || value.stage != stage
            || ramflux_protocol::canonical_json_bytes(&value)? != bytes
        {
            return Err(wrong());
        }
        if role == "responder" {
            let adoption = self.pairing_adoption()?.ok_or_else(wrong)?;
            if adoption.full_generation_nonce != value.nonce {
                return Err(wrong());
            }
        } else {
            self.full_source_retirement_owner(operation, &value.native_hash, now)?;
        }
        Ok(Some(value))
    }
}

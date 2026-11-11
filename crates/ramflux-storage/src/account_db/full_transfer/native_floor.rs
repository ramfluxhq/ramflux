// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Additional job-local rollback floor. It never replaces installed-account admission.
use super::FullTransferStage;
use crate::StorageError;
use ramflux_crypto::custody::{AuthorityPins, PinOutcome, VerifiedRecord};
use ramflux_protocol::custody::{
    object_hash,
    pairing::{PairingWire, context_v3::TranscriptV3},
};
use rusqlite::OptionalExtension as _;
use zeroize::Zeroizing;

pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS native_floor(singleton INTEGER PRIMARY KEY CHECK(singleton=1),pins BLOB NOT NULL);";
fn changed() -> StorageError {
    StorageError::PairingField("HeadChanged")
}
pub(super) fn validate_sas_base(
    record: &ramflux_crypto::custody::pairing::FullResumeRecord,
    base: &VerifiedRecord,
) -> Result<(), StorageError> {
    let transcript = TranscriptV3::from_wire_bytes(&record.transcript).map_err(|_| changed())?;
    let common = &transcript.initiator.common;
    let body = &base.envelope().body;
    if body.account_anchor != common.account_anchor
        || body.master_certificate.body.master_public_key != common.master_public_key
        || body.device_set_epoch != common.device_set_epoch
        || object_hash(base.envelope()).map_err(|_| changed())? != common.record_hash
    {
        return Err(changed());
    }
    Ok(())
}
impl FullTransferStage<'_> {
    fn native_floor(&self) -> Result<Option<AuthorityPins>, StorageError> {
        let bytes = self
            .connection
            .query_row("SELECT pins FROM native_floor WHERE singleton=1", [], |row| {
                Ok(Zeroizing::new(row.get::<_, Vec<u8>>(0)?))
            })
            .optional()?;
        bytes.map(|value| ramflux_protocol::parse_i_json(&value).map_err(|_| changed())).transpose()
    }
    /// Persist independently verified native observations before any job action/import.
    /// The first observation must be the exact saved SAS base; subsequent observations
    /// use the ordinary native pin owner's sticky revocations, epochs and fork fences.
    /// A valid revoking/forked head is retained even though it authorizes no data action.
    /// The SDK must additionally enforce its installed floor and existing freshness policy;
    /// this operation grants no role, J6 acknowledgement, tail admission or authority.
    /// # Errors
    /// Refuses another account/master, an unseeded non-base head, rollback/forks or lock.
    pub fn observe_full_native_head(
        &mut self,
        current: &VerifiedRecord,
    ) -> Result<(), StorageError> {
        self.db.require_full_stage_unlock()?;
        let record = self.resume_record()?;
        let transcript =
            TranscriptV3::from_wire_bytes(&record.transcript).map_err(|_| changed())?;
        let common = &transcript.initiator.common;
        let body = &current.envelope().body;
        if body.account_anchor != common.account_anchor
            || body.master_certificate.body.master_public_key != common.master_public_key
        {
            return Err(changed());
        }
        let mut pins = if let Some(pins) = self.native_floor()? {
            pins
        } else {
            validate_sas_base(&record, current)?;
            AuthorityPins::default()
        };
        let outcome = pins.observe(current).map_err(|_| changed())?;
        let bytes = Zeroizing::new(serde_json::to_vec(&pins)?);
        self.db.require_full_stage_unlock()?;
        self.connection.execute("INSERT INTO native_floor(singleton,pins) VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET pins=excluded.pins", rusqlite::params![bytes.as_slice()])?;
        if matches!(outcome, PinOutcome::Fenced(_)) {
            return Err(changed());
        }
        pins.require_current(current).map_err(|_| changed())
    }

    /// Require the job's exact last accepted unfenced head before using cached authority.
    /// The caller still obtains fresh authority and enforces the installed account floor.
    /// # Errors
    /// Refuses an unseeded/stale/fenced head or a locked stage. This grants no data admission.
    pub fn require_full_native_floor(&self, current: &VerifiedRecord) -> Result<(), StorageError> {
        self.db.require_full_stage_unlock()?;
        self.native_floor()?.ok_or_else(changed)?.require_current(current).map_err(|_| changed())
    }
}

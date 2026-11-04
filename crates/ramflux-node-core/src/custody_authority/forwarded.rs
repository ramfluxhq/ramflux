// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Foreign authority pins have a separate durable ceiling and never enroll local accounts.
use super::{CustodyAccountState, crypto};
use crate::{
    CustodyPublication, DeviceAuthKeyResponse, IdentityRegistry, NodeCoreError, RouterCore,
    RouterRedbStore,
};
use ramflux_crypto::custody::PinOutcome;
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};

const FOREIGN: TableDefinition<&str, &[u8]> = TableDefinition::new("foreign_custody_pins_v1");
const MAX_FOREIGN: u64 = 4096;
const MAX_FOREIGN_BYTES: usize = 1024 * 1024;
fn storage(e: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(e.to_string())
}

impl RouterCore {
    /// Verify bounded foreign evidence and persist monotonic pins independently of local enrollment.
    /// # Errors
    /// Refuses client provenance, excessive evidence, unrelated roots, stale authority and forks.
    pub fn authenticated_native_forwarded_source_with_floors(
        &self,
        envelope: &ramflux_protocol::Envelope,
        floors: &[CustodyPublication],
        store: &RouterRedbStore,
        origin: crate::RouterEnvelopeOrigin,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        if origin != crate::RouterEnvelopeOrigin::Federation || floors.len() > 64 {
            return Err(NodeCoreError::Unauthorized(
                "invalid forwarded floor provenance or count".into(),
            ));
        }
        let (authority, source) = DeviceAuthKeyResponse::forwarded_envelope_source(envelope)?;
        let evidence = authority.custody_authority.ok_or_else(|| {
            NodeCoreError::Unauthorized("native forwarded authority missing".into())
        })?;
        if floors.iter().any(|p| p.record.body.account_anchor != source.root_commitment()) {
            return Err(NodeCoreError::Unauthorized("forwarded floor root mismatch".into()));
        }
        let now = crate::now_unix_seconds();
        let publication = CustodyPublication {
            record: evidence.publication.record.clone(),
            compacted_ids: evidence.publication.compacted_ids.clone(),
        };
        let custodian = evidence.custodian_publication.as_ref().map(|p| CustodyPublication {
            record: p.record.clone(),
            compacted_ids: p.compacted_ids.clone(),
        });
        // Read local floors before acquiring the database writer (local publication locks first).
        let mut local = Vec::new();
        for anchor in custodian
            .as_ref()
            .map(|p| p.record.body.account_anchor.as_str())
            .into_iter()
            .chain(std::iter::once(source.root_commitment()))
        {
            if let Some(publication) = self.custody_record(anchor, now)? {
                local.push(publication);
            }
        }
        let tx = store.migration_db().begin_write().map_err(storage)?;
        let mut registry = IdentityRegistry::default();
        {
            let table = tx.open_table(FOREIGN).map_err(storage)?;
            for anchor in std::iter::once(source.root_commitment())
                .chain(custodian.as_ref().map(|p| p.record.body.account_anchor.as_str()))
            {
                if let Some(bytes) = table.get(anchor).map_err(storage)? {
                    let state: CustodyAccountState =
                        serde_json::from_slice(bytes.value()).map_err(storage)?;
                    registry.apply_custody_account(anchor.into(), state)?;
                }
            }
        }
        let mut refusal = None;
        for current in
            local.iter().chain(custodian.iter()).chain(floors).chain(std::iter::once(&publication))
        {
            let anchor = &current.record.body.account_anchor;
            let verified = registry.verify_custody(current, now)?;
            let mut pins = registry.custody.pins_for(anchor);
            let previous = registry.custody.records.get(anchor).map(|p| &p.record);
            let outcome = match pins.observe_with_previous(&verified, previous) {
                Ok(outcome) => outcome,
                Err(error) => {
                    refusal = Some(crypto(&error));
                    break;
                }
            };
            let accepted = if matches!(outcome, PinOutcome::Fenced(_)) {
                registry
                    .custody
                    .records
                    .get(anchor)
                    .cloned()
                    .ok_or_else(|| storage("foreign fenced head missing"))?
            } else {
                current.clone()
            };
            let state = CustodyAccountState { publication: accepted, pins };
            let bytes = serde_json::to_vec(&state).map_err(storage)?;
            let mut table = tx.open_table(FOREIGN).map_err(storage)?;
            if bytes.len() > MAX_FOREIGN_BYTES
                || (table.get(anchor.as_str()).map_err(storage)?.is_none()
                    && table.len().map_err(storage)? >= MAX_FOREIGN)
            {
                return Err(NodeCoreError::Capacity { resource: "foreign custody pins" });
            }
            table.insert(anchor.as_str(), bytes.as_slice()).map_err(storage)?;
            registry.apply_custody_account(anchor.clone(), state)?;
            if let PinOutcome::Fenced(alert) = outcome {
                refusal = Some(NodeCoreError::CustodyConflict { alert: Box::new(alert) });
                break;
            }
        }
        // Verified revocation/fork evidence remains durable even when the old sender is refused.
        tx.commit().map_err(storage)?;
        if let Some(error) = refusal {
            return Err(error);
        }
        let verified = registry.verify_custody(&publication, now)?;
        registry.custody.require_current(&verified).map_err(|e| crypto(&e))?;
        if registry.custody.records.get(source.root_commitment()) != Some(&publication) {
            return Err(NodeCoreError::Unauthorized("stale native foreign authority".into()));
        }
        Ok(source)
    }
}

#[cfg(test)]
impl RouterRedbStore {
    pub(crate) fn foreign_custody_state(
        &self,
        anchor: &str,
    ) -> Result<Option<CustodyAccountState>, NodeCoreError> {
        use redb::ReadableDatabase;
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(FOREIGN) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(storage(e)),
        };
        table
            .get(anchor)
            .map_err(storage)?
            .map(|bytes| serde_json::from_slice(bytes.value()).map_err(storage))
            .transpose()
    }
}

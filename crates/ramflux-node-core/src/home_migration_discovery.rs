// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh discovery signatures may change their timestamps without changing the configured home.
use crate::{MigrationNode, NodeCoreError};
use ramflux_protocol::{WellKnownClientRecord, home_migration::Refusal};
pub const HOME_MIGRATION_CAPABILITY: &str = "home_migration_v1";
impl MigrationNode {
    /// Require owner admission to supply current signed discovery for this configured node CA.
    /// # Errors
    /// Rejects absent or oversized CA material before enabling the capability.
    pub fn require_client_discovery(mut self, ca_cert_pem: String) -> Result<Self, NodeCoreError> {
        if ca_cert_pem.trim().is_empty() || ca_cert_pem.len() > 64 * 1024 {
            return Err(failure(Refusal::PinMismatch));
        }
        self.client_ca_cert_pem = Some(ca_cert_pem);
        Ok(self)
    }
    pub(crate) fn for_client_discovery(
        &self,
        record: Option<&WellKnownClientRecord>,
        expected_hash: &str,
        now: u64,
    ) -> Result<Self, NodeCoreError> {
        let Some(ca) = &self.client_ca_cert_pem else {
            return Ok(self.clone());
        };
        let record = record.ok_or_else(|| failure(Refusal::EvidenceRequired))?;
        ramflux_protocol::verify_client_discovery_record(record, now)
            .map_err(|_| failure(Refusal::PinMismatch))?;
        let hash = ramflux_protocol::custody::framed_hash(
            ramflux_protocol::domain::CUSTODY_OBJECT_HASH,
            record,
        )
        .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        if record.node_id != self.node_id()
            || record.node_public_key != self.public_key()
            || record.node_ca_cert_pem.trim() != ca.trim()
            || record.gateway_tcp_addr != self.gateway_tcp_addr
            || !record.client_capabilities.iter().any(|cap| cap == HOME_MIGRATION_CAPABILITY)
            || hash != expected_hash
        {
            return Err(failure(Refusal::PinMismatch));
        }
        let mut node = self.clone();
        node.discovery_hash = hash;
        Ok(node)
    }
}
fn failure(reason: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(reason)
}

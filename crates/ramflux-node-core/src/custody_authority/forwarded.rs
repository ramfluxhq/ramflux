// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native forwarded senders share the durable custody publication and fencing boundary.
use crate::{
    CustodyPublication, DeviceAuthKeyResponse, NodeCoreError, RouterCore, RouterRedbStore,
};

impl RouterCore {
    pub(crate) fn authenticate_native_forwarded_source(
        &self,
        envelope: &ramflux_protocol::Envelope,
        store: Option<&RouterRedbStore>,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let store = store.ok_or_else(|| {
            NodeCoreError::Unauthorized("native foreign authority requires durable pins".into())
        })?;
        self.authenticated_native_forwarded_source_with_floors(
            envelope,
            &[],
            store,
            crate::RouterEnvelopeOrigin::Federation,
        )
    }

    /// Persist independently signed native floors before admitting a forwarded sender.
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
        let now = crate::now_unix_seconds();
        if let Some(custodian) = &evidence.custodian_publication {
            self.publish_custody_record(
                &CustodyPublication {
                    record: custodian.record.clone(),
                    compacted_ids: custodian.compacted_ids.clone(),
                },
                now,
                store,
            )?;
        }
        for floor in floors {
            if floor.record.body.account_anchor != source.root_commitment() {
                return Err(NodeCoreError::Unauthorized("forwarded floor root mismatch".into()));
            }
            self.publish_custody_record(floor, now, store)?;
        }
        self.publish_custody_record(
            &CustodyPublication {
                record: evidence.publication.record.clone(),
                compacted_ids: evidence.publication.compacted_ids.clone(),
            },
            now,
            store,
        )?;
        // A concurrent newer publication or a persisted conflict must still fence admission.
        let current = self.custody_record(source.root_commitment(), now)?;
        if current.as_ref().map(|publication| &publication.record)
            != Some(&evidence.publication.record)
        {
            return Err(NodeCoreError::Unauthorized("stale native foreign authority".into()));
        }
        Ok(source)
    }
}

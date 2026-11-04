// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed submission refusals preserve signed routing evidence without mutating acceptance state.
use super::{
    InboxRoute, NodeCoreError, Refusal, RouterCore, RouterRedbStore, TARGETS, record_hash, storage,
};
use redb::ReadableDatabase;
impl RouterCore {
    /// Construct a non-fatal response before mailbox acceptance. Migrated routing hints are signed.
    /// # Errors
    /// Fails closed if permanent evidence or the matching local node signing key is unavailable.
    pub fn migration_submission_refusal(
        &self,
        store: &RouterRedbStore,
        envelope: &ramflux_protocol::Envelope,
        reason: Refusal,
        now: u64,
    ) -> Result<crate::EnvelopeSubmitResponse, NodeCoreError> {
        let mut response = crate::EnvelopeSubmitResponse {
            migration_refusal: Some(reason),
            outcome: "rejected_home_migration".into(),
            target_delivery_id: envelope.target_delivery_id.clone(),
            inbox_seq: None,
            cursor: None,
            nack: None,
        };
        if reason != Refusal::HomeMigrated {
            return Ok(response);
        }
        let tx = store.migration_db().begin_read().map_err(storage)?;
        let anchor = match tx.open_table(TARGETS) {
            Ok(table) => table
                .get(envelope.target_delivery_id.as_str())
                .map_err(storage)?
                .map(|row| super::decode::<InboxRoute>(row.value()))
                .transpose()?
                .map(|route| route.anchor),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(storage(error)),
        }
        .or_else(|| {
            ramflux_protocol::parse_qualified_device_id(&envelope.target_delivery_id)
                .ok()
                .flatten()
                .map(|(anchor, _)| anchor)
        })
        .ok_or_else(|| storage("migrated target root unavailable"))?;
        response.nack = Some(self.migration_nack(
            store,
            &anchor,
            &envelope.target_delivery_id,
            &envelope.envelope_id,
            now,
        )?);
        Ok(response)
    }
    /// Refuse a new submission from a local sender whose home moved away.
    /// # Errors
    /// Fails closed when the committed source evidence or its signer is unavailable.
    pub fn migration_source_submission_refusal(
        &self,
        store: &RouterRedbStore,
        envelope: &ramflux_protocol::Envelope,
        anchor: &str,
        reason: Refusal,
        now: u64,
    ) -> Result<crate::EnvelopeSubmitResponse, NodeCoreError> {
        Ok(crate::EnvelopeSubmitResponse {
            migration_refusal: Some(reason),
            outcome: "rejected_home_migration".into(),
            target_delivery_id: envelope.target_delivery_id.clone(),
            inbox_seq: None,
            cursor: None,
            nack: if reason == Refusal::HomeMigrated {
                Some(self.migration_nack(
                    store,
                    anchor,
                    &envelope.target_delivery_id,
                    &envelope.envelope_id,
                    now,
                )?)
            } else {
                None
            },
        })
    }
    /// Bind an ordinary-client refusal to the authenticated challenge/request nonce.
    pub(crate) fn migration_owner_refusal(
        &self,
        store: &RouterRedbStore,
        device: &ramflux_protocol::custody::DeviceRef,
        nonce: &str,
        reason: Refusal,
        now: u64,
    ) -> Result<ramflux_protocol::custody::CustodyRefusal, NodeCoreError> {
        let nack = if reason == Refusal::HomeMigrated {
            let target =
                ramflux_protocol::qualified_device_id(&device.account_anchor, &device.device_id)
                    .map_err(storage)?;
            Some(Box::new(self.migration_nack(
                store,
                &device.account_anchor,
                &target,
                nonce,
                now,
            )?))
        } else {
            None
        };
        Ok(ramflux_protocol::custody::CustodyRefusal::HomeMigration { reason, nack })
    }
    fn migration_nack(
        &self,
        store: &RouterRedbStore,
        anchor: &str,
        target: &str,
        operation_id: &str,
        now: u64,
    ) -> Result<ramflux_protocol::Nack, NodeCoreError> {
        let head = store
            .migration_home(anchor)?
            .ok_or_else(|| storage("migrated root home evidence unavailable"))?;
        let signer = self.node_service_signer().ok_or_else(|| {
            NodeCoreError::Unauthorized("migration refusal requires node signer".into())
        })?;
        if signer.public_key_base64url() != head.node_record.body.node_signing_public_key {
            return Err(NodeCoreError::Unauthorized(
                "migration refusal node signer does not match committed source".into(),
            ));
        }
        let mut nack = ramflux_protocol::Nack {
            schema: "ramflux.nack.v1".into(),
            version: 1,
            domain: ramflux_protocol::domain::NACK.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: signer.signing_key_id().into(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: String::new(),
            },
            nack_id: format!("migrated:{}:{}", head.record.epoch(), operation_id),
            envelope_id: operation_id.into(),
            receiver_device_id: target.into(),
            reason: ramflux_protocol::NackReason::HomeNodeMigrated,
            received_at: i64::try_from(now).map_err(storage)?,
            retry_after: None,
            proof_hash: Some(record_hash(&head.record).map_err(storage)?),
            new_home_node_hint: Some(head.record.home().0.into()),
        };
        signer.sign_nack(&mut nack)?;
        Ok(nack)
    }
}

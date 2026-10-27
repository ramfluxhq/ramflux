// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed submission refusals preserve signed routing evidence without mutating acceptance state.
use super::{
    HEADS, InboxRoute, NodeCoreError, RecordEvidence, Refusal, RouterCore, RouterRedbStore,
    TARGETS, record_hash, storage,
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
        let table = tx.open_table(TARGETS).map_err(storage)?;
        let route: InboxRoute = super::decode(
            table
                .get(envelope.target_delivery_id.as_str())
                .map_err(storage)?
                .ok_or_else(|| storage("migrated target route unavailable"))?
                .value(),
        )?;
        let heads = tx.open_table(HEADS).map_err(storage)?;
        let head: RecordEvidence = super::decode(
            heads
                .get(route.anchor.as_str())
                .map_err(storage)?
                .ok_or_else(|| storage("migrated target home evidence unavailable"))?
                .value(),
        )?;
        let signer = self
            .node_service_signer()
            .ok_or_else(|| storage("migration refusal requires node signer"))?;
        if signer.public_key_base64url() != head.node_record.body.node_signing_public_key {
            return Err(storage("migration refusal node signer does not match committed source"));
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
            nack_id: format!("migrated:{}:{}", head.record.epoch(), envelope.envelope_id),
            envelope_id: envelope.envelope_id.clone(),
            receiver_device_id: envelope.target_delivery_id.clone(),
            reason: ramflux_protocol::NackReason::HomeNodeMigrated,
            received_at: i64::try_from(now).map_err(storage)?,
            retry_after: None,
            proof_hash: Some(record_hash(&head.record).map_err(storage)?),
            new_home_node_hint: Some(head.record.home().0.into()),
        };
        signer.sign_nack(&mut nack)?;
        response.nack = Some(nack);
        Ok(response)
    }
}

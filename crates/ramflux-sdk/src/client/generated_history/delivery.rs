// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conditional history-page courier plans: durable outbox first, then send, then advance.
//! One page per target is in flight; the writer owns every ratchet and store change.
use super::producer::{InFlight, Outgoing, TRANSFER, page_key, refused};
use super::{RamfluxClient, SdkError};
use crate::client::identity_authority::NativeOperation;
use crate::client::routed::{Route, SendMaterial, SendMaterialRequest};
use crate::{GatewayDirectMessage, GatewaySessionConfig};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::Envelope;
use serde::{Deserialize, Serialize};

/// Minimum spacing between accepted pages to one target; far inside the receiver window.
const PAGE_INTERVAL_SECS: i64 = 1;
/// Resends of one sealed page before its chain is restarted from the durable item cursor.
const MAX_PAGE_ATTEMPTS: u32 = 10;

/// The sealed in-flight page. Bound to every carried owner as a history container, so an
/// Edit or Delete of any owner removes the whole cached page in the same transaction.
#[derive(Serialize, Deserialize)]
struct Cached {
    transfer_id: Vec<u8>,
    page: u64,
    envelope: Envelope,
}

pub(crate) struct Plan {
    key: String,
    fingerprint: serde_json::Value,
    target: RootQualifiedDeviceRef,
    pub(crate) message: GatewayDirectMessage,
    pub(crate) request: SendMaterialRequest,
    pub(crate) envelope: Option<Envelope>,
}

fn backoff(attempts: u32) -> i64 {
    (1_i64 << attempts.min(6)).min(60)
}

impl RamfluxClient {
    /// Select one due transfer. A retained sealed page is resent unchanged; an invalidated
    /// one (any owner erased, expired or torn) restarts the digest chain after a quiet period.
    /// # Errors
    /// Returns storage and authority errors; unavailable authority only defers a target.
    pub(crate) fn prepare_generated_history_delivery(
        &self,
        config: &GatewaySessionConfig,
    ) -> Result<Option<Plan>, SdkError> {
        if !crate::client::target_selection::schema_v1_selected() {
            return Ok(None);
        }
        let db = self.account_db()?;
        let now = crate::time::now_unix_timestamp();
        for key in db.actor_state_keys(TRANSFER)? {
            let Some(mut row) = db.load_actor_state::<Outgoing>(&key)? else { continue };
            if row.done || row.next_at > now {
                continue;
            }
            let Ok(target) = self.device_identity(&row.target) else {
                // An unknown target can never be admitted again under this row.
                self.retire_generated_history_transfer(&key, &row.target)?;
                continue;
            };
            match self.history_target_epoch(&target) {
                Ok(Some(epoch)) if epoch == row.target_epoch => (),
                Ok(_) => {
                    self.retire_generated_history_transfer(&key, &row.target)?;
                    continue;
                }
                Err(
                    SdkError::InboundPending(_) | SdkError::DirectoryAuthorityUnavailable { .. },
                ) => continue,
                Err(error) => return Err(error),
            }
            let page = page_key(&row.target);
            let cached = db.load_actor_state::<Cached>(&page)?;
            let envelope = match (row.in_flight.clone(), cached) {
                (Some(flight), Some(cached))
                    if row.attempts < MAX_PAGE_ATTEMPTS
                        && cached.transfer_id == row.transfer_id
                        && cached.page == flight.page
                        && cached.envelope.envelope_id == flight.envelope_id
                        && cached.envelope.payload_hash == flight.payload_hash
                        && cached
                            .envelope
                            .created_at
                            .saturating_add(i64::from(cached.envelope.ttl))
                            > now =>
                {
                    Some(cached.envelope)
                }
                (Some(_), _) => {
                    // The page may already have reached the receiver under this digest; a
                    // rebuilt page with another digest would fork the chain. Start a new chain.
                    db.write_transaction(|| {
                        db.remove_actor_state(&page)?;
                        row.restart_chain()?;
                        row.attempts = 0;
                        row.next_at = now.saturating_add(super::producer::RESTART_AFTER_IDLE_SECS);
                        db.persist_actor_state(&key, &row)?;
                        Ok::<_, SdkError>(())
                    })?;
                    continue;
                }
                (None, Some(_)) => {
                    db.remove_actor_state(&page)?;
                    None
                }
                (None, None) => None,
            };
            row.attempts = row.attempts.saturating_add(1);
            row.next_at = now.saturating_add(backoff(row.attempts));
            db.persist_actor_state(&key, &row)?;
            let message = GatewayDirectMessage {
                conversation_id: String::new(),
                message_id: String::new(),
                envelope_id: crate::new_surface_message_id()?,
                source_principal_id: config.principal_id.clone(),
                sender_id: config.device_id.clone(),
                recipient_device_id: Some(target.device_id().into()),
                recipient_principal_commitment: Some(target.root_commitment().into()),
                target_delivery_id: target.storage_key().into(),
                encrypted_body: Vec::new(),
                created_at: now,
                ttl: self.content_ttl()?,
            };
            let request = self.routed_send_material_request(config, &message)?;
            return Ok(Some(Plan {
                key,
                fingerprint: serde_json::to_value(&row)?,
                target,
                message,
                request,
                envelope,
            }));
        }
        Ok(None)
    }

    fn retire_generated_history_transfer(&self, key: &str, target: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            db.remove_actor_state(&page_key(target))?;
            db.remove_actor_state(key)?;
            Ok(())
        })
    }

    fn current_history_transfer(&self, plan: &Plan) -> Result<Option<Outgoing>, SdkError> {
        let db = self.account_db()?;
        let Some(row) = db.load_actor_state::<Outgoing>(&plan.key)? else { return Ok(None) };
        if serde_json::to_value(&row)? != plan.fingerprint
            || self.history_target_epoch(&plan.target)? != Some(row.target_epoch)
            || !self.history_cached_page_current(&row)?
        {
            return Ok(None);
        }
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
        self.require_native_operation(&plan.target, NativeOperation::Sync)?;
        Ok(Some(row))
    }

    // A plan may outlive an Edit/Delete while the network material is fetched. The
    // transfer row is content-free and survives that retirement; its fingerprint
    // alone cannot authorize handing the plan's captured ciphertext to transport.
    fn history_cached_page_current(&self, row: &Outgoing) -> Result<bool, SdkError> {
        let Some(flight) = &row.in_flight else { return Ok(true) };
        let Some(cached) = self.account_db()?.load_actor_state::<Cached>(&page_key(&row.target))?
        else {
            return Ok(false);
        };
        Ok(cached.transfer_id == row.transfer_id
            && cached.page == flight.page
            && cached.envelope.envelope_id == flight.envelope_id
            && cached.envelope.payload_hash == flight.payload_hash)
    }

    /// Build, seal and durably retain the next page in one writer transaction.
    /// Returns `None` when the plan is stale, only skipped rows were consumed, or the
    /// transfer is finished.
    /// # Errors
    /// Returns sealing, authority and storage errors; the transaction rolls back as a whole.
    pub(crate) fn seal_generated_history_delivery(
        &self,
        config: &GatewaySessionConfig,
        mut plan: Plan,
        material: SendMaterial,
    ) -> Result<Option<(Plan, Envelope)>, SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let Some(mut row) = self.current_history_transfer(&plan)? else { return Ok(None) };
            if let Some(envelope) = plan.envelope.clone() {
                return Ok(Some((plan, envelope)));
            }
            let now = crate::time::now_unix_timestamp();
            if row.chain_expired(now) {
                row.restart_chain()?;
            }
            let Some(built) = self.build_generated_history_page(
                &row.transfer_id,
                row.next_page,
                &row.last_digest,
                row.cursor.as_ref(),
            )?
            else {
                row.done = true;
                row.attempts = 0;
                db.persist_actor_state(&plan.key, &row)?;
                return Ok(None);
            };
            if built.page.items.is_empty() {
                row.cursor = Some(built.after);
                row.skipped = row.skipped.saturating_add(built.skipped);
                row.attempts = 0;
                row.next_at = now;
                db.persist_actor_state(&plan.key, &row)?;
                return Ok(None);
            }
            self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
            self.require_native_operation(&plan.target, NativeOperation::Sync)?;
            let (identity, inner) = self.encode_generated_history_page(&built)?;
            let inner = zeroize::Zeroizing::new(inner);
            plan.message.conversation_id.clone_from(&built.conversation);
            plan.message.message_id = ramflux_protocol::encode_base64url(&identity.id);
            let sealed = self.seal_generated_routed_prepared(
                config,
                &plan.message,
                &inner,
                Route::control(),
                material,
            )?;
            let envelope = crate::dm::gateway_generated_envelope_from_sealed(
                config,
                &mut plan.message,
                sealed,
            )?;
            let page = page_key(&row.target);
            db.persist_actor_state(
                &page,
                &Cached {
                    transfer_id: row.transfer_id.clone(),
                    page: row.next_page,
                    envelope: envelope.clone(),
                },
            )?;
            for owner in &built.owners {
                db.bind_message_container_reference(owner, &page)?;
            }
            row.in_flight = Some(InFlight {
                page: row.next_page,
                previous: row.last_digest.clone(),
                digest: built.page.page_digest.clone(),
                after: built.after,
                owners: built.owners,
                skipped: built.skipped,
                envelope_id: envelope.envelope_id.clone(),
                payload_hash: envelope.payload_hash.clone(),
            });
            db.persist_actor_state(&plan.key, &row)?;
            plan.fingerprint = serde_json::to_value(&row)?;
            Ok(Some((plan, envelope)))
        })
    }

    /// After the gateway accepted the page: advance the chain and the item cursor, and drop
    /// the retained ciphertext. A stale plan changes nothing.
    /// # Errors
    /// Returns storage errors.
    pub(crate) fn complete_generated_history_delivery(&self, plan: &Plan) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let Some(mut row) = self.current_history_transfer(plan)? else { return Ok(()) };
            let Some(flight) = row.in_flight.take() else { return Ok(()) };
            let now = crate::time::now_unix_timestamp();
            row.next_page =
                flight.page.checked_add(1).ok_or_else(|| refused("history page overflow"))?;
            row.last_digest = flight.digest;
            row.cursor = Some(flight.after);
            row.exported =
                row.exported.saturating_add(u64::try_from(flight.owners.len()).unwrap_or(u64::MAX));
            row.skipped = row.skipped.saturating_add(flight.skipped);
            row.last_submit_at = now;
            row.next_at = now.saturating_add(PAGE_INTERVAL_SECS);
            row.attempts = 0;
            db.remove_actor_state(&page_key(&row.target))?;
            db.persist_actor_state(&plan.key, &row)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::producer::Cursor;
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};

    #[tokio::test]
    async fn history_captured_page_is_rechecked_after_an_owner_is_erased() -> TestResult {
        let own = Fixture::new("history-stale-plan-erasure").await?;
        own.client.send_direct_message("c", "owner", "sender", b"body")?;
        let mut row = Outgoing::new(&own.client.owned_device_identity()?, 1)?;
        let envelope = Envelope {
            schema: "test".into(),
            version: 1,
            domain: "test".into(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "key".into(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "signature".into(),
            },
            envelope_id: "captured-page".into(),
            source_principal_id: "source".into(),
            source_device_id: "source-device".into(),
            target_delivery_id: row.target.clone(),
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::SelfDeviceControl,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 300,
            created_at: crate::time::now_unix_timestamp(),
            encrypted_payload: "ciphertext".into(),
            payload_hash: "payload-hash".into(),
            delivery_mode: None,
            collapse_tag: None,
            report_commitment: None,
        };
        row.in_flight = Some(InFlight {
            page: 0,
            previous: vec![0; 32],
            digest: vec![1; 32],
            after: Cursor { conversation: "c".into(), created_at: 1, message: "owner".into() },
            owners: vec!["owner".into()],
            skipped: 0,
            envelope_id: envelope.envelope_id.clone(),
            payload_hash: envelope.payload_hash.clone(),
        });
        let db = own.client.account_db()?;
        let key = page_key(&row.target);
        db.write_transaction(|| {
            db.persist_actor_state(
                &key,
                &Cached {
                    transfer_id: row.transfer_id.clone(),
                    page: 0,
                    envelope: envelope.clone(),
                },
            )?;
            db.bind_message_container_reference("owner", &key)?;
            Ok::<(), SdkError>(())
        })?;
        assert!(own.client.history_cached_page_current(&row)?);
        let captured = envelope.clone();
        db.delete_direct_message("c", "owner", "local", "erase-owner")?;
        assert!(!captured.encrypted_payload.is_empty(), "the prepared plan still owns ciphertext");
        assert!(
            !own.client.history_cached_page_current(&row)?,
            "retiring the stored page revokes a previously captured plan even when its transfer fingerprint survives"
        );
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable bounded reordering buffer for authenticated future surface events.
use super::{Carrier, SurfaceSender, invalid, key};
use crate::{RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::json;
const MAX_PENDING: usize = 64;
const MAX_PER_SURFACE: usize = 32;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const TTL_SECONDS: u64 = 600;
#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    carrier: Carrier,
    surface_ref: String,
    message: String,
    version: u64,
    expires_at: u64,
    envelope_id: String,
    wire_expires_at: i64,
    group_epoch: Option<u64>,
}
pub(super) fn pending_key(carrier: &Carrier) -> Result<String, SdkError> {
    Ok(format!(
        "{}{}/{}",
        "surface/pending/",
        ramflux_protocol::hash_base64url(
            "ramflux.surface.pending_author.v1",
            carrier.author_principal_id.as_bytes()
        ),
        ramflux_protocol::hash_base64url(
            "ramflux.surface.pending_delivery.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &carrier.surface_reference()?,
                &carrier.sender_principal_id,
                &carrier.message_id
            ))?
        )
    ))
}
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
impl RamfluxClient {
    fn surface_pending(&self, author: &str) -> Result<Vec<Pending>, SdkError> {
        let prefix = format!(
            "surface/pending/{}/",
            ramflux_protocol::hash_base64url(
                "ramflux.surface.pending_author.v1",
                author.as_bytes()
            )
        );
        Ok(self.account_db()?.surface_history_page(&prefix, &prefix, 65)?)
    }
    pub(super) fn surface_pending_id_matches(&self, carrier: &Carrier) -> Result<bool, SdkError> {
        let existing = self.account_db()?.load_actor_state::<Pending>(&pending_key(carrier)?)?;
        existing.map_or(Ok(true), |p| Ok(p.carrier.bytes()? == carrier.bytes()?))
    }
    pub(super) fn queue_surface_pending(
        &self,
        carrier: &Carrier,
        message: &str,
        sender: SurfaceSender<'_>,
        version: u64,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let reference = carrier.surface_reference()?;
        let mut retained = Vec::new();
        for pending in self.surface_pending(&carrier.author_principal_id)? {
            if pending.expires_at <= now() {
                if pending.carrier.payload_kind == super::PayloadKind::Event {
                    self.mark_surface_out_of_sync(&pending.carrier, pending.version)?;
                }
                db.delete_surface_state(&pending_key(&pending.carrier)?)?;
                self.expire_surface_placeholder(&pending.carrier)?;
            } else {
                retained.push(pending);
            }
        }
        if retained.iter().any(|p| {
            p.surface_ref == reference
                && p.carrier.sender_principal_id == carrier.sender_principal_id
                && p.carrier.message_id == carrier.message_id
        }) {
            return Ok(true);
        }
        self.ensure_surface_pending_view(carrier)?;
        let current = self.surface_state_ref(&reference)?.map_or(0, |(_, s)| s.version());
        let entry = Pending {
            carrier: carrier.clone(),
            surface_ref: reference.clone(),
            message: message.into(),
            version,
            expires_at: now()
                .saturating_add(TTL_SECONDS)
                .min(sender.expires_at.map_or(u64::MAX, |v| u64::try_from(v).unwrap_or(0))),
            envelope_id: sender.envelope_id.to_owned(),
            wire_expires_at: sender.expires_at.unwrap_or(i64::MAX),
            group_epoch: sender.group_epoch,
        };
        let bytes = retained
            .iter()
            .filter(|p| p.surface_ref == reference)
            .try_fold(serde_json::to_vec(&entry)?.len(), |sum, p| {
                serde_json::to_vec(p).map(|b| sum.saturating_add(b.len()))
            })?;
        if retained.len() >= MAX_PENDING
            || retained.iter().filter(|p| p.surface_ref == reference).count() >= MAX_PER_SURFACE
            || bytes > 1024 * 1024
            || version > current.saturating_add(64)
        {
            if carrier.payload_kind == super::PayloadKind::Event {
                self.mark_surface_out_of_sync(carrier, version)?;
            }
            return Ok(false);
        }
        let total = retained.iter().try_fold(serde_json::to_vec(&entry)?.len(), |sum, p| {
            serde_json::to_vec(p).map(|b| sum.saturating_add(b.len()))
        })?;
        if total > MAX_BYTES {
            if carrier.payload_kind == super::PayloadKind::Event {
                self.mark_surface_out_of_sync(carrier, version)?;
            }
            return Ok(false);
        }
        db.persist_actor_state(&pending_key(carrier)?, &entry)?;
        Ok(true)
    }
    pub(super) fn drain_surface_pending(&self, reference: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let view = db
            .client_record("surface", reference)?
            .ok_or_else(|| invalid("pending surface view missing"))?;
        let author = view["author_principal_id"]
            .as_str()
            .ok_or_else(|| invalid("pending author missing"))?;
        // Every successful iteration deletes one of at most 64 records for this author.
        for _ in 0..MAX_PENDING {
            let current = self.surface_state_ref(reference)?.map_or(0, |(_, s)| s.version());
            let mut ready = self
                .surface_pending(author)?
                .into_iter()
                .filter(|p| {
                    p.surface_ref == reference
                        && (p.version <= current.saturating_add(1) || p.expires_at <= now())
                })
                .collect::<Vec<_>>();
            ready.sort_by_key(|p| p.version);
            let Some(pending) = ready.into_iter().next() else {
                break;
            };
            let carrier = &pending.carrier;
            db.delete_surface_state(&pending_key(carrier)?)?;
            if pending.expires_at <= now() && carrier.payload_kind == super::PayloadKind::Event {
                self.mark_surface_out_of_sync(carrier, pending.version)?;
            }
            if pending.expires_at <= now() || !self.surface_pending_member(carrier)? {
                self.surface_error(
                    &carrier.conversation_id,
                    &pending.message,
                    SurfaceSender {
                        principal: &carrier.sender_principal_id,
                        device: &carrier.sender_device_id,
                        envelope_id: &pending.envelope_id,
                        expires_at: Some(pending.wire_expires_at),
                        group_epoch: pending.group_epoch,
                    },
                    None,
                    &json!({"code":"surface_pending_expired_or_member_removed"}),
                )?;
                continue;
            }
            let result = self.project_surface_once(
                &carrier.conversation_id,
                &pending.message,
                SurfaceSender {
                    principal: &carrier.sender_principal_id,
                    device: &carrier.sender_device_id,
                    envelope_id: &pending.envelope_id,
                    expires_at: Some(pending.wire_expires_at),
                    group_epoch: pending.group_epoch,
                },
                &carrier.bytes()?,
                false,
            )?;
            if result.retryable {
                break;
            }
            if result.accepted {
                db.replace_surface_message_content(
                    &carrier.conversation_id,
                    &pending.message,
                    result.fallback_text.as_bytes(),
                )?;
            }
        }
        Ok(())
    }
    fn ensure_surface_pending_view(&self, carrier: &Carrier) -> Result<(), SdkError> {
        let reference = carrier.surface_reference()?;
        if carrier.sender_principal_id == carrier.author_principal_id
            && self.account_db()?.client_record("surface", &reference)?.is_none()
        {
            self.account_db()?.persist_client_record("surface",&reference,&json!({"id":reference,"surface_ref":reference,"surface_id":carrier.surface_id,"conversation_id":carrier.conversation_id,"author_principal_id":carrier.author_principal_id,"version":0,"surface_hash":null,"closed":false,"out_of_sync":false,"renderer_error":null}))?;
        }
        Ok(())
    }
    pub(super) fn mark_surface_out_of_sync(
        &self,
        carrier: &Carrier,
        missing: u64,
    ) -> Result<(), SdkError> {
        let reference = carrier.surface_reference()?;
        let db = self.account_db()?;
        if self.surface_state_ref(&reference)?.is_some_and(|(_, state)| state.version() >= missing)
        {
            return Ok(());
        }
        let missing =
            missing.max(db.load_actor_state::<u64>(&key("out_of_sync", &reference))?.unwrap_or(0));
        db.persist_actor_state(&key("out_of_sync", &reference), &missing)?;
        if let Some(mut view) = db.client_record("surface", &reference)? {
            view["out_of_sync"] = json!(true);
            db.persist_client_record("surface", &reference, &view)?;
        }
        Ok(())
    }
    fn expire_surface_placeholder(&self, carrier: &Carrier) -> Result<(), SdkError> {
        let reference = carrier.surface_reference()?;
        if self.surface_state_ref(&reference)?.is_none() {
            self.account_db()?.delete_surface_placeholder(&reference)?;
            self.account_db()?.delete_surface_state(&key("out_of_sync", &reference))?;
        }
        Ok(())
    }
    pub(crate) fn expire_surface_pending(&self) -> Result<(), SdkError> {
        self.account_db()?.surface_transaction(|| {
            let db = self.account_db()?;
            let cursor = db
                .load_actor_state::<String>("surface/pending_expiry_cursor")?
                .unwrap_or_else(|| "surface/pending/".into());
            let rows = db.surface_record_page::<Pending>("surface/pending/", &cursor, 65)?;
            let next = if rows.len() == 65 {
                rows.last().map(|(key, _)| key.clone()).unwrap_or_default()
            } else {
                "surface/pending/".into()
            };
            for (key, entry) in rows {
                if entry.expires_at <= now() {
                    if entry.carrier.payload_kind == super::PayloadKind::Event {
                        self.mark_surface_out_of_sync(&entry.carrier, entry.version)?;
                    }
                    db.delete_surface_state(&key)?;
                    self.expire_surface_placeholder(&entry.carrier)?;
                }
            }
            db.persist_actor_state("surface/pending_expiry_cursor", &next)?;
            Ok(())
        })
    }
    fn surface_pending_member(&self, carrier: &Carrier) -> Result<bool, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let Some(thread) =
            self.account_db()?.client_record("conversation", &carrier.conversation_id)?
        else {
            return Ok(false);
        };
        if let Some(group) = thread["group_id"].as_str() {
            Ok(self.surface_group_device_allowed(group, &carrier.sender_device_id)?
                && self.surface_group_device_allowed(group, &local.device_id)?)
        } else {
            let peers = thread["participants"]
                .as_array()
                .ok_or_else(|| invalid("surface pending conversation participants missing"))?;
            Ok(peers.iter().any(|p| p == &carrier.sender_principal_id)
                && peers.iter().any(|p| p == &local.principal_id))
        }
    }
}

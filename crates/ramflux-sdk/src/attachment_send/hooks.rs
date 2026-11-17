// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Where the send path meets retirement: binding at authoring, and retiring grants of devices
//! that stopped being targets before admission.

use ramflux_protocol::message::{MediaKeySlot, MediaRef, QualifiedDevice};

use super::bus::AuthorityPin;
use super::meta::GrantRecord;
use super::plane::Plane;
use super::retire::{self, Sent, Source, Subset};
use crate::bus::state::LocalBusAccountState;
use crate::gateway::GatewayCustodyConfig;
use crate::{RamfluxClient, SdkError};

/// What the authoring step needs to bind grants to the actual message id.
#[derive(Clone)]
pub(crate) struct Binding {
    pub custody: GatewayCustodyConfig,
    pub source: String,
    pub generation: u64,
    pub public_key: [u8; 32],
}

impl Binding {
    pub(crate) fn of(account: &LocalBusAccountState, pin: &AuthorityPin) -> Result<Self, SdkError> {
        Ok(Self {
            custody: account.gateway_config.custody.clone().ok_or(SdkError::NetworkingPending)?,
            source: pin.source.clone(),
            generation: pin.generation,
            public_key: pin.public_key,
        })
    }
}

/// Called from the authored-message capture, before the first envelope leaves: binds every
/// grant of every large attachment of this message to the actual message id.
/// # Errors
/// Returns the retirement refusal; the message is then not submitted.
pub(crate) fn bind_authored(
    client: &RamfluxClient,
    message_id: &str,
    media: &[MediaRef],
) -> Result<(), SdkError> {
    let Some(binding) = client.attachment_binding.as_ref() else {
        return Ok(());
    };
    let db = client.account_db()?;
    let mut prepares = Vec::new();
    for reference in media.iter().filter(|reference| reference.large_manifest.is_some()) {
        let Some(row) = db.client_record("attachment-object", &reference.object_id)? else {
            continue;
        };
        let prepare = row
            .get("prepare_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(SdkError::ReplayMismatch)?;
        prepares.push((prepare, reference));
    }
    if prepares.is_empty() {
        return Ok(());
    }
    let files: Vec<Sent<'_>> =
        prepares.iter().map(|(prepare_id, media)| Sent { prepare_id, media }).collect();
    let source = Source {
        authority: &binding.source,
        generation: binding.generation,
        public_key: &binding.public_key,
    };
    let now = super::unix_now()?;
    retire::with_client_ctx(client, &binding.custody, |ctx| {
        retire::bind_message(ctx, message_id, &files, &source, now)
    })
}

/// Retires registered grants of devices that left the roster. The grants are bound under the
/// unadmitted name of the prepare, signed, queued and delivered; a failed delivery stays queued
/// for the sweep.
/// # Errors
/// Returns the retirement refusal.
pub(crate) fn retire_excluded(
    account: &LocalBusAccountState,
    pin: &AuthorityPin,
    plane: &dyn Plane,
    prepare_id: &str,
    base: &MediaRef,
    grants: &[GrantRecord],
) -> Result<(), SdkError> {
    let slots: Vec<MediaKeySlot> = grants
        .iter()
        .filter_map(|grant| {
            Some(MediaKeySlot {
                recipient: Some(QualifiedDevice {
                    account_anchor: grant.account_anchor.clone(),
                    device_id: grant.device_id.clone(),
                    device_epoch: grant.device_epoch,
                }),
                encrypted_key: Vec::new(),
                format: 1,
                grant_id: grant.grant_id.to_vec(),
                read_capability: grant.capability.clone()?,
            })
        })
        .collect();
    if slots.is_empty() {
        return Ok(());
    }
    let only: Vec<[u8; 32]> = grants
        .iter()
        .filter(|grant| grant.capability.is_some())
        .map(|grant| grant.grant_id)
        .collect();
    let mut media = base.clone();
    media.key_slots = slots;
    let message_id = format!("unadmitted:{prepare_id}");
    let files = [Sent { prepare_id, media: &media }];
    let source =
        Source { authority: &pin.source, generation: pin.generation, public_key: &pin.public_key };
    let now = super::unix_now()?;
    retire::with_ctx(account, |ctx| {
        retire::retire_grants(
            ctx,
            Some(plane),
            &Subset { message_id: &message_id, files: &files, only: &only },
            &source,
            now,
        )
    })
    .map(|_| ())
}

/// Delivers every queued retirement through `plane`, one blocking call at a time on a worker,
/// never on the account actor. An unreachable relay leaves the work queued.
/// # Errors
/// Returns a storage or signing failure; delivery failures are not errors.
pub(crate) async fn deliver_pending(
    account: &LocalBusAccountState,
    plane: std::sync::Arc<dyn Plane>,
    pin: &AuthorityPin,
) -> Result<retire::Delivery, SdkError> {
    let source =
        Source { authority: &pin.source, generation: pin.generation, public_key: &pin.public_key };
    let mut out = retire::Delivery::default();
    let mut after: Option<[u8; 32]> = None;
    loop {
        let now = super::unix_now()?;
        let page = retire::with_ctx(account, |ctx| retire::pending_page(ctx, after.as_ref(), now))?;
        let Some(last) = page.last() else { break };
        after = Some(last.signed.request().operation_id);
        let full = page.len() >= 64;
        for item in page {
            let worker = std::sync::Arc::clone(&plane);
            let (item, reply) = tokio::task::spawn_blocking(move || {
                let reply = retire::call_retire(worker.as_ref(), &item);
                (item, reply)
            })
            .await
            .map_err(|_| SdkError::GatewaySessionNotEstablished)?;
            retire::with_ctx(account, |ctx| {
                retire::settle(ctx, &source, &item, Some(reply), &mut out)
            })?;
        }
        if !full {
            break;
        }
    }
    Ok(out)
}

/// Startup and send-time sweep: finishes interrupted wipes and redelivers queued retirements.
/// Best effort; a failure is retried at the next call.
pub(crate) async fn sweep(account: &LocalBusAccountState, pin: &AuthorityPin) {
    let Ok(plane) = super::plane_for(account) else { return };
    let _ = retire::with_ctx(account, |ctx| ctx.store.cleanup_cancelled().map_err(SdkError::from));
    let _ = deliver_pending(account, plane, pin).await;
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated native send admission into the existing durable opaque inbox.
use crate::{
    InboxEntry, RouterCore, RouterRedbStore, RouterSubmitOutcome, envelope_replay_tuple_key,
};
use ramflux_crypto::{RootQualifiedDeviceRef, custody::VerifiedRecord};
use ramflux_protocol::custody::{CustodyRefusal, CustodyServerFrame, CustodySession};
fn invalid(_: impl std::fmt::Display) -> CustodyRefusal {
    CustodyRefusal::InvalidInput
}
#[derive(Clone, Copy)]
pub(crate) struct DeliveryAuthority<'a> {
    pub authority: &'a VerifiedRecord,
    pub session: &'a CustodySession,
    pub source: &'a RootQualifiedDeviceRef,
}
pub(crate) fn submit(
    router: &RouterCore,
    store: &RouterRedbStore,
    credentials: DeliveryAuthority<'_>,
    envelope: ramflux_protocol::Envelope,
    now: u64,
) -> Result<CustodyServerFrame, CustodyRefusal> {
    let DeliveryAuthority { authority, session, source } = credentials;
    let cert = authority.authorize(&session.device_ref, "message", now).map_err(invalid)?;
    if envelope.source_device_id != session.device_ref.device_id
        || envelope.source_principal_id != authority.envelope().body.principal_id
        || envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
            != Some(source.root_commitment())
        || envelope.schema != "ramflux.envelope.v1"
        || envelope.domain != ramflux_protocol::domain::ENVELOPE
        || envelope.version != 1
    {
        return Err(CustodyRefusal::InvalidInput);
    }
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::envelope_sender_signed_bytes(&envelope).map_err(invalid)?,
        &envelope.signed.signature,
        &cert.branch_signing_public_key,
    )
    .map_err(invalid)?;
    if store
        .custody_prekey(&envelope.target_delivery_id)
        .map_err(|_| CustodyRefusal::PersistenceUnavailable)?
        .is_none()
    {
        return Err(CustodyRefusal::AuthorityUnavailable);
    }
    let replay = envelope_replay_tuple_key(source, &envelope);
    let expiry = envelope
        .created_at
        .checked_add(i64::from(envelope.ttl))
        .ok_or(CustodyRefusal::InvalidInput)?;
    let id = envelope.envelope_id.clone();
    let outcome = router.submit_envelope_at(source, envelope, i64::try_from(now).map_err(invalid)?);
    let (entry, status) = match outcome {
        RouterSubmitOutcome::Online(delivery) => (
            InboxEntry {
                inbox_seq: delivery.inbox_seq,
                target_delivery_id: delivery.target_delivery_id,
                envelope: delivery.envelope,
            },
            "online",
        ),
        RouterSubmitOutcome::OfflineQueued(queued) => (queued.entry, "offline_queued"),
        _ => return Err(CustodyRefusal::InvalidInput),
    };
    if let Err(error) = store.record_submission_increment(&replay, expiry, Some(&entry)) {
        tracing::error!(%error,"custody inbox persistence failed after acceptance; terminating to avoid a state fork");
        std::process::abort();
    }
    Ok(CustodyServerFrame::Submitted { envelope_id: id, outcome: status.into() })
}

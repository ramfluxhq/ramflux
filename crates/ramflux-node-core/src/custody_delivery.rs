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

fn candidate_size_preflight(envelope: &ramflux_protocol::Envelope) -> Result<(), CustodyRefusal> {
    if !ramflux_protocol::schema_profile::schema_v1_live() {
        return Ok(());
    }
    ramflux_protocol::message::outer::refuse_live_bridge(envelope).map_err(map_outer_profile)?;
    let sizes = ramflux_protocol::message::outer::IngressSizes::measure_live(envelope, &[], &[])
        .map_err(map_outer_profile)?;
    ramflux_protocol::message::outer::check_ingress_caps(sizes).map_err(map_outer_profile)
}

fn map_outer_profile(error: ramflux_protocol::message::outer::OuterProfileError) -> CustodyRefusal {
    use ramflux_protocol::message::outer::OuterProfileError;
    match error {
        OuterProfileError::PayloadTooLarge => CustodyRefusal::PayloadTooLarge,
        _ => CustodyRefusal::InvalidInput,
    }
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
    candidate_size_preflight(&envelope)?;
    ramflux_protocol::ephemeral::require_durable(&envelope)
        .map_err(|_| CustodyRefusal::InvalidInput)?;
    let DeliveryAuthority { source, .. } = credentials;
    verify_sender(credentials, &envelope, now)?;
    let lease = acquire_submission(router, store, &envelope, now)?;
    if store
        .custody_prekey(&envelope.target_delivery_id)
        .map_err(|_| CustodyRefusal::PersistenceUnavailable)?
        .is_none()
    {
        return Err(CustodyRefusal::AuthorityUnavailable);
    }
    let retry_owner = match store
        .admit_sender_retry(source, &envelope, i64::try_from(now).map_err(invalid)?)
        .map_err(|error| crate::sender_retry::custody_refusal(&error))?
    {
        crate::sender_retry::RetryAdmission::Owner(owner) => owner,
        retry => {
            drop(lease);
            let assignment = match retry {
                crate::sender_retry::RetryAdmission::Accepted(assignment) => assignment,
                crate::sender_retry::RetryAdmission::Waiting(waiter) => waiter
                    .resolved_blocking()
                    .map_err(|error| crate::sender_retry::custody_refusal(&error))?,
                crate::sender_retry::RetryAdmission::Owner(_) => unreachable!(),
            };
            crate::publication::await_sender_retry(
                &store
                    .publication_core()
                    .map_err(|error| crate::sender_retry::custody_refusal(&error))?,
                assignment,
            )
            .map_err(|error| crate::sender_retry::custody_refusal(&error))?;
            return Ok(CustodyServerFrame::Submitted {
                envelope_id: envelope.envelope_id,
                outcome: "offline_queued".into(),
            });
        }
    };
    retry_owner
        .bind(&envelope.target_delivery_id)
        .map_err(|error| crate::sender_retry::custody_refusal(&error))?;
    router
        .prepare_publication_target(store, &envelope.target_delivery_id)
        .map_err(|_| CustodyRefusal::PersistenceUnavailable)?;
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
        RouterSubmitOutcome::RejectedSecurity { reason, .. } => {
            if reason == "payload_too_large" {
                return Err(CustodyRefusal::PayloadTooLarge);
            }
            return Err(crate::sender_retry::refusal_from_reason(&reason)
                .as_ref()
                .map_or(CustodyRefusal::InvalidInput, crate::sender_retry::custody_refusal));
        }
        _ => return Err(CustodyRefusal::InvalidInput),
    };
    if let Err(error) = store.record_leased_submission(
        &replay,
        expiry,
        Some(&entry),
        Some(source.root_commitment()),
        Some(lease),
    ) {
        if crate::publication::proved_non_write() {
            return Err(CustodyRefusal::AbortedRetrySafe);
        }
        tracing::error!(%error,"custody inbox persistence failed after acceptance; terminating to avoid a state fork");
        std::process::abort();
    }
    retry_owner.accepted_entry(
        store,
        source.root_commitment(),
        &entry,
        i64::try_from(now).unwrap_or(i64::MAX),
    );
    Ok(CustodyServerFrame::Submitted { envelope_id: id, outcome: status.into() })
}

fn verify_sender(
    credentials: DeliveryAuthority<'_>,
    envelope: &ramflux_protocol::Envelope,
    now: u64,
) -> Result<(), CustodyRefusal> {
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
        &ramflux_protocol::envelope_sender_signed_bytes(envelope).map_err(invalid)?,
        &envelope.signed.signature,
        &cert.branch_signing_public_key,
    )
    .map_err(invalid)?;
    Ok(())
}

fn acquire_submission(
    router: &RouterCore,
    store: &RouterRedbStore,
    envelope: &ramflux_protocol::Envelope,
    now: u64,
) -> Result<crate::SubmissionLease, CustodyRefusal> {
    match store.acquire_submission(&envelope.target_delivery_id) {
        Ok(lease) => Ok(lease),
        Err(crate::NodeCoreError::HomeMigration(reason)) => {
            let response = router
                .migration_submission_refusal(store, envelope, reason, now)
                .map_err(|_| CustodyRefusal::PersistenceUnavailable)?;
            Err(CustodyRefusal::HomeMigration { reason, nack: response.nack.map(Box::new) })
        }
        Err(_) => Err(CustodyRefusal::PersistenceUnavailable),
    }
}

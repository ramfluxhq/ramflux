// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Routes one sealed own-device envelope through the real `RouterCore` and `RouterRedbStore`, so a
//! test can deliver it to a receiver as the node would (shared by the task-courier and agent tests).
use crate::time::now_unix_timestamp;

pub(crate) async fn publish_router_envelope(
    router: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: ramflux_protocol::Envelope,
) -> Result<ramflux_node_core::InboxEntry, ramflux_node_core::NodeCoreError> {
    router.prepare_publication_target(store, &envelope.target_delivery_id)?;
    let replay = ramflux_node_core::envelope_replay_tuple_key(source, &envelope);
    let expiry = envelope.created_at.checked_add(i64::from(envelope.ttl)).ok_or_else(|| {
        ramflux_node_core::NodeCoreError::Redb("fixture replay expiry overflow".into())
    })?;
    let now = now_unix_timestamp();
    let admission = store.admit_sender_retry(source, &envelope, now)?;
    let (owner, retry) = match admission {
        ramflux_node_core::sender_retry::RetryAdmission::Owner(owner) => (Some(owner), None),
        ramflux_node_core::sender_retry::RetryAdmission::Accepted(retry) => (None, Some(retry)),
        ramflux_node_core::sender_retry::RetryAdmission::Waiting(waiter) => {
            (None, Some(waiter.resolved().await?))
        }
    };
    let operation = ramflux_node_core::publication::capture(|| {
        if let Some(retry) = retry {
            let assignment = ramflux_node_core::publication::await_sender_retry(
                &store.publication_core()?,
                retry,
            )?;
            return Ok(ramflux_node_core::InboxEntry {
                inbox_seq: assignment.inbox_seq,
                target_delivery_id: assignment.target_delivery_id,
                envelope,
            });
        }
        let owner = owner.ok_or_else(|| {
            ramflux_node_core::NodeCoreError::Redb("test: retry owner missing".into())
        })?;
        owner.bind(&envelope.target_delivery_id)?;
        let entry = match router.submit_envelope(source, envelope) {
            ramflux_node_core::RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
            ramflux_node_core::RouterSubmitOutcome::Online(online) => {
                ramflux_node_core::InboxEntry {
                    inbox_seq: online.inbox_seq,
                    target_delivery_id: online.target_delivery_id,
                    envelope: online.envelope,
                }
            }
            other => {
                return Err(ramflux_node_core::NodeCoreError::Redb(format!(
                    "fixture router submit {other:?}"
                )));
            }
        };
        store.record_submission_increment_for_sender(
            &replay,
            expiry,
            Some(&entry),
            Some(source.root_commitment()),
        )?;
        owner.accepted_entry(store, source.root_commitment(), &entry, now);
        Ok(entry)
    })?;
    operation.published().await
}

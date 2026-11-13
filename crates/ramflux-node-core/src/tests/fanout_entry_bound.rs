// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T3b preflights the rewritten child before replay or multi-target reservation.
use super::*;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn entry_admission_all_origins_fanout() -> Result {
    for mode in 0..=1 {
        for over in [false, true] {
            let _store_directory_0 = temp_store_path(&format!("fanout-entry-bound-{mode}-{over}"))?;
            let root = _store_directory_0.to_path_buf();
            let store = crate::publication::open_durability_fixture(&root, mode)?;
            let router = RouterCore::new();
            store.bootstrap_router(&router)?;
            for (device, seed) in [("source", 601), ("left", 602)] {
                let mut registration =
                    registration_request(&router, "fanout", device, seed, None, device)?;
                registration.target_delivery_id = format!("target_{device}");
                registration.session_id = format!("session_{device}");
                router.mvp1_register_identity(&registration)?;
            }
            let mut raw =
                envelope("parent-entry-bound", "unused", DeliveryClass::SelfDeviceControl);
            raw.created_at = i64::try_from(crate::now_unix_seconds())?;
            raw.encrypted_payload.clear();
            let envelope = signed_registered_envelope(raw, "fanout", "source", 601)?;
            let mut normalized = envelope.clone();
            router.refresh_registered_envelope_authority(&mut normalized)?;
            normalized.target_delivery_id = "target_left".into();
            normalized.envelope_id = mvp10_fanout_envelope_id(&envelope.envelope_id, "left");
            let base = crate::single_entry_frame_size(&normalized)?;
            let mut envelope = envelope;
            envelope.encrypted_payload =
                "x".repeat(crate::ENTRY_FRAME_BYTE_CAP - base + usize::from(over));
            let envelope = signed_registered_envelope(envelope, "fanout", "source", 601)?;
            let now = envelope.created_at;
            let request = ItestMvp10OwnDeviceFanoutRequest {
                principal_id: "fanout".into(),
                source_device_id: "source".into(),
                envelope,
            };
            let prepared = crate::publication::capture(|| {
                router.prepare_sender_fanout(&store, &request, now)
            })?
            .published_blocking()??
            .resolved_blocking()?;
            assert_eq!(prepared.delivered.len(), 1);
            if over {
                assert_eq!(prepared.delivered[0].outcome, "payload_too_large");
            } else {
                assert!(matches!(
                    prepared.delivered[0].outcome.as_str(),
                    "online" | "offline_queued"
                ));
            }
            assert_eq!(store.inbox_status("target_left")?.1, u64::from(!over));
            assert_eq!(router.resume("target_left", 0, 10).len(), usize::from(!over));
            assert_eq!(store.sender_retry_registry_size(), 0);
            if over {
                legacy_retry(&router, &store, &request, normalized, now)?;
            }
        }
    }
    Ok(())
}

fn legacy_retry(
    router: &RouterCore,
    store: &crate::RouterRedbStore,
    request: &ItestMvp10OwnDeviceFanoutRequest,
    mut child: Envelope,
    now: i64,
) -> Result {
    // A pre-bound row may be above today's admission limit. Its retry creates nothing.
    child.encrypted_payload.clone_from(&request.envelope.encrypted_payload);
    child.signed.signature.clone_from(&request.envelope.signed.signature);
    let source = router.authenticated_envelope_source_durable(&request.envelope, store)?;
    let replay_key = crate::envelope_replay_tuple_key(&source, &child);
    let row = crate::InboxEntry {
        inbox_seq: 1,
        target_delivery_id: child.target_delivery_id.clone(),
        envelope: child,
    };
    let lease = store.acquire_submission(&row.target_delivery_id)?;
    store.record_leased_submission(
        &replay_key,
        now + 3600,
        Some(&row),
        Some(source.root_commitment()),
        Some(lease),
    )?;
    store.record_identity_registry(&router.mvp1_identities_snapshot())?;
    let restored = store.load_router()?.ok_or("legacy restore")?;
    restored.prepare_publication_target(store, &row.target_delivery_id)?;
    let reply =
        crate::publication::capture(|| restored.prepare_sender_fanout(store, request, now))?
            .published_blocking()??
            .resolved_blocking()?;
    assert_eq!(reply.delivered[0].inbox_seq, Some(1));
    assert_eq!(store.inbox_status(&row.target_delivery_id)?.1, 1);
    assert_eq!(store.sender_retry_registry_size(), 0);
    Ok(())
}

#[test]
fn legacy_fanout_prepares_and_measures_each_child_once() -> Result {
    for mode in 0..=1 {
        for leased in [false, true] {
            let _store_directory_1 =
                temp_store_path(&format!("legacy-fanout-once-{mode}-{leased}"))?;
            let root = _store_directory_1.to_path_buf();
            let store = crate::publication::open_durability_fixture(&root, mode)?;
            let router = RouterCore::new();
            store.bootstrap_router(&router)?;
            for (device, seed) in [("source", 601), ("left", 602)] {
                let mut registration =
                    registration_request(&router, "fanout", device, seed, None, device)?;
                registration.target_delivery_id = format!("target_{device}");
                registration.session_id = format!("session_{device}");
                router.mvp1_register_identity(&registration)?;
            }
            let mut raw = envelope("legacy-once", "unused", DeliveryClass::SelfDeviceControl);
            raw.created_at = i64::try_from(crate::now_unix_seconds())?;
            raw.encrypted_payload = "x".repeat(64 * 1024);
            let envelope = signed_registered_envelope(raw, "fanout", "source", 601)?;
            let now = envelope.created_at;
            let request = ItestMvp10OwnDeviceFanoutRequest {
                principal_id: "fanout".into(),
                source_device_id: "source".into(),
                envelope,
            };
            let mut child = request.envelope.clone();
            router.refresh_registered_envelope_authority(&mut child)?;
            child.target_delivery_id = "target_left".into();
            child.envelope_id = mvp10_fanout_envelope_id(&request.envelope.envelope_id, "left");
            let expected = serde_json::to_vec(&serde_json::json!({"inbox_seq":u64::MAX,"target_delivery_id":child.target_delivery_id,"envelope":child}))?.len();
            crate::entry_bound::SIZED_BYTES.with(|count| count.set(0));
            let (plan, leases) = if leased {
                crate::publication::capture(|| router.accept_leased_fanout(request, &store, now))?
                    .published_blocking()??
            } else {
                (router.accept_own_device_fanout_replay(request, now)?, Vec::new())
            };
            let measured = crate::entry_bound::SIZED_BYTES.with(std::cell::Cell::get);
            assert_eq!(plan.deliveries.len(), 1);
            assert_eq!(
                measured, expected,
                "actual serializer bytes: one normalized child per check"
            );
            drop(leases);
        }
    }
    Ok(())
}

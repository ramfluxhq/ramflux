// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T3b preflights the rewritten child before replay or multi-target reservation.
use super::*;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn entry_admission_all_origins_fanout() -> Result {
    for mode in 0..=1 {
        for over in [false, true] {
            let root = temp_store_path(&format!("fanout-entry-bound-{mode}-{over}"))?;
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
            let prepared = crate::publication::capture(|| {
                router.prepare_sender_fanout(
                    &store,
                    &ItestMvp10OwnDeviceFanoutRequest {
                        principal_id: "fanout".into(),
                        source_device_id: "source".into(),
                        envelope,
                    },
                    now,
                )
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
        }
    }
    Ok(())
}

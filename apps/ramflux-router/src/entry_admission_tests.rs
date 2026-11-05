// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T3a/c/d use real authenticated router ingress and independent final-frame sizes.
use ramflux_node_core::{ENTRY_FRAME_BYTE_CAP, RouterCore};
use std::sync::Arc;
fn wire_size(envelope: &ramflux_protocol::Envelope) -> anyhow::Result<usize> {
    let entry = serde_json::json!({"inbox_seq":u64::MAX,"target_delivery_id":envelope.target_delivery_id,"envelope":envelope});
    let frames = [
        serde_json::json!({"frame_type":"deliver","entry":entry}),
        serde_json::json!({"frame_type":"deliver","incarnation_id":"ffffffffffffffffffffffffffffffff","entry":entry,"retain_until":i64::MIN}),
        serde_json::json!({"frame_type":"entry","incarnation_id":"ffffffffffffffffffffffffffffffff","record":{"entry":entry,"retain_until":i64::MIN}}),
    ];
    frames
        .iter()
        .map(|value| Ok(serde_json::to_vec(value)?.len()))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .max()
        .ok_or_else(|| anyhow::anyhow!("no frames"))
}
fn run(origin: &str) -> anyhow::Result<()> {
    for mode in 0..=1 {
        for over in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "entry-bound-{origin}-{mode}-{over}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
            ));
            let store =
                Arc::new(ramflux_node_core::publication::open_durability_fixture(&root, mode)?);
            let state = Arc::new(RouterCore::new());
            let mut envelope =
                crate::router_runtime::tests::current_envelope("entry-bound", "point-target")?;
            crate::router_runtime::tests::register_test_device_at(
                &state,
                "alice",
                "alice_phone",
                "target_alice",
                1,
                envelope.created_at,
            )?;
            state.refresh_registered_envelope_authority(&mut envelope)?;
            envelope
                .ext
                .ext
                .insert("escaped_metadata".into(), serde_json::json!("\"\\\n".repeat(30)));
            envelope.encrypted_payload.clear();
            let base = wire_size(&envelope)?;
            envelope.encrypted_payload =
                "x".repeat(ENTRY_FRAME_BYTE_CAP - base + usize::from(over));
            envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(
                &envelope,
                ramflux_crypto::blake3_256("ramflux.test.runtime.device.v1", b"alice/alice_phone"),
            )?;
            assert_eq!(wire_size(&envelope)?, ENTRY_FRAME_BYTE_CAP + usize::from(over));
            if origin == "gateway" {
                envelope.ext.ext.remove("source_device_authority");
            }
            let handle =
                crate::router_runtime::RouterHandle::tokio(state.clone(), store.clone(), None);
            let migration = origin == "migration";
            let body = if migration {
                serde_json::json!({"peer_node_id":"entry-bound-peer","envelope":envelope,"migration_evidence":{"commit_proof":null,"retain_until":envelope.created_at+120,"floors":[]}})
            } else {
                serde_json::to_value(&envelope)?
            };
            let response = crate::handlers::handle_mesh_request_value(
                ramflux_transport::MeshHttpRequest {
                    method: "POST".into(),
                    path: if migration { "/mvp0/envelope/forwarded" } else { "/mvp0/envelope" }
                        .into(),
                    body: serde_json::to_vec(&body)?,
                },
                &handle,
                if origin == "gateway" { "ramflux-gateway" } else { "ramflux-federation" },
            )?;
            let value: serde_json::Value = serde_json::from_slice(&response.body)?;
            let delivery = if migration { &value["delivery"] } else { &value };
            if over {
                assert_eq!(delivery["outcome"], "payload_too_large", "{value}");
                assert_eq!(
                    state.resume("point-target", 0, 10),
                    Vec::<ramflux_node_core::InboxEntry>::new()
                );
                assert_eq!(store.inbox_status("point-target")?.1, 0);
                assert_eq!(store.sender_retry_registry_size(), 0);
                if migration {
                    assert_eq!(value["retryable"], false);
                }
            } else {
                assert_eq!(delivery["inbox_seq"], 1, "{value}");
                assert_eq!(store.inbox_status("point-target")?.1, 1);
                assert_eq!(state.resume("point-target", 0, 10).len(), 1);
            }
            drop(handle);
            drop(state);
            drop(store);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}
#[test]
fn entry_admission_all_origins_gateway() -> anyhow::Result<()> {
    run("gateway")
}
#[test]
fn entry_admission_all_origins_federation() -> anyhow::Result<()> {
    run("federation")
}
#[test]
fn entry_admission_all_origins_migration() -> anyhow::Result<()> {
    run("migration")
}

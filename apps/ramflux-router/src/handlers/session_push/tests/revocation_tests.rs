// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Accepted metadata remains authoritative after a sender is revoked.
use super::*;
#[test]
fn accepted_reply_survives_sender_revocation() -> anyhow::Result<()> {
    for kind in ["submit", "forward", "fanout"] {
        for quic in [false, true] {
            revocation_case(kind, quic)?;
        }
    }
    Ok(())
}
fn revocation_case(kind: &str, quic: bool) -> anyhow::Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let (state, store, path) = crate::router_runtime::tests::test_router("post-commit-revocation")?;
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    if kind == "fanout" {
        crate::router_runtime::tests::register_test_device_at(
            &state,
            "alice",
            "alice_tablet",
            "target_tablet",
            2,
            now,
        )?;
    }
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    let mut envelope =
        crate::router_runtime::tests::current_envelope("committed-before-revoke", "reply-target")?;
    if kind == "forward" {
        state.refresh_registered_envelope_authority(&mut envelope)?;
    }
    let (request, commitment) = revoked_set(&state, now)?;
    let revoked = Arc::new(AtomicBool::new(false));
    let (flag, actor, persistence) = (Arc::clone(&revoked), Arc::clone(&state), Arc::clone(&store));
    let hook = ramflux_node_core::durability_test_hooks::observe(
        path.clone(),
        Arc::new(move |_, operation, _| {
            if operation == "sender_reply_lookup" && !flag.swap(true, Ordering::SeqCst) {
                actor
                    .publish_signed_device_set(&request, &persistence)
                    .map_err(std::io::Error::other)?;
            }
            Ok(())
        }),
    );
    let handle = RouterHandle::tokio(state, store, None);
    let (route, body, peer) = match kind {
        "submit" => ("/mvp0/envelope", serde_json::to_value(&envelope)?, "ramflux-gateway"),
        "forward" => (
            "/mvp0/envelope/forwarded",
            json!({"envelope":envelope,"migration_evidence":null}),
            "ramflux-federation",
        ),
        _ => (
            "/mvp10/own-devices/fanout",
            json!({"principal_id":"alice","source_device_id":"alice_phone","envelope":envelope}),
            "ramflux-gateway",
        ),
    };
    let response = if quic {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(super::super::super::handle_mesh_quic_request_value(
                &ramflux_transport::GatewayQuicRequest {
                    method: "POST".into(),
                    path: route.into(),
                    body,
                },
                &handle,
                peer,
            ))?
            .body
    } else {
        let response = super::super::super::handle_mesh_request_value(
            ramflux_transport::MeshHttpRequest {
                method: "POST".into(),
                path: route.into(),
                body: serde_json::to_vec(&body)?,
            },
            &handle,
            peer,
        )?;
        serde_json::from_slice(&response.body)?
    };
    assert!(revoked.load(Ordering::SeqCst), "real post-commit hook");
    assert!(handle.state().signed_device_set(&commitment).is_some_and(|s| {
        s.devices.iter().any(|d| {
            d.device_id == "alice_phone" && d.status == ramflux_protocol::DeviceSetStatus::Revoked
        })
    }));
    let delivery = match kind {
        "submit" => &response,
        "forward" => &response["delivery"],
        _ => &response["delivered"][0],
    };
    let target = delivery["target_delivery_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("reply: {response}"))?;
    assert_eq!(delivery["inbox_seq"], 1);
    let point = serde_json::to_value(handle.state().fetch_entry(target, 1, 0)?)?;
    assert_eq!(delivery["incarnation_id"], point["incarnation_id"]);
    assert_eq!(delivery["retain_until"], point["record"]["retain_until"]);
    drop(hook);
    drop(handle);
    std::fs::remove_file(path)?;
    Ok(())
}
fn revoked_set(
    state: &ramflux_node_core::RouterCore,
    now: i64,
) -> anyhow::Result<(ramflux_node_core::DeviceSetPublishRequest, String)> {
    let root = ramflux_crypto::create_identity_root(
        "alice",
        ramflux_crypto::blake3_256("ramflux.test.registration_root.v1", b"alice"),
    );
    let commitment = ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
    let mut old = state.signed_device_set(&commitment).ok_or_else(|| anyhow::anyhow!("set"))?;
    for entry in &mut old.devices {
        if entry.device_id == "alice_phone" {
            entry.status = ramflux_protocol::DeviceSetStatus::Revoked;
            entry.revoked_at = Some(now);
        }
    }
    let record = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: old.principal_kind,
            device_set_epoch: old.device_set_epoch + 1,
            devices: old.devices,
        },
    )?;
    let request = ramflux_node_core::DeviceSetPublishRequest {
        root_public_key: ramflux_protocol::encode_base64url(
            root.signing_key.verifying_key().to_bytes(),
        ),
        record,
    };
    Ok((request, commitment))
}

#[test]
fn incarnation_mismatch_precedes_future_sequence() -> anyhow::Result<()> {
    let (router, path, accepted) = seed("E-before-sequence")?;
    let wrong = "ffffffffffffffffffffffffffffffff";
    for seq in [1, 2, u64::MAX] {
        let batch = call(
            &router,
            "POST",
            "/mvp0/ack-bound-batch",
            json!({"target_delivery_id":"target","incarnation_id":wrong,"inbox_seqs":[seq]}),
        )?;
        let ack = json!({"schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1","ext":{"inbox_seq":seq},"signing_key_id":"test","signature_alg":"ed25519","signature":"","ack_id":"ack","envelope_id":"unused","receiver_device_id":"receiver","received_at":0,"cursor_after":null});
        let bound = call(
            &router,
            "POST",
            "/mvp0/ack-bound",
            json!({"target_delivery_id":"target","incarnation_id":wrong,"ack":ack}),
        )?;
        let point = call(
            &router,
            "GET",
            &format!("/mvp1/inbox-entry/target/{seq}?incarnation_id={wrong}"),
            Value::Null,
        )?;
        for reply in [batch, bound, point] {
            assert_eq!(reply["reason"], "incarnation_mismatch");
            assert_eq!(reply["incarnation_id"], accepted["incarnation_id"]);
        }
    }
    assert_eq!(router.state().resume("target", 0, 10).len(), 1);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

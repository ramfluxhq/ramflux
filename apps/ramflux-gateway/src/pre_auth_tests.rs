// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{GatewayQuicContext, gateway_state, session::pre_auth_gate_for_gateway_open};
use ramflux_node_core::{GatewayClientFrame, GatewayOpenFrame, GatewayPreAuthPolicy};

fn context() -> anyhow::Result<GatewayQuicContext> {
    let context = crate::session::tests::test_gateway_context()?;
    gateway_state(&context.state)?.set_pre_auth_policy(GatewayPreAuthPolicy {
        enabled: true,
        per_source_ip_handshake_rate: 1,
        window_seconds: 3_600,
        ..GatewayPreAuthPolicy::default()
    })?;
    Ok(context)
}

// Exercise the same strict frame decoder used by Quinn, TCP+TLS and compio.
fn open(source: &str, now: u64) -> anyhow::Result<GatewayOpenFrame> {
    let frame = GatewayClientFrame::Open {
        open: GatewayOpenFrame {
            protocol_version: ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION.to_owned(),
            transport_kind: "quic_quinn".to_owned(),
            client_instance_id: "preauth-source-test".to_owned(),
            device_id: "device".to_owned(),
            target_delivery_id: "target".to_owned(),
            stream_nonce: "nonce".to_owned(),
            previous_session_id: None,
            resume_token_hash: None,
            last_seen_inbox_seq: None,
            max_inflight_downstream: 4,
            max_inflight_upstream: 4,
            pre_auth_cookie: None,
            pre_auth_now: Some(now),
            source_ip_hash: Some(source.to_owned()),
        },
    };
    let bytes = serde_json::to_vec(&frame)?;
    let crate::ingress::Ingress::Session(decoded) =
        crate::ingress::parse(&bytes, "192.0.2.1".parse()?)?
    else {
        anyhow::bail!("Open must retain its existing wire shape");
    };
    let GatewayClientFrame::Open { open } = *decoded else {
        anyhow::bail!("expected decoded Open");
    };
    Ok(open)
}

#[test]
fn rotating_source_claims_cannot_reset_pre_auth_bucket() -> anyhow::Result<()> {
    let context = context()?;
    assert!(pre_auth_gate_for_gateway_open(&open("claim-0", 1)?, &context)?.is_none());
    for attempt in 1..=4 {
        let frame = open(&format!("claim-{attempt}"), 1)?;
        assert!(
            pre_auth_gate_for_gateway_open(&frame, &context)?.is_some(),
            "rotating a client source claim must not grant another handshake"
        );
    }
    Ok(())
}

#[test]
fn advancing_client_clock_cannot_expire_pre_auth_attempts() -> anyhow::Result<()> {
    let context = context()?;
    assert!(pre_auth_gate_for_gateway_open(&open("same-claim", 1)?, &context)?.is_none());
    assert!(
        pre_auth_gate_for_gateway_open(&open("same-claim", 86_400)?, &context)?.is_some(),
        "client time must not expire a server-observed handshake"
    );
    Ok(())
}

#[test]
fn distinct_transport_peers_do_not_share_client_claimed_bucket() -> anyhow::Result<()> {
    let mut context = context()?;
    for source in
        ["192.0.2.1:1234", "192.0.2.2:1234", "[2001:db8:1:2::1]:1234", "[2001:db8:1:3::1]:1234"]
    {
        context.remote_addr = source.parse()?;
        assert!(
            pre_auth_gate_for_gateway_open(&open("shared-claim", 1)?, &context)?.is_none(),
            "distinct transport bucket {source} must have its own allowance"
        );
    }
    Ok(())
}

#[test]
fn ipv4_mapped_nat64_and_ipv6_prefix_aliases_share_observed_buckets() -> anyhow::Result<()> {
    let mut context = context()?;
    for (index, source) in ["192.0.2.1:1234", "[::ffff:192.0.2.1]:4321", "[64:ff9b::c000:201]:5678"]
        .into_iter()
        .enumerate()
    {
        context.remote_addr = source.parse()?;
        let challenge =
            pre_auth_gate_for_gateway_open(&open(&format!("alias-{index}"), 1)?, &context)?;
        assert_eq!(challenge.is_some(), index > 0, "one IPv4 source bucket: {source}");
    }
    context.remote_addr = "[64:ff9b::c000:202]:1234".parse()?;
    assert!(pre_auth_gate_for_gateway_open(&open("other-nat64", 1)?, &context)?.is_none());
    context.remote_addr = "[2001:db8:1:2::1]:1234".parse()?;
    assert!(pre_auth_gate_for_gateway_open(&open("ipv6-0", 1)?, &context)?.is_none());
    context.remote_addr = "[2001:db8:1:2::ffff]:4321".parse()?;
    assert!(pre_auth_gate_for_gateway_open(&open("ipv6-1", 1)?, &context)?.is_some());
    Ok(())
}

#[test]
fn cookie_retries_bind_to_observed_peer_and_server_clock() -> anyhow::Result<()> {
    let mut context = context()?;
    context.remote_addr = "192.0.2.1:1234".parse()?;
    assert!(pre_auth_gate_for_gateway_open(&open("first", 1)?, &context)?.is_none());
    let challenge = pre_auth_gate_for_gateway_open(&open("second", 1)?, &context)?
        .ok_or_else(|| anyhow::anyhow!("observed peer must require a cookie"))?;
    let mut retry = open("third", 9_007_199_254_740_991)?;
    retry.pre_auth_cookie = Some(challenge.pre_auth_cookie);
    assert!(pre_auth_gate_for_gateway_open(&retry, &context)?.is_none());
    context.remote_addr = "192.0.2.2:4321".parse()?;
    assert!(pre_auth_gate_for_gateway_open(&open("other-peer", 1)?, &context)?.is_none());
    assert!(
        pre_auth_gate_for_gateway_open(&retry, &context).is_err(),
        "a challenged peer cannot reuse a different transport peer's cookie"
    );
    Ok(())
}

#[cfg(feature = "itest-http")]
#[test]
fn http_headers_cannot_rotate_source_or_advance_server_clock() -> anyhow::Result<()> {
    let context = context()?;
    let peer = "192.0.2.1".parse()?;
    let mut request = ramflux_node_core::NodeHttpRequest {
        method: "POST".to_owned(),
        path: "/mvp6/preauth/probe".to_owned(),
        body: Vec::new(),
        keep_alive: false,
        source_ip_hash: Some("first-claim".to_owned()),
        pre_auth_cookie: None,
        pre_auth_now: Some(1),
        forwarded_proto: None,
        forwarded_for: Some("198.51.100.1".to_owned()),
    };
    assert!(crate::pre_auth_gate(&request, peer, &context.state, &context.store)?.is_none());
    request.source_ip_hash = Some("next-claim".to_owned());
    request.pre_auth_now = Some(86_400);
    request.forwarded_for = Some("198.51.100.2".to_owned());
    assert!(crate::pre_auth_gate(&request, peer, &context.state, &context.store)?.is_some());
    assert!(
        crate::pre_auth_gate(&request, "192.0.2.2".parse()?, &context.state, &context.store)?
            .is_none()
    );
    Ok(())
}

pub(crate) fn mount_key(
    state: &mut ramflux_node_core::GatewayState,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?).as_bytes())?;
    state.configure_pre_auth_cookie_key(path)?;
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn preauth_wire_and_peer_boundary_matrix() -> anyhow::Result<()> {
    let frame = GatewayClientFrame::Open { open: open("wire-sentinel", 1)? };
    let mut value = serde_json::to_value(&frame)?;
    for field in ["source_ip_hash", "pre_auth_now"] {
        let object = value
            .get_mut("open")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| anyhow::anyhow!("Open object"))?;
        let old = object.remove(field).ok_or_else(|| anyhow::anyhow!("legacy field missing"))?;
        assert!(crate::ingress::parse(&serde_json::to_vec(&value)?, "192.0.2.1".parse()?).is_ok());
        value["open"][field] = serde_json::Value::Null;
        assert!(crate::ingress::parse(&serde_json::to_vec(&value)?, "192.0.2.1".parse()?).is_ok());
        value["open"][field] = serde_json::json!({"wrong":"type"});
        assert!(crate::ingress::parse(&serde_json::to_vec(&value)?, "192.0.2.1".parse()?).is_err());
        value["open"][field] = old;
    }
    let mut context = context()?;
    context.remote_addr = "192.0.2.1:1000".parse()?;
    assert!(pre_auth_gate_for_gateway_open(&open("port-first", 1)?, &context)?.is_none());
    let cookie = pre_auth_gate_for_gateway_open(&open("cookie", 1)?, &context)?
        .ok_or_else(|| anyhow::anyhow!("challenge"))?
        .pre_auth_cookie;
    context.remote_addr = "192.0.2.1:2000".parse()?;
    let mut retry = open("port-rebound", 1)?;
    retry.pre_auth_cookie = Some(cookie);
    assert!(pre_auth_gate_for_gateway_open(&retry, &context)?.is_none());
    context.remote_addr = "192.0.2.2:2000".parse()?;
    assert!(pre_auth_gate_for_gateway_open(&open("fresh-peer", 1)?, &context)?.is_none());
    assert!(pre_auth_gate_for_gateway_open(&retry, &context).is_err());
    Ok(())
}

#[test]
fn production_gate_samples_clock_under_lock_and_refuses_failed_commit() -> anyhow::Result<()> {
    use std::time::{Duration, UNIX_EPOCH};
    let context = context()?;
    let source = crate::pre_auth::source_key(context.remote_addr.ip());
    let at = |seconds| UNIX_EPOCH + Duration::from_secs(seconds);
    assert!(
        super::admit_with_clock(&source, None, &context.state, &context.store, || at(100))?
            .is_none()
    );
    let saved = context.store.load_state()?.ok_or_else(|| anyhow::anyhow!("saved state"))?;
    assert_eq!(serde_json::to_value(&saved)?["pre_auth_time_floor"], 100);
    let invalid = super::admit_with_clock(&source, None, &context.state, &context.store, || {
        UNIX_EPOCH - Duration::from_secs(1)
    })
    .err()
    .ok_or_else(|| anyhow::anyhow!("pre-epoch accepted"))?;
    assert_eq!(invalid.to_string(), "clock_invalid");
    let rollback =
        super::admit_with_clock(&source, None, &context.state, &context.store, || at(99))
            .err()
            .ok_or_else(|| anyhow::anyhow!("rollback accepted"))?;
    assert_eq!(rollback.to_string(), "clock_rollback");
    context.store.fail_next_pre_auth_commit();
    assert!(
        super::admit_with_clock(&source, None, &context.state, &context.store, || at(101)).is_err()
    );
    let saved = context.store.load_state()?.ok_or_else(|| anyhow::anyhow!("saved state"))?;
    assert_eq!(serde_json::to_value(saved)?["pre_auth_time_floor"], 100);
    assert!(
        super::admit_with_clock(&source, None, &context.state, &context.store, || at(101))?
            .is_some()
    );
    let held = crate::gateway_state(&context.state)?;
    let (began, waiting) = std::sync::mpsc::channel();
    let shared = context.clone();
    let peer = source.clone();
    let (sampled, observed) = std::sync::mpsc::channel();
    let caller = std::thread::spawn(move || -> Result<(), String> {
        began.send(()).map_err(|e| e.to_string())?;
        super::admit_with_clock(&peer, None, &shared.state, &shared.store, || {
            let _ = sampled.send(());
            at(102)
        })
        .map_err(|e| e.to_string())?;
        Ok(())
    });
    waiting.recv()?;
    assert!(observed.try_recv().is_err(), "production gate sampled before acquiring state lock");
    drop(held);
    caller.join().map_err(|_| anyhow::anyhow!("gate thread panic"))?.map_err(anyhow::Error::msg)?;
    observed.recv()?;
    Ok(())
}

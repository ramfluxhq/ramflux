// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use serde_json::json;
#[derive(serde::Deserialize)]
struct Old {
    delivered: bool,
}
const ID: &str = "0123456789abcdef0123456789abcdef";
fn request() -> crate::GatewayForwardDeliverRequest {
    let mut envelope = crate::session::tests::test_envelope();
    envelope.target_delivery_id = "target".into();
    crate::GatewayForwardDeliverRequest {
        source_gateway_id: "source".into(),
        target_delivery_id: "target".into(),
        forwarded: true,
        incarnation_id: Some(ID.into()),
        retain_until: Some(12345),
        frame: ramflux_node_core::GatewayServerFrame::Deliver {
            entry: ramflux_node_core::InboxEntry {
                target_delivery_id: "target".into(),
                inbox_seq: 1,
                envelope,
            },
        },
    }
}
#[test]
fn forwarding_fields_and_cross_field_rules() -> anyhow::Result<()> {
    let valid = serde_json::to_value(request())?;
    assert!(validate(&request()).is_ok());
    for (path, value, expected) in [
        ("/source_gateway_id", json!(""), "invalid forwarding identity"),
        (
            "/source_gateway_id",
            json!(format!("{}x", "é".repeat(128))),
            "invalid forwarding identity",
        ),
        ("/source_gateway_id", json!("x".repeat(257)), "invalid forwarding identity"),
        ("/target_delivery_id", json!(""), "invalid forwarding identity"),
        (
            "/target_delivery_id",
            json!(format!("{}x", "é".repeat(128))),
            "invalid forwarding identity",
        ),
        ("/target_delivery_id", json!("other"), "forward target/sequence mismatch"),
        ("/target_delivery_id", json!("x".repeat(257)), "invalid forwarding identity"),
        ("/forwarded", json!(false), "forward marker required"),
        ("/incarnation_id", json!("BAD"), "invalid forward incarnation/deadline pair"),
        ("/incarnation_id", json!("A".repeat(32)), "invalid forward incarnation/deadline pair"),
        ("/retain_until", json!(0), "invalid forward incarnation/deadline pair"),
        ("/retain_until", json!(-1), "invalid forward incarnation/deadline pair"),
        ("/frame/entry/target_delivery_id", json!("other"), "forward target/sequence mismatch"),
        (
            "/frame/entry/envelope/target_delivery_id",
            json!("other"),
            "forward target/sequence mismatch",
        ),
        ("/frame/entry/inbox_seq", json!(0), "forward target/sequence mismatch"),
        ("/frame", json!({"frame_type":"heartbeat","now":1}), "durable Deliver required"),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(path).ok_or_else(|| anyhow::anyhow!("missing test path {path}"))? = value;
        let parsed: crate::GatewayForwardDeliverRequest = serde_json::from_value(bad)?;
        assert_eq!(
            validate(&parsed).err().map(|e| e.to_string()).as_deref(),
            Some(expected),
            "{path}"
        );
    }
    for missing in ["incarnation_id", "retain_until"] {
        let mut bad = valid.clone();
        bad.as_object_mut().ok_or_else(|| anyhow::anyhow!("fixture object"))?.remove(missing);
        let parsed = serde_json::from_value(bad)?;
        assert_eq!(
            validate(&parsed).err().map(|e| e.to_string()).as_deref(),
            Some("invalid forward incarnation/deadline pair")
        );
    }
    Ok(())
}
#[test]
fn mesh_compat_overflow() -> anyhow::Result<()> {
    for outcome in [
        Outcome::Queued,
        Outcome::Overflowed,
        Outcome::NoSession,
        Outcome::Full,
        Outcome::Unsupported,
        Outcome::Expired,
    ] {
        let reply = response(outcome);
        let wire = serde_json::to_value(&reply)?;
        let old = wire["delivered"].as_bool().ok_or_else(|| anyhow::anyhow!("missing bool"))?;
        assert_eq!(old, matches!(outcome, Outcome::Queued | Outcome::Overflowed));
        match outcome {
            Outcome::Queued | Outcome::Overflowed => assert!(handled(&reply)?),
            Outcome::NoSession => assert!(!handled(&reply)?),
            _ => assert_eq!(
                handled(&reply).err().map(|e| e.to_string()).as_deref(),
                Some("invalid durable mesh result")
            ),
        }
        let mut bad = wire;
        bad["delivered"] = json!(!old);
        assert_eq!(
            serde_json::from_value::<Response>(bad).err().map(|e| e.to_string()).as_deref(),
            Some("forward delivered/outcome mismatch")
        );
    }
    for delivered in [false, true] {
        let old: Response = serde_json::from_value(json!({"delivered":delivered}))?;
        assert_eq!(handled(&old)?, delivered);
    }
    for (bad, expected) in [
        (json!({}), "missing field `delivered`"),
        (json!({"delivered":1}), "invalid type: integer `1`, expected a boolean"),
        (
            json!({"delivered":true,"outcome":"mystery"}),
            "unknown variant `mystery`, expected one of `queued`, `overflowed`, `no_session`, `full`, `unsupported`, `expired`",
        ),
    ] {
        assert_eq!(
            serde_json::from_value::<Response>(bad).err().map(|e| e.to_string()).as_deref(),
            Some(expected)
        );
    }
    Ok(())
}
#[tokio::test]
async fn sender_recipient_matrix() -> anyhow::Result<()> {
    for capable in [false, true] {
        for modern in [false, true] {
            let hub = std::sync::Arc::new(crate::GatewaySessionHub::default());
            let (send, frames) = crate::session_push::tests::support::sink();
            hub.register_session(
                "target".into(),
                "session".into(),
                send,
                capable.then(|| ID.into()),
            )
            .await?;
            let mut req = request();
            if !modern {
                req.incarnation_id = None;
                req.retain_until = None;
            }
            let reply = crate::serve::handle_gateway_forward_deliver(&hub, req).await?;
            assert!(reply.delivered);
            hub.flushed("target").await?;
            let frames = frames.lock().map_err(|_| anyhow::anyhow!("frames poisoned"))?;
            assert_eq!(frames.len(), 1);
            if capable && !modern {
                assert_eq!(frames[0]["frame_type"], "resync");
                assert_eq!(frames[0]["reason"], "not_pushed");
                assert_eq!(frames[0]["after_inbox_seq"], 0);
                assert_eq!(frames[0]["incarnation_id"], ID);
            } else {
                assert_eq!(frames[0]["frame_type"], "deliver");
                assert_eq!(frames[0].get("incarnation_id").is_some(), capable);
                if capable {
                    assert_eq!(frames[0]["retain_until"], 12345);
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn actual_mesh_overflow_is_handled_by_old_and_new_decoders() -> anyhow::Result<()> {
    let hub = std::sync::Arc::new(crate::GatewaySessionHub::default());
    let (send, _) = crate::session_push::tests::support::sink();
    hub.register_with_limit("target".into(), "session".into(), send.clone(), Some(ID.into()), 16)
        .await?;
    let guard = send.lock().await;
    let mut reply = response(Outcome::NoSession);
    for _ in 0..17 {
        reply = crate::serve::handle_gateway_forward_deliver(&hub, request()).await?;
    }
    assert_eq!(reply.outcome, Some(Outcome::Overflowed));
    let wire = serde_json::to_value(&reply)?;
    let old: Old = serde_json::from_value(wire.clone())?;
    let new: Response = serde_json::from_value(wire)?;
    assert!(old.delivered);
    assert!(handled(&new)?);
    drop(guard);
    Ok(())
}

#[test]
fn forwarding_inclusive_identity_and_deadline_bounds() -> anyhow::Result<()> {
    for target in ["x".repeat(256), "é".repeat(128)] {
        let mut req = request();
        req.source_gateway_id = target.clone();
        req.target_delivery_id = target.clone();
        let ramflux_node_core::GatewayServerFrame::Deliver { entry } = &mut req.frame else {
            anyhow::bail!("fixture Deliver");
        };
        entry.target_delivery_id = target.clone();
        entry.envelope.target_delivery_id = target;
        req.retain_until = Some(1);
        assert_eq!(req.source_gateway_id.len(), 256);
        validate(&req)?;
    }
    Ok(())
}
#[test]
fn forwarding_wire_roundtrip_and_null_refusal() -> anyhow::Result<()> {
    let frame = serde_json::to_string(&request().frame)?;
    for metadata in [String::new(), format!("\"incarnation_id\":\"{ID}\",\"retain_until\":1,")] {
        let bytes = format!("{{\"source_gateway_id\":\"source\",\"target_delivery_id\":\"target\",\"forwarded\":true,{metadata}\"frame\":{frame}}}").into_bytes();
        let decoded: crate::GatewayForwardDeliverRequest = serde_json::from_slice(&bytes)?;
        validate(&decoded)?;
        assert_eq!(serde_json::to_vec(&decoded)?, bytes);
    }
    for fields in [
        json!({"incarnation_id":null}),
        json!({"retain_until":null}),
        json!({"incarnation_id":null,"retain_until":null}),
    ] {
        let mut bad = serde_json::to_value(request())?;
        for (key, value) in fields.as_object().ok_or_else(|| anyhow::anyhow!("null fixture"))? {
            bad[key] = value.clone();
        }
        assert_eq!(
            serde_json::from_value::<crate::GatewayForwardDeliverRequest>(bad)
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some("forward field must not be null")
        );
    }
    Ok(())
}

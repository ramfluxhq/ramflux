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
    for (path, value) in [
        ("/source_gateway_id", json!("")),
        ("/source_gateway_id", json!("x".repeat(257))),
        ("/target_delivery_id", json!("")),
        ("/target_delivery_id", json!("other")),
        ("/target_delivery_id", json!("x".repeat(257))),
        ("/forwarded", json!(false)),
        ("/incarnation_id", json!("BAD")),
        ("/incarnation_id", json!("A".repeat(32))),
        ("/incarnation_id", json!(null)),
        ("/retain_until", json!(null)),
        ("/retain_until", json!(0)),
        ("/retain_until", json!(-1)),
        ("/frame/entry/target_delivery_id", json!("other")),
        ("/frame/entry/envelope/target_delivery_id", json!("other")),
        ("/frame/entry/inbox_seq", json!(0)),
        ("/frame", json!({"frame_type":"heartbeat","now":1})),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(path).ok_or_else(|| anyhow::anyhow!("missing test path {path}"))? = value;
        let parsed: crate::GatewayForwardDeliverRequest = serde_json::from_value(bad)?;
        assert!(validate(&parsed).is_err(), "accepted {path}");
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
        assert_eq!(
            handled(&reply).is_ok(),
            matches!(outcome, Outcome::Queued | Outcome::Overflowed | Outcome::NoSession)
        );
        let mut bad = wire;
        bad["delivered"] = json!(!old);
        assert!(serde_json::from_value::<Response>(bad).is_err());
    }
    for delivered in [false, true] {
        let old: Response = serde_json::from_value(json!({"delivered":delivered}))?;
        assert_eq!(handled(&old)?, delivered);
    }
    for bad in [json!({}), json!({"delivered":1}), json!({"delivered":true,"outcome":"mystery"})] {
        assert!(serde_json::from_value::<Response>(bad).is_err());
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

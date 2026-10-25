// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded acknowledgement windows, expiry and disconnected-session retention.
use super::*;
#[test]
fn server_retention_ack_history_is_bounded_without_losing_out_of_order_deliveries()
-> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    let first = inbox.append(envelope("first", "target", DeliveryClass::OpaqueEvent));
    for index in 0..crate::inbox::ROUTER_ACK_WINDOW {
        let id = format!("next-{index}");
        let entry = inbox.append(envelope(&id, "target", DeliveryClass::OpaqueEvent));
        let mut request = ack(&id);
        request.ext.ext.insert("inbox_seq".into(), serde_json::json!(entry.inbox_seq));
        inbox.apply_ack_for_target("target", &request)?;
    }
    let extra = inbox.append(envelope("extra", "target", DeliveryClass::OpaqueEvent));
    let mut extra_ack = ack("extra");
    extra_ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(extra.inbox_seq));
    assert!(matches!(
        inbox.apply_ack_for_target("target", &extra_ack),
        Err(NodeCoreError::Capacity { .. })
    ));
    assert_eq!(inbox.pull_after("target", 0, 10).len(), 2);
    let mut first_ack = ack("first");
    first_ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(first.inbox_seq));
    inbox.apply_ack_for_target("target", &first_ack)?;
    inbox.apply_ack_for_target("target", &extra_ack)?;
    let cursor = inbox.cursor_state("target").ok_or("cursor")?;
    assert_eq!(cursor.settled_inbox_seq, extra.inbox_seq);
    assert_eq!(cursor.acked_inbox_seqs.len(), 0);
    assert!(cursor.acked_envelope_ids.len() <= crate::inbox::ROUTER_ACK_WINDOW);
    inbox.apply_ack_for_target("target", &first_ack)?;
    Ok(())
}
#[test]
fn server_retention_inbox_expiry_preserves_live_gaps_and_sequence_watermarks()
-> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    let first = inbox.append(envelope("live", "target", DeliveryClass::OpaqueEvent));
    let mut old = envelope("expired", "target", DeliveryClass::OpaqueEvent);
    old.ttl = 1;
    let expired = inbox.append(old);
    assert_eq!(inbox.expire(1_760_000_002), 1);
    assert_eq!(inbox.pull_after("target", 0, 10), vec![first.clone()]);
    let mut request = ack("live");
    request.ext.ext.insert("inbox_seq".into(), serde_json::json!(first.inbox_seq));
    let cursor = inbox.apply_ack_for_target("target", &request)?;
    assert_eq!(cursor.settled_inbox_seq, expired.inbox_seq);
    assert_eq!(cursor.issued_inbox_seq, expired.inbox_seq);
    Ok(())
}
#[test]
fn server_retention_gateway_keeps_live_sinks_and_drops_expired_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let mut state = GatewayState::new();
    for (id, lifecycle) in [
        ("closed", GatewaySessionLifecycle::Closed),
        ("expired", GatewaySessionLifecycle::Live),
        ("active", GatewaySessionLifecycle::Live),
    ] {
        state.open_session(GatewaySession {
            session_id: id.into(),
            target_delivery_id: id.into(),
            device_id: "phone".into(),
            opened_at: 1,
            last_heartbeat_at: 1,
            lifecycle,
        });
        state.deliver(GatewayFrame::Drain { session_id: id.into() })?;
    }
    assert_eq!(state.prune_retained_sessions(1000, 300, &BTreeSet::from(["active".into()])), 2);
    assert!(state.session("active").is_some());
    assert!(state.session("expired").is_none());
    assert_eq!(state.queued_frame_count("expired"), 0);
    Ok(())
}

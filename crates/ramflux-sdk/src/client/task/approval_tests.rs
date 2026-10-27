// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Requester-visible task approval requests, signed cross-device decisions, and durable pending reads.
use super::decisions::{grant, open, resolution};
use super::*;
use crate::client::task::approval::{Packet, Payload, Request};
use ramflux_protocol::TaskDecision;
use serde_json::Value;
fn request(f: &Fixture) -> Result<Packet, SdkError> {
    let grant = grant(f)?;
    let mut body = grant.signing_body;
    let arguments = json!({"command":"echo approved"});
    body.arguments_hash = Some(ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::MCP_GRANT,
        &ramflux_protocol::canonical_json_bytes(&arguments)?,
    ));
    let binding = body.task_binding.clone().ok_or_else(|| invalid("binding"))?;
    let approval = crate::LocalMcpApprovalRecord {
        approval_id: body.approval_id.clone(),
        server_id: body.server_id.clone(),
        tool_name: body.tool_name.clone(),
        capability: body.capability.clone(),
        risk_level: ramflux_protocol::RiskLevel::High,
        tool_scope: body.tool_scope.clone(),
        confirmation_mode: "remote_app".into(),
        expires_at: body.expires_at,
        status: "pending".into(),
        details: json!({"arguments":arguments,"requested_grant_id":body.grant_id,"single_use":true,"arguments_hash":body.arguments_hash,"task_binding":binding}),
    };
    let packet = f.agent.sign_task_approval(Payload::Request {
        request: Box::new(Request { binding, approval, grant_body: body }),
    })?;
    f.agent.account_db()?.persist_actor_state(&key("approval_source", &packet.id()?), &packet)?;
    Ok(packet)
}
#[test]
fn a_requesters_second_device_reads_the_remote_approval_and_returns_a_task_bound_signed_decision()
-> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let packet = request(&f)?;
    f.human.accept_task_approval(&packet)?;
    let mut sibling = client(&f.root.join("human2"), "human", 61)?;
    sibling.create_device_branch("human", "human2-device", 1, [65; 32]);
    // The same-root history carries the task and verified peer device key, never an executable grant.
    super::own::manifests(&f)?;
    sibling.import_own_task_packets(&f.human.own_task_packets("human2-device")?, "human-device")?;
    sibling.accept_task_approval(&packet)?;
    let rows = sibling.task_remote_approvals()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["task_binding"]["task_id"], "task");
    let id = rows[0]["approval_id"].as_str().ok_or("approval id")?;
    assert_eq!(sibling.canonical_task_approval_decision(id, "thread", "task", "step")?, "approval");
    assert!(sibling.canonical_task_approval_decision(id, "thread", "other", "step").is_err());
    assert!(
        sibling
            .account_db()?
            .journal_after(0, 128)?
            .iter()
            .any(|row| row.topic == "mcp.approval.request")
    );
    let decision = sibling.decide_task_approval(id, true)?;
    assert_eq!(decision["decision_id"], "approval");
    assert_eq!(sibling.task_remote_approvals()?, Vec::<Value>::new());
    let jobs = sibling.account_db()?.task_record_page::<approval::Job>(
        "task/approval_decision_out/",
        "task/approval_decision_out/",
        10,
    )?;
    let reply = &jobs[0].1.packet;
    let d = sibling.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let mut manifest = super::own::manifest(&f.human)?;
    manifest.devices.extend(super::own::manifest(&sibling)?.devices);
    crate::client::identity_authority::test_support::sign_manifest(
        f.human.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut manifest,
        2,
    )?;
    for local in [&f.agent, &f.human] {
        local.persist_identity_directory(&manifest)?;
        local.accept_task_approval(reply)?;
        local.accept_task_approval(reply)?;
    }
    assert_eq!(f.human.task_remote_approvals()?, Vec::<Value>::new());
    let Payload::Decision { grant_signature: Some(signature), request, .. } = &reply.payload else {
        return Err("decision missing".into());
    };
    ramflux_crypto::verify_device_branch_signature(
        &ramflux_protocol::encode_base64url(d.signing_key.verifying_key().to_bytes()),
        &request.grant_body,
        signature,
    )?;
    let mut changed = reply.clone();
    if let Payload::Decision { request, .. } = &mut changed.payload {
        request.binding.opening_revision += 1;
    }
    assert!(f.agent.accept_task_approval(&changed).is_err());
    assert!(
        f.human.decide_task_approval(id, false).is_err(),
        "another device cannot replace the first decision"
    );
    drop(sibling);
    Ok(())
}
#[test]
fn requester_approval_is_a_durable_pending_resolution_after_writer_restart() -> TestResult {
    let mut f = Fixture::new()?;
    open(&f, "task")?;
    let c = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(resolution("task", TaskDecision::Resume)),
    )?;
    assert!(project(&f.human, &c)?.pending);
    let before = f.human.task_get(Some("thread"), "task")?["pending_resolution"].clone();
    assert_eq!(before["task_id"], "task");
    assert_eq!(before["state"], "awaiting_executor");
    drop(f.human.active_account_db.take());
    f.human.unlock_account("human", b"task-test-secret")?;
    let restored = &f.human;
    assert_eq!(restored.task_get(Some("thread"), "task")?["pending_resolution"], before);
    let view = restored.task_get(Some("thread"), "task")?;
    assert_eq!(view["actors"]["requester"]["actor_kind_verified"], false);
    assert_eq!(view["actors"]["assignee"]["actor_kind_verified"], false);
    Ok(())
}

#[test]
fn an_assignee_cannot_show_different_arguments_from_the_human_signed_tool_capability() -> TestResult
{
    let f = Fixture::new()?;
    open(&f, "task")?;
    let mut packet = request(&f)?;
    if let Payload::Request { request } = &mut packet.payload {
        request.approval.details["arguments"] = json!({"command":"different"});
    }
    let changed = f.agent.sign_task_approval(packet.payload)?;
    assert!(f.human.accept_task_approval(&changed).is_err());
    assert_eq!(f.human.task_remote_approvals()?, Vec::<Value>::new());
    Ok(())
}

#[test]
fn peer_request_capacity_cannot_consume_the_requesters_decision_return_headroom() -> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let packet = request(&f)?;
    f.human.accept_task_approval(&packet)?;
    let db = f.human.account_db()?;
    // Seed the local encrypted queue indexes at their boundary. The decision uses
    // the actual validated request and the normal attended decision implementation.
    for i in 0..63 {
        db.persist_actor_state(&key("approval_in", &format!("full-{i}")), &packet)?;
    }
    for i in 0..32 {
        db.persist_actor_state(
            &key("approval_out", &format!("full-{i}")),
            &approval::Job { packet: packet.clone(), attempts: 0, next_at: 0 },
        )?;
    }
    let id = format!("task_approval_{}", packet.id()?);
    let result = f.human.decide_task_approval(&id, true)?;
    assert_eq!(result["status"], "approved");
    assert_eq!(db.task_state_usage("task/approval_decision_out/")?.0, 1);
    assert_eq!(db.task_state_usage("task/approval_decision_in/")?.0, 0);
    assert_eq!(db.task_state_usage("task/approval_receipt/")?.0, 1);
    assert_eq!(f.human.decide_task_approval(&id, true)?["status"], "approved");
    assert!(f.human.decide_task_approval(&id, false).is_err());
    Ok(())
}

#[test]
fn r5_pending_resolution_names_its_step_across_restart_and_executor_timeout() -> TestResult {
    let mut f = Fixture::new()?;
    open(&f, "task")?;
    let c = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(resolution("task", TaskDecision::Resume)),
    )?;
    assert!(project(&f.human, &c)?.pending);
    assert_eq!(f.human.task_get(Some("thread"), "task")?["pending_resolution"]["step_id"], "step");
    drop(f.human.active_account_db.take());
    f.human.unlock_account("human", b"task-test-secret")?;
    assert_eq!(f.human.task_get(Some("thread"), "task")?["pending_resolution"]["step_id"], "step");
    f.human.release_local_task_slots(crate::time::now_unix_timestamp() + 61)?;
    let pending = f.human.task_get(Some("thread"), "task")?["pending_resolution"].clone();
    assert_eq!(pending["step_id"], "step");
    assert_eq!(pending["state"], "executor_timeout");
    Ok(())
}

#[path = "approval_r5_tests.rs"]
mod r5;

#[path = "approval_r6_tests.rs"]
mod r6;

#[test]
fn remote_task_approvals_are_paged_with_local_mcp_rows_on_keyless_readers_and_disappear_after_decision()
-> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let packet = request(&f)?;
    f.human.accept_task_approval(&packet)?;
    let db = f.human.account_db()?;
    db.persist_client_record(
        "self",
        "account",
        &json!({"principal_id":"human","device_id":"human-device"}),
    )?;
    db.persist_client_record(
        "approval",
        "local-first",
        &json!({"id":"local-first","approval_id":"local-first","status":"pending"}),
    )?;
    let mut reader = RamfluxClient::new();
    reader.active_account_db = Some(db.open_reader()?);
    let page = |body| {
        crate::bus::read_model::read(
            &reader,
            &crate::LocalBusFrame::request(
                "page",
                Some("human".into()),
                "test",
                "mcp.approval.list",
                body,
            ),
        )
    };
    let first = page(json!({"limit":1}))?;
    assert_eq!(first["approvals"][0]["id"], "local-first");
    let second = page(json!({"limit":1,"cursor":first["next_cursor"]}))?;
    let remote = &second["approvals"][0];
    assert_eq!(remote["task_binding"]["task_id"], "task");
    assert_eq!(remote["conversation_id"], "thread");
    assert!(second["next_cursor"].is_null());
    let legacy = page(json!({}))?;
    assert_eq!(legacy["approvals"].as_array().ok_or("rows")?.len(), 2);
    db.persist_client_record(
        "approval",
        remote["approval_id"].as_str().ok_or("approval id")?,
        remote,
    )?;
    f.human.decide_task_approval(remote["approval_id"].as_str().ok_or("approval id")?, false)?;
    let remaining = page(json!({"limit":100}))?;
    assert_eq!(remaining["approvals"].as_array().ok_or("rows")?.len(), 1);
    let legacy_remaining = page(json!({}))?;
    assert_eq!(legacy_remaining["approvals"], remaining["approvals"]);
    Ok(())
}

#[test]
fn pending_approvals_after_one_hundred_twenty_nine_expired_rows_remain_visible() -> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let original = request(&f)?;
    let mut packets = std::collections::BTreeMap::new();
    for n in 0..130 {
        let mut request = original.request().clone();
        request.approval.approval_id = format!("approval-{n}");
        request.grant_body.approval_id = request.approval.approval_id.clone();
        let packet = f.agent.sign_task_approval(Payload::Request { request: Box::new(request) })?;
        packets.insert(key("approval_in", &packet.id()?), packet);
    }
    let last = packets.keys().next_back().ok_or("packet")?.clone();
    let last_id = packets.get(&last).ok_or("last packet")?.id()?;
    for (id, mut packet) in packets {
        if id != last {
            packet.local_expires_at = Some(1);
        }
        f.human.account_db()?.persist_actor_state(&id, &packet)?;
    }
    let rows = f.human.task_remote_approvals()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["approval_id"], format!("task_approval_{last_id}"));
    Ok(())
}

#[test]
fn remote_approvals_respect_legacy_frame_limits_and_page_without_losing_rows() -> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let original = request(&f)?;
    for n in 0..60 {
        let mut request = original.request().clone();
        request.approval.approval_id = format!("approval-{n}");
        request.grant_body.approval_id = request.approval.approval_id.clone();
        request.approval.details["arguments"] = json!({"text":"x".repeat(20_000)});
        request.grant_body.arguments_hash = Some(ramflux_protocol::hash_base64url(
            ramflux_protocol::domain::MCP_GRANT,
            &ramflux_protocol::canonical_json_bytes(&request.approval.details["arguments"])?,
        ));
        let packet = f.agent.sign_task_approval(Payload::Request { request: Box::new(request) })?;
        f.human.account_db()?.persist_actor_state(&key("approval_in", &packet.id()?), &packet)?;
    }
    let mut request = crate::LocalBusFrame::request(
        "approvals",
        Some("human".into()),
        "test",
        "mcp.approval.list",
        json!({}),
    );
    let error =
        crate::bus::read_model::read(&f.human, &request).err().ok_or("unbounded list accepted")?;
    assert!(error.to_string().contains("use cursor/limit"), "{error}");
    let mut seen = std::collections::BTreeSet::new();
    let mut cursor = Value::Null;
    loop {
        request.body = json!({"limit":100,"cursor":cursor});
        let page = crate::bus::read_model::read(&f.human, &request)?;
        assert!(serde_json::to_vec(&page)?.len() < 512 * 1024);
        let rows = page["approvals"].as_array().ok_or("rows")?;
        assert_ne!(rows.len(), 0);
        for row in rows {
            assert!(seen.insert(row["approval_id"].as_str().ok_or("id")?.to_owned()));
        }
        cursor = page["next_cursor"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert_eq!(seen.len(), 60);
    Ok(())
}

#[test]
fn approval_pages_advance_over_expired_keys_without_reading_the_entire_backlog() -> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let original = request(&f)?;
    let mut packets = std::collections::BTreeMap::new();
    for n in 0..130 {
        let mut request = original.request().clone();
        request.approval.approval_id = format!("bounded-approval-{n}");
        request.grant_body.approval_id = request.approval.approval_id.clone();
        let packet = f.agent.sign_task_approval(Payload::Request { request: Box::new(request) })?;
        packets.insert(key("approval_in", &packet.id()?), packet);
    }
    let (last, live) = packets.last_key_value().ok_or("packet")?;
    let last = last.clone();
    let live = live.clone();
    let expected = format!("task_approval_{}", live.id()?);
    for (key, mut packet) in packets {
        packet.local_expires_at = Some(1);
        f.human.account_db()?.persist_actor_state(&key, &packet)?;
    }
    // Data beyond this page is deliberately undecodable. A bounded page must not read it.
    f.human.account_db()?.persist_actor_state(&last, &json!({"not_a_packet":true}))?;
    let mut request = crate::LocalBusFrame::request(
        "bounded",
        Some("human".into()),
        "test",
        "mcp.approval.list",
        json!({"limit":100}),
    );
    let first = crate::bus::read_model::read(&f.human, &request)?;
    assert_eq!(first["approvals"], json!([]));
    let cursor = first["next_cursor"].as_str().ok_or("progress cursor")?;
    f.human.account_db()?.persist_actor_state(&last, &live)?;
    request.body = json!({"limit":100,"cursor":cursor});
    let second = crate::bus::read_model::read(&f.human, &request)?;
    let rows = second["approvals"].as_array().ok_or("approvals")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["approval_id"], expected);
    assert!(second["next_cursor"].is_null());
    request.account_id = Some("different-account".into());
    assert!(
        crate::bus::read_model::read(&f.human, &request).is_err(),
        "cursor must remain account scoped"
    );
    Ok(())
}

#[test]
fn legacy_approval_scans_are_capped_and_cursor_pages_still_reach_the_final_live_row() -> TestResult
{
    let f = Fixture::new()?;
    open(&f, "task")?;
    let live = request(&f)?;
    let mut expired = live.clone();
    expired.local_expires_at = Some(1);
    let db = f.human.account_db()?;
    db.write_transaction(|| -> TestResult {
        for n in 0..1050 {
            db.persist_actor_state(&format!("task/approval_in/{n:04}"), &expired)?;
        }
        db.persist_actor_state("task/approval_in/zz-final", &live)?;
        Ok(())
    })?;
    let mut request = crate::LocalBusFrame::request(
        "capped",
        Some("human".into()),
        "test",
        "mcp.approval.list",
        json!({}),
    );
    let error =
        crate::bus::read_model::read(&f.human, &request).err().ok_or("uncapped legacy scan")?;
    assert!(error.to_string().contains("use cursor/limit"));
    let mut cursor = Value::Null;
    let mut pages = 0;
    let mut seen = Vec::new();
    loop {
        pages += 1;
        assert!(pages < 20, "cursor must advance over skipped keys");
        request.body = json!({"limit":100,"cursor":cursor});
        let page = crate::bus::read_model::read(&f.human, &request)?;
        seen.extend(page["approvals"].as_array().ok_or("rows")?.clone());
        cursor = page["next_cursor"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert_eq!(pages, 11);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["approval_id"], format!("task_approval_{}", live.id()?));
    Ok(())
}

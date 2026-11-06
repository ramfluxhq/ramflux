// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::{TaskEventBody as B, TaskStatus as S, *};
pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

fn device() -> ramflux_crypto::DeviceBranch {
    ramflux_crypto::create_device_branch("human", "device", 1, [23; 32])
}
pub(super) fn body_variants() -> Vec<B> {
    vec![
        B::Start(TaskStart {
            task_id: "task".into(),
            conversation_id: "thread".into(),
            requester: "human".into(),
            assignee: "agent".into(),
            text: "text\n😀".into(),
            constraints: Some("constraints".into()),
        }),
        B::Proposal(TaskProposal {
            task_id: "task".into(),
            conversation_id: "thread".into(),
            proposer: "agent".into(),
            assignee: "agent".into(),
            title: "title".into(),
            steps: vec![step(S::Proposed, None)],
        }),
        B::Accept(TaskAccept { task_id: "task".into(), version: 2 }),
        B::Decline(TaskDecline { task_id: "task".into(), version: 2 }),
        B::Update(TaskUpdate {
            task_id: "task".into(),
            version: 3,
            state: S::NeedsMe,
            steps: vec![step(S::NeedsMe, Some(NeedsMe::Approval { grant_id: "grant".into() }))],
            result_ref: Some("result".into()),
            result_summary: Some("summary".into()),
        }),
        B::Cancel(TaskCancel { task_id: "task".into(), base_revision: 3 }),
        B::Resolve(TaskResolve {
            task_id: "task".into(),
            base_revision: 3,
            step_id: "step".into(),
            target: NeedsMe::Choice { surface_id: "surface".into() },
            decision_id: "decision".into(),
            decision: TaskDecision::Resume,
        }),
    ]
}
fn step(state: S, needs_me: Option<NeedsMe>) -> TaskStep {
    TaskStep { id: "step".into(), title: "title".into(), state, needs_me }
}
fn event(body: B) -> Result<TaskEvent, Box<dyn std::error::Error>> {
    let event = TaskEvent::new(
        "thread".into(),
        body,
        SignedFields {
            signing_key_id: "device:device".into(),
            signature_alg: SignatureAlg::Ed25519,
            signature: String::new(),
        },
    )?
    .with_extensions(Ext {
        ext: [(
            "extra".into(),
            json!({"state":"unchanged","number":9_007_199_254_740_991_u64,"array":[true,null,"😀"]}),
        )]
        .into(),
    })?;
    let signature =
        ramflux_crypto::sign_canonical_bytes_with_device_branch(&event.signing_bytes()?, &device());
    Ok(event.with_signature(signature)?)
}
fn decode(bytes: &[u8]) -> Result<TaskEvent, SdkError> {
    let public =
        ramflux_protocol::encode_base64url(device().signing_key.verifying_key().to_bytes());
    RamfluxClient::decode_generated_task_event(
        bytes,
        &TaskSigner {
            principal_id: "human",
            actor_type: ActorType::Human,
            signing_key_id: "device:device",
            public_key_base64url: &public,
        },
    )
}
fn refusal(result: Result<TaskEvent, SdkError>, reason: crate::TaskRefusalCode) {
    let error = result.err();
    assert!(
        matches!(&error,Some(SdkError::TaskRefused {reason:actual,..}) if *actual==reason),
        "expected {reason:?}, got {error:?}"
    );
}
#[test]
fn all_seven_generated_task_events_preserve_native_signing_bytes() -> TestResult {
    for body in body_variants() {
        let native = event(body)?;
        let bytes = RamfluxClient::encode_generated_task_event(&native)?;
        let decoded = decode(&bytes)?;
        assert_eq!(decoded, native);
        assert_eq!(decoded.signing_bytes()?, native.signing_bytes()?);
        assert_eq!(RamfluxClient::encode_generated_task_event(&decoded)?, bytes);
    }
    for state in [S::Proposed, S::Running, S::Done, S::Failed, S::Cancelled] {
        let native = event(B::Update(TaskUpdate {
            task_id: "task".into(),
            version: 2,
            state,
            steps: vec![],
            result_ref: None,
            result_summary: None,
        }))?;
        assert_eq!(decode(&RamfluxClient::encode_generated_task_event(&native)?)?, native);
    }
    for target in [
        NeedsMe::Input { surface_id: "surface".into() },
        NeedsMe::Approval { grant_id: "grant".into() },
    ] {
        let native = event(B::Resolve(TaskResolve {
            task_id: "task".into(),
            base_revision: 1,
            step_id: "step".into(),
            target,
            decision_id: "decision".into(),
            decision: TaskDecision::Deny,
        }))?;
        assert_eq!(decode(&RamfluxClient::encode_generated_task_event(&native)?)?, native);
    }
    Ok(())
}
#[test]
fn generated_task_event_fields_and_cross_field_rules_reject_tampering() -> TestResult {
    use crate::TaskRefusalCode::{InvalidEvent, InvalidRequest};
    let native = event(body_variants().remove(0))?;
    let bytes = RamfluxClient::encode_generated_task_event(&native)?;
    let original = g::TaskEvent::decode(bytes.as_slice())?;
    for index in 0..10 {
        let mut changed = original.clone();
        match index {
            0 => changed.schema.push('x'),
            1 => changed.version = 2,
            2 => changed.domain.push('x'),
            3 => changed.conversation_id = "different".into(),
            4 => changed.ext = None,
            5 => changed.signed = None,
            6 => changed.signed.as_mut().ok_or("signed")?.signing_key_id = "other".into(),
            7 => changed.signed.as_mut().ok_or("signed")?.signature_alg = None,
            8 => changed.signed.as_mut().ok_or("signed")?.signature = "invalid".into(),
            _ => changed.event = None,
        }
        refusal(
            decode(&changed.encode_to_vec()),
            if matches!(index, 3 | 6 | 8) { InvalidEvent } else { InvalidRequest },
        );
    }
    for index in 0..6 {
        let mut changed = original.clone();
        let Some(g::task_event_body::Value::Start(start)) =
            changed.event.as_mut().and_then(|v| v.value.as_mut())
        else {
            return Err("start".into());
        };
        let body = start.value.as_mut().ok_or("body")?;
        match index {
            0 => body.task_id.clear(),
            1 => body.conversation_id = "other".into(),
            2 => body.requester.clear(),
            3 => body.assignee.clear(),
            4 => body.text.clear(),
            _ => body.constraints = Some(String::new()),
        }
        refusal(decode(&changed.encode_to_vec()), InvalidEvent);
    }
    // Nonminimal varint and reordered tags fail before native signature hashing.
    let mut nonminimal = bytes.clone();
    let version = nonminimal.windows(2).position(|v| v == [0x10, 1]).ok_or("version")?;
    nonminimal.splice(version + 1..version + 2, [0x81, 0]);
    refusal(decode(&nonminimal), InvalidRequest);
    let mut reordered = vec![0x10, 1];
    reordered.extend(bytes);
    refusal(decode(&reordered), InvalidRequest);
    Ok(())
}
#[test]
fn typed_task_carrier_binds_every_outer_field_and_native_signature() -> TestResult {
    let mut client = RamfluxClient::new();
    client.create_device_branch("human", "device", 1, [23; 32]);
    let native = event(body_variants().remove(0))?;
    let bytes = client.encode_generated_task_carrier(native, "message".into())?;
    let carrier = client.decode_generated_task_carrier(&bytes)?;
    let key = ramflux_protocol::encode_base64url(device().signing_key.verifying_key().to_bytes());
    let mut unsigned = carrier.clone();
    unsigned.signature.clear();
    let domain = b"ramflux.message.typed.TaskCarrier.v1";
    let body = unsigned.encode_to_vec();
    let mut expected = u32::try_from(domain.len())?.to_be_bytes().to_vec();
    expected.extend(domain);
    expected.extend(u32::try_from(body.len())?.to_be_bytes());
    expected.extend(body);
    ramflux_crypto::verify_canonical_signature(&expected, &carrier.signature, &key)?;
    for index in 0..8 {
        let mut changed = carrier.clone();
        match index {
            0 => changed.content_type = "other".into(),
            1 => changed.conversation_id = "other".into(),
            2 => changed.message_id.clear(),
            3 => changed.principal_id.clear(),
            4 => changed.device_id.clear(),
            5 => changed.event = None,
            6 => changed.signature = encode_base64url([0; 64]),
            _ => changed.message_id.push('x'),
        }
        let bytes = g::Task { payload: Some(g::task::Payload::Carrier(changed)) }.encode_to_vec();
        let error = client
            .decode_generated_task_carrier(&bytes)
            .err()
            .ok_or("tampered carrier accepted")?;
        if index >= 6 {
            assert!(matches!(error, SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed)));
        } else {
            assert!(
                matches!(
                    error,
                    SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. }
                ),
                "field {index}: {error:?}"
            );
        }
    }
    Ok(())
}

fn approval_packet()
-> Result<(g::TaskApprovalPacket, crate::LocalMcpGrantSigningBody), Box<dyn std::error::Error>> {
    let binding = g::TaskApprovalBinding {
        conversation_id: "thread".into(),
        task_id: "task".into(),
        step_id: "step".into(),
        opening_revision: 2,
        requester: "human".into(),
        assignee: "agent".into(),
        executor_device_id: "executor".into(),
    };
    let native_binding = crate::TaskApprovalBinding {
        conversation_id: binding.conversation_id.clone(),
        task_id: binding.task_id.clone(),
        step_id: binding.step_id.clone(),
        opening_revision: binding.opening_revision,
        requester: binding.requester.clone(),
        assignee: binding.assignee.clone(),
        executor_device_id: binding.executor_device_id.clone(),
    };
    let arguments = json!({"command":"echo approved","state":"literal"});
    let arguments_hash = hash_base64url(domain::MCP_GRANT, &canonical_json_bytes(&arguments)?);
    let native = crate::LocalMcpGrantSigningBody {
        task_binding: Some(native_binding),
        approval_id: "approval".into(),
        grant_id: "grant".into(),
        server_id: "server".into(),
        tool_name: "tool".into(),
        tool_scope: Some("scope".into()),
        capability: McpCapability::RunShell,
        registry_hash: "registry".into(),
        tool_manifest_set_hash: "manifest".into(),
        full_delegation: false,
        single_use: true,
        arguments_hash: Some(arguments_hash.clone()),
        expires_at: 4_000_000_000,
    };
    let capability: g::McpCapability = serde_json::from_value(json!({"runShell":{}}))?;
    let grant = g::LocalMcpGrantSigningBody {
        task_binding: Some(binding.clone()),
        approval_id: native.approval_id.clone(),
        grant_id: native.grant_id.clone(),
        server_id: native.server_id.clone(),
        tool_name: native.tool_name.clone(),
        tool_scope: native.tool_scope.clone(),
        capability: Some(capability),
        registry_hash: native.registry_hash.clone(),
        tool_manifest_set_hash: native.tool_manifest_set_hash.clone(),
        full_delegation: false,
        single_use: true,
        arguments_hash: Some(arguments_hash.clone()),
        expires_at: native.expires_at,
    };
    let request = g::TaskApprovalRequest {
        binding: Some(binding),
        approval: Some(g::LocalMcpApprovalRecord {
            approval_id: native.approval_id.clone(),
            server_id: native.server_id.clone(),
            tool_name: native.tool_name.clone(),
            capability: Some(capability),
            risk_level: Some(serde_json::from_value(json!({"high":{}}))?),
            tool_scope: native.tool_scope.clone(),
            confirmation_mode: "remote_app".into(),
            expires_at: native.expires_at,
            status: "pending".into(),
            details: Some(json_value(
                &json!({"arguments":arguments,"arguments_hash":arguments_hash}),
            )?),
        }),
        grant_body: Some(grant),
    };
    let signature = ramflux_crypto::sign_with_device_branch(&device(), &native)?;
    Ok((
        g::TaskApprovalPacket {
            payload: Some(g::TaskApprovalPayload {
                value: Some(g::task_approval_payload::Value::Decision(
                    g::TaskApprovalPayloadDecision {
                        request: Some(request),
                        approved: true,
                        grant_signature: Some(signature),
                    },
                )),
            }),
            principal: "human".into(),
            device: "device".into(),
            signature: String::new(),
        },
        native,
    ))
}
#[test]
fn generated_approval_preserves_native_grant_signature_and_rejects_every_grant_field() -> TestResult
{
    let mut client = RamfluxClient::new();
    client.create_device_branch("human", "device", 1, [23; 32]);
    let (packet, native) = approval_packet()?;
    let bytes = client.encode_generated_task_approval(packet.clone())?;
    let decoded = client.decode_generated_task_approval(&bytes)?;
    let Some(g::task_approval_payload::Value::Decision(decision)) =
        decoded.payload.as_ref().and_then(|v| v.value.as_ref())
    else {
        return Err("decision".into());
    };
    let mapped = super::approval::native_request(decision.request.as_ref().ok_or("request")?)?;
    assert_eq!(canonical_json_bytes(&mapped.grant_body)?, canonical_json_bytes(&native)?);
    let public = encode_base64url(device().signing_key.verifying_key().to_bytes());
    ramflux_crypto::verify_device_branch_signature(
        &public,
        &native,
        decision.grant_signature.as_deref().ok_or("grant signature")?,
    )?;
    for field in 0..13 {
        let mut changed = packet.clone();
        let Some(g::task_approval_payload::Value::Decision(decision)) =
            changed.payload.as_mut().and_then(|v| v.value.as_mut())
        else {
            return Err("decision".into());
        };
        let grant = decision.request.as_mut().and_then(|v| v.grant_body.as_mut()).ok_or("grant")?;
        match field {
            0 => grant.task_binding.as_mut().ok_or("binding")?.step_id.push('x'),
            1 => grant.approval_id.push('x'),
            2 => grant.grant_id.push('x'),
            3 => grant.server_id.push('x'),
            4 => grant.tool_name.push('x'),
            5 => grant.tool_scope = Some("other".into()),
            6 => grant.capability = Some(serde_json::from_value(json!({"sendMessage":{}}))?),
            7 => grant.registry_hash.push('x'),
            8 => grant.tool_manifest_set_hash.push('x'),
            9 => grant.full_delegation = true,
            10 => grant.single_use = false,
            11 => grant.arguments_hash = Some("other".into()),
            _ => grant.expires_at += 1,
        }
        let error = client
            .encode_generated_task_approval(changed)
            .err()
            .ok_or("tampered grant accepted")?;
        if matches!(field, 2 | 7 | 8) {
            assert!(
                matches!(error, SdkError::SignatureVerificationFailed(_)),
                "grant field {field}: {error:?}"
            );
        } else {
            assert!(
                matches!(
                    error,
                    SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. }
                ),
                "grant field {field}: {error:?}"
            );
        }
    }
    for (approved, signature) in [(true, None), (false, Some("unexpected".into()))] {
        let mut changed = packet.clone();
        let Some(g::task_approval_payload::Value::Decision(value)) =
            changed.payload.as_mut().and_then(|v| v.value.as_mut())
        else {
            return Err("decision".into());
        };
        value.approved = approved;
        value.grant_signature = signature;
        assert!(matches!(
            client.encode_generated_task_approval(changed),
            Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. })
        ));
    }
    let mut denied = packet;
    let Some(g::task_approval_payload::Value::Decision(value)) =
        denied.payload.as_mut().and_then(|v| v.value.as_mut())
    else {
        return Err("decision".into());
    };
    value.approved = false;
    value.grant_signature = None;
    let bytes = client.encode_generated_task_approval(denied)?;
    client.decode_generated_task_approval(&bytes)?;
    Ok(())
}

fn leaf_paths(value: &Value, prefix: &mut Vec<String>, paths: &mut Vec<Vec<String>>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                prefix.push(key.clone());
                leaf_paths(value, prefix, paths);
                prefix.pop();
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                prefix.push(index.to_string());
                leaf_paths(value, prefix, paths);
                prefix.pop();
            }
        }
        _ => paths.push(prefix.clone()),
    }
}
fn mutate_leaf(value: &mut Value, path: &[String]) -> TestResult {
    let mut current = value;
    for key in path {
        current = if current.is_array() {
            current
                .as_array_mut()
                .ok_or("array")?
                .get_mut(key.parse::<usize>()?)
                .ok_or("array leaf")?
        } else {
            current.get_mut(key).ok_or("object leaf")?
        };
    }
    match current {
        Value::String(text) => {
            if let Ok(number) = text.parse::<u64>() {
                *text = (number + 1).to_string();
            } else {
                text.push('x');
            }
        }
        Value::Number(number) => {
            *number = serde_json::Number::from(number.as_u64().ok_or("numeric leaf")? + 1);
        }
        Value::Bool(value) => *value = !*value,
        Value::Null => *current = Value::Bool(true),
        _ => return Err("not a leaf".into()),
    }
    Ok(())
}
#[test]
fn every_event_payload_leaf_remains_covered_by_the_native_signature() -> TestResult {
    for body in body_variants() {
        let native = event(body)?;
        let bytes = RamfluxClient::encode_generated_task_event(&native)?;
        let generated = g::TaskEvent::decode(bytes.as_slice())?;
        let original = serde_json::to_value(&generated)?;
        let payload = original.get("event").ok_or("event")?;
        let mut paths = Vec::new();
        leaf_paths(payload, &mut Vec::new(), &mut paths);
        assert_ne!(paths, Vec::<Vec<String>>::new());
        for path in paths {
            let mut changed = original.clone();
            mutate_leaf(changed.get_mut("event").ok_or("event")?, &path)?;
            let changed: g::TaskEvent = serde_json::from_value(changed)?;
            refusal(decode(&changed.encode_to_vec()), crate::TaskRefusalCode::InvalidEvent);
        }
    }
    Ok(())
}
#[test]
fn task_delivery_cap_is_checked_before_parsing_or_hashing() {
    let mut client = RamfluxClient::new();
    client.create_device_branch("human", "device", 1, [23; 32]);
    let bytes = vec![0xff; super::super::MAX_DELIVERY_BYTES + 1];
    for result in [
        decode(&bytes).map(|_| ()),
        client.decode_generated_task_carrier(&bytes).map(|_| ()),
        client.decode_generated_task_approval(&bytes).map(|_| ()),
    ] {
        assert!(
            matches!(result,Err(SdkError::TaskDeliveryTooLarge {bytes:actual,limit}) if actual==bytes.len() && limit==super::super::MAX_DELIVERY_BYTES)
        );
    }
}

fn request_mut(
    packet: &mut g::TaskApprovalPacket,
) -> Result<&mut g::TaskApprovalRequest, Box<dyn std::error::Error>> {
    let Some(g::task_approval_payload::Value::Decision(value)) =
        packet.payload.as_mut().and_then(|v| v.value.as_mut())
    else {
        return Err("decision".into());
    };
    Ok(value.request.as_mut().ok_or("request")?)
}
#[test]
fn generated_approval_rejects_each_binding_and_display_field_with_exact_errors() -> TestResult {
    let mut client = RamfluxClient::new();
    client.create_device_branch("human", "device", 1, [23; 32]);
    let bytes = client.encode_generated_task_approval(approval_packet()?.0)?;
    let packet = client.decode_generated_task_approval(&bytes)?;
    for field in 0..7 {
        let mut changed = packet.clone();
        let binding = request_mut(&mut changed)?.binding.as_mut().ok_or("binding")?;
        match field {
            0 => binding.conversation_id.push('x'),
            1 => binding.task_id.push('x'),
            2 => binding.step_id.push('x'),
            3 => binding.opening_revision += 1,
            4 => binding.requester.push('x'),
            5 => binding.assignee.push('x'),
            _ => binding.executor_device_id.push('x'),
        }
        let bytes = g::Task { payload: Some(g::task::Payload::Approval(changed)) }.encode_to_vec();
        assert!(
            matches!(
                client.decode_generated_task_approval(&bytes),
                Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. })
            ),
            "binding {field}"
        );
    }
    for field in 0..10 {
        let mut changed = packet.clone();
        let record = request_mut(&mut changed)?.approval.as_mut().ok_or("record")?;
        match field {
            0 => record.approval_id.push('x'),
            1 => record.server_id.push('x'),
            2 => record.tool_name.push('x'),
            3 => record.capability = Some(serde_json::from_value(json!({"sendMessage":{}}))?),
            4 => record.risk_level = Some(serde_json::from_value(json!({"low":{}}))?),
            5 => record.tool_scope = Some("other".into()),
            6 => record.confirmation_mode.push('x'),
            7 => record.expires_at += 1,
            8 => record.status = "decided".into(),
            _ => {
                record.details = Some(json_value(
                    &json!({"arguments":{"command":"other"},"arguments_hash":"other"}),
                )?);
            }
        }
        let bytes = g::Task { payload: Some(g::task::Payload::Approval(changed)) }.encode_to_vec();
        let error = client
            .decode_generated_task_approval(&bytes)
            .err()
            .ok_or("changed display accepted")?;
        if field == 6 {
            assert!(matches!(error, SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed)));
        } else {
            assert!(
                matches!(
                    error,
                    SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. }
                ),
                "display {field}: {error:?}"
            );
        }
    }
    for field in 0..3 {
        let mut changed = packet.clone();
        let request = request_mut(&mut changed)?;
        match field {
            0 => request.binding = None,
            1 => request.approval = None,
            _ => request.grant_body = None,
        }
        let bytes = g::Task { payload: Some(g::task::Payload::Approval(changed)) }.encode_to_vec();
        assert!(matches!(
            client.decode_generated_task_approval(&bytes),
            Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. })
        ));
    }
    Ok(())
}

#[test]
fn generated_event_step_rules_and_revision_bounds_keep_native_refusals() -> TestResult {
    let native = event(body_variants().remove(4))?;
    let bytes = RamfluxClient::encode_generated_task_event(&native)?;
    let original = g::TaskEvent::decode(bytes.as_slice())?;
    for rule in 0..6 {
        let mut changed = original.clone();
        let Some(g::task_event_body::Value::Update(value)) =
            changed.event.as_mut().and_then(|v| v.value.as_mut())
        else {
            return Err("update".into());
        };
        let body = value.value.as_mut().ok_or("body")?;
        match rule {
            0 => body.state = Some(serde_json::from_value(json!({"done":{}}))?),
            1 => {
                body.steps.first_mut().ok_or("step")?.state =
                    Some(serde_json::from_value(json!({"running":{}}))?);
            }
            2 => body.steps.first_mut().ok_or("step")?.needs_me = None,
            3 => body.steps.push(body.steps.first().ok_or("step")?.clone()),
            4 => body.steps = vec![body.steps.first().ok_or("step")?.clone(); 65],
            _ => body.version = MAX_TASK_VERSION + 1,
        }
        refusal(
            decode(&changed.encode_to_vec()),
            if rule == 5 {
                crate::TaskRefusalCode::StaleRevision
            } else {
                crate::TaskRefusalCode::InvalidEvent
            },
        );
    }
    let mut extension = original;
    extension
        .ext
        .as_mut()
        .and_then(|v| v.ext.as_mut())
        .and_then(|v| v.members.first_mut())
        .ok_or("extension")?
        .key = "other".into();
    refusal(decode(&extension.encode_to_vec()), crate::TaskRefusalCode::InvalidEvent);
    Ok(())
}

// Shared event, carrier and approval scenarios for the complete Task round trip.
#[test]
fn t17a_event_carrier_approval_scenarios_round_trip() -> TestResult {
    all_seven_generated_task_events_preserve_native_signing_bytes()?;
    typed_task_carrier_binds_every_outer_field_and_native_signature()?;
    generated_approval_preserves_native_grant_signature_and_rejects_every_grant_field()?;
    Ok(())
}

#[path = "review_tests.rs"]
mod review_tests;

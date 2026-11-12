// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use crate::client::routed::{Kind, Routing};
use ramflux_protocol::{GroupStateChange, SharedGroupRole};
use serde_json::json;

fn entry(source: &Fixture) -> TestResult<crate::GatewayInboxEntry> {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    let mut outer = vectors["envelope"].clone();
    outer["source_principal_id"] = json!(source.manifest.principal_id);
    outer["source_device_id"] = json!(source.client.owned_device_identity()?.device_id());
    outer["created_at"] = json!(crate::custody::network_now()?);
    outer["ext"] = json!({"source_root_commitment":source.client.own_account_anchor()?});
    outer["signature"] = json!(ramflux_crypto::sign_protocol_object_with_device_branch(
        source.client.device_branch.as_ref().ok_or("branch")?,
        &outer
    )?);
    Ok(crate::GatewayInboxEntry {
        envelope: serde_json::from_value(outer)?,
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "unused-by-native-control-admission".into(),
    })
}

fn beacon(source: &Fixture) -> TestResult<g::GroupStateControl> {
    Ok(g::GroupStateControl {
        schema: super::super::controls::CONTROL_SCHEMA.into(),
        body: Some(g::GroupControlBody {
            value: Some(g::group_control_body::Value::DeviceSet(g::GroupControlBodyDeviceSet {
                group_id: "typed-state".into(),
                actor: Some(g::NativeGroupActor {
                    canonical: ramflux_protocol::canonical_json_bytes(
                        &source.client.owned_group_actor(&source.config.target_delivery_id)?,
                    )?,
                }),
                device_set_epoch: 1,
            })),
        }),
    })
}

fn frame(source: &Fixture, value: g::GroupStateControl, unknown: bool) -> TestResult<Vec<u8>> {
    let mut identity =
        source.client.allocate_generated_identity("typed-state-thread", 1000, false)?;
    identity.group_id = Some("typed-state".into());
    identity.group_epoch = Some(1);
    let mut body =
        g::Control { operation: 4, payload: Some(g::control::Payload::GroupState(value)) }
            .encode_to_vec();
    if unknown {
        body.extend_from_slice(&[0xf8, 0x07, 1]);
    }
    Ok(g::Inner { layer: g::registry::COMPILED_LAYER, kind: 8, identity: Some(identity), body }
        .encode_to_vec())
}

fn route() -> Routing {
    Routing {
        kind: Kind::GroupControl,
        conversation_id: "typed-state-thread".into(),
        group_id: Some("typed-state".into()),
        message_id: "unused-by-native-control-admission".into(),
        group_message_id: None,
        attachments: false,
    }
}

#[tokio::test]
async fn generated_group_state_uses_native_current_role_and_exact_actor_before_retention()
-> TestResult {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let own = Box::pin(Fixture::new("generated-group-state-owner")).await?;
    let outsider = Box::pin(Fixture::new("generated-group-state-outsider")).await?;
    own.client.persist_fetched_identity_directory(&outsider.manifest)?;
    let primary =
        own.client.born_v3_account.as_ref().ok_or("account")?.group_primary(own.vault.as_ref())?;
    own.client.shared_group_create_with_primary(
        "typed-state",
        "typed-state-thread",
        None,
        &own.config.target_delivery_id,
        Some(&primary),
    )?;
    let member = outsider.client.owned_group_actor(&outsider.config.target_delivery_id)?.identity;
    own.client.shared_group_change_with_primary(
        "typed-state",
        &own.config.target_delivery_id,
        GroupStateChange::Add { member: member.clone(), role: SharedGroupRole::Member },
        Some(&primary),
    )?;
    let value = beacon(&outsider)?;
    let raw = frame(&outsider, value.clone(), true)?;
    assert!(!decode(&raw)?.ok_or("typed packet")?.supported);
    own.client.authorize_generated_group_control_body(&entry(&outsider)?, &route(), &raw)?;
    let packet = from_generated(&value)?;
    let prepared = super::super::PreparedSharedGroup::Control(packet);
    own.client.authorize_prepared_shared_group(&prepared, &entry(&outsider)?, &route())?;
    own.client.shared_group_change_with_primary(
        "typed-state",
        &own.config.target_delivery_id,
        GroupStateChange::Remove {
            root_commitment: member.root_commitment,
            device_id: member.device_id,
        },
        Some(&primary),
    )?;
    assert!(
        own.client
            .authorize_prepared_shared_group(&prepared, &entry(&outsider)?, &route())
            .is_err(),
        "writer must recheck CURRENT group membership before a prepared effect"
    );
    assert!(
        own.client
            .authorize_generated_group_control_body(&entry(&outsider)?, &route(), &raw)
            .is_err(),
        "unknown fields never admit a removed native actor"
    );
    let mut changed = beacon(&own)?;
    let Some(g::group_control_body::Value::DeviceSet(changed_beacon)) =
        changed.body.as_mut().and_then(|body| body.value.as_mut())
    else {
        return Err("beacon".into());
    };
    changed_beacon.actor.as_mut().ok_or("actor")?.canonical.push(b' ');
    assert!(from_generated(&changed).is_err(), "native canonical proof bytes cannot normalize");
    let own_raw = frame(&own, beacon(&own)?, false)?;
    assert!(
        own.client
            .authorize_generated_group_control_body(&entry(&outsider)?, &route(), &own_raw)
            .is_err(),
        "a different verified pair source cannot assert the owner's actor"
    );
    Ok(())
}

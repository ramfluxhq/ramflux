// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public generated effects remain inert on a real generation-zero account with a sibling.
use super::*;
use crate::{GatewayInboxEntry, SdkError};
use ramflux_protocol::message as g;

fn actors(client: &RamfluxClient) -> TestResult<Vec<(String, Vec<u8>)>> {
    let db = client.account_db()?;
    db.actor_state_keys("")?
        .into_iter()
        .map(|key| {
            let value = db
                .load_actor_state::<Box<serde_json::value::RawValue>>(&key)?
                .ok_or("actor disappeared")?;
            Ok((key, value.get().as_bytes().to_vec()))
        })
        .collect()
}

fn dormant<T>(result: Result<T, SdkError>) {
    assert!(
        matches!(result, Err(SdkError::GeneratedRefused { reason, .. })
        if reason == "generated profile is not selected"),
        "public generated effects must refuse before allocation or authority lookup"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn generation_zero_generated_sdk_effects_are_inert() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        generation_zero_generated_sdk_effects_are_inert_body(),
    )
    .await?
}

async fn generation_zero_generated_sdk_effects_are_inert_body() -> TestResult {
    let mut own = Fixture::new("generation-zero-effects").await?;
    let sibling = own.enroll_sibling("generation-zero-sibling", "sibling").await?;
    assert!(
        !crate::client::target_selection::schema_v1_selected(),
        "test requires generation zero"
    );
    own.client.require_native_operation(
        &sibling.client.owned_device_identity()?,
        crate::client::identity_authority::NativeOperation::Sync,
    )?;
    own.client.send_direct_message("thread", "existing", "primary", b"unchanged body")?;
    own.client.account_db()?.store_message_content("thread", "existing", b"unchanged body")?;
    let before = actors(&own.client)?;
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: own.config.target_delivery_id.clone(),
        envelope: serde_json::from_value(vector["envelope"].clone())?,
    };
    dormant(own.client.apply_generated_delete_entry(
        &entry,
        &g::EventIdentity::default(),
        "thread",
        &g::Delete::default(),
    ));
    dormant(own.client.apply_generated_edit_entry(&entry, "thread", b""));
    dormant(own.client.apply_generated_reaction_entry(
        &entry,
        &g::EventIdentity::default(),
        "thread",
        &g::Reaction::default(),
    ));
    dormant(own.client.change_self_sync(
        "thread",
        g::SelfSync { operation: 6, mute: true, ..Default::default() },
    ));
    dormant(own.client.bootstrap_self_sync(&sibling.client.owned_device_identity()?));
    dormant(own.client.start_generated_history_transfer(&sibling.config.device_id));
    dormant(own.client.start_generated_history_transfers());
    dormant(own.client.encrypt_generated_group_message("group", "primary", &g::Message::default()));
    dormant(own.client.erase_self_sync_conversation("thread"));
    dormant(own.client.recreate_self_sync_conversation("thread"));
    dormant(own.client.clear_self_sync_draft_after_send("thread"));
    dormant(own.client.retire_generated_peer_control("operation"));
    dormant(own.client.generated_object_revoke_inner(g::ObjectRevokeAccess::default(), "peer"));
    let distribution = crate::SdkGroupSenderKeyDistribution {
        schema: String::new(),
        version: 0,
        group_id: "group".into(),
        sender_id: "primary".into(),
        group_key_epoch: 1,
        group_state_hash: None,
        sender_key_seed: [0; 32],
        sender_key_signature: None,
        sender_device_signing_public_key: None,
    };
    dormant(own.client.generated_group_key_inner(
        "thread",
        1,
        &distribution,
        &sibling.client.owned_device_identity()?,
    ));
    assert!(
        actors(&own.client)? == before,
        "counters, ratchets and queue actor bytes must stay unchanged"
    );
    assert_eq!(
        own.client.account_db()?.message_content("existing")?.ok_or("body missing")?,
        b"unchanged body",
        "profile refusal must preserve stored content"
    );
    Ok(())
}

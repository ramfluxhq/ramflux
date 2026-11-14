// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Active-profile malformed mutations preserve a real account and native authority checks.
use super::*;
use crate::{GatewayInboxEntry, SdkError};
use ramflux_protocol::message as g;

pub(super) fn actors(client: &RamfluxClient) -> TestResult<Vec<(String, Vec<u8>)>> {
    let db = client.account_db()?;
    // SDK actor namespaces are ASCII. Bound each indexed page and the total snapshot.
    let mut keys = Vec::new();
    for first in 0_u8..=126 {
        keys.extend(db.actor_state_key_page(&char::from(first).to_string(), 4096)?);
        assert!(keys.len() < 4096, "fixture actor snapshot exceeded its budget");
    }
    keys.into_iter()
        .map(|key| {
            let value = db
                .load_actor_state::<Box<serde_json::value::RawValue>>(&key)?
                .ok_or("actor disappeared")?;
            Ok((key, value.get().as_bytes().to_vec()))
        })
        .collect()
}

fn refused<T>(result: Result<T, SdkError>) {
    assert!(result.err().is_some(), "malformed generated effect must refuse");
}

#[tokio::test(flavor = "current_thread")]
async fn active_profile_malformed_effects_preserve_account() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        active_profile_malformed_effects_preserve_account_body(),
    )
    .await?
}

async fn active_profile_malformed_effects_preserve_account_body() -> TestResult {
    let mut own = Fixture::new("active-effects").await?;
    let sibling = own.enroll_sibling("active-sibling", "sibling").await?;
    assert!(ramflux_protocol::schema_profile::schema_v1_live(), "test requires the active profile");
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
    refused(own.client.apply_generated_delete_entry(
        &entry,
        &g::EventIdentity::default(),
        "thread",
        &g::Delete::default(),
    ));
    refused(own.client.apply_generated_edit_entry(&entry, "thread", b""));
    refused(own.client.apply_generated_reaction_entry(
        &entry,
        &g::EventIdentity::default(),
        "thread",
        &g::Reaction::default(),
    ));
    refused(own.client.encrypt_generated_group_message("group", "primary", &g::Message::default()));
    refused(own.client.generated_object_revoke_inner(g::ObjectRevokeAccess::default(), "peer"));
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
    refused(own.client.generated_group_key_inner(
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
        "malformed effects must preserve stored content"
    );
    Ok(())
}

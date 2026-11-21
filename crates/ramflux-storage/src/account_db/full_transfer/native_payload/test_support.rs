// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded physical native fixtures; these supply no signer or install authority.
use super::*;
use crate::account_db::full_transfer::{
    CodecRule, FamilyRule, FieldRule, MergeRule, full_transfer_catalog,
};
use ramflux_protocol::custody::pairing::full_transfer::{Disposition, U64};

pub(in crate::account_db::full_transfer) fn inner(
    text_bytes: usize,
) -> Result<g::Inner, Box<dyn std::error::Error>> {
    if text_bytes > g::validation::MAX_TEXT_BYTES + 1 {
        return Err("fixture text limit".into());
    }
    let author = g::QualifiedDevice {
        account_anchor: ramflux_protocol::encode_base64url([31; 32]),
        device_id: "original-native-device".into(),
        device_epoch: 1,
    };
    let conversation =
        g::dm_scope::derive(&author.account_anchor, &ramflux_protocol::encode_base64url([32; 32]))?;
    Ok(g::Inner {
        layer: g::registry::COMPILED_LAYER,
        kind: 1,
        identity: Some(g::EventIdentity {
            id: g::identity::derive(&author, &conversation, 1)?.to_vec(),
            author: Some(author),
            conversation_id: conversation,
            device_sequence: 1,
            hlc: 1000,
            ..Default::default()
        }),
        body: g::Message {
            text: "t".repeat(text_bytes),
            erasure_nonce: vec![9; 32],
            ..Default::default()
        }
        .encode_to_vec(),
    })
}

pub(in crate::account_db::full_transfer) fn rule() -> Result<FamilyRule, Box<dyn std::error::Error>>
{
    static FIELDS: [FieldRule; 3] = [
        FieldRule {
            name: "message_id",
            nullable: true,
            disposition: Disposition::Transfer,
            merge: MergeRule::Immutable,
            codec: CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false },
        },
        FieldRule {
            name: "conversation_id",
            nullable: false,
            disposition: Disposition::Transfer,
            merge: MergeRule::Immutable,
            codec: CodecRule::SqlText { min_bytes: U64(1), max_bytes: U64(32768), nullable: false },
        },
        FieldRule {
            name: "body",
            nullable: false,
            disposition: Disposition::Transfer,
            merge: MergeRule::Immutable,
            codec: CodecRule::SqlNativePayload { payload: NativePayload::DirectHistoryV1 },
        },
    ];
    // A test descriptor only: the live compiled family remains RequiresOwner until
    // evidence, erasure and contribution/materialization owners are implemented.
    let mut rule = *full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == "sql/runtime_message_content")
        .ok_or("content declaration")?;
    rule.codec_version = U64(2);
    rule.codec = &FIELDS;
    rule.require_typed_codec()?;
    Ok(rule)
}

/// Test-only unauthenticated own-account data; never fabricated peer-origin evidence.
pub(in crate::account_db::full_transfer) fn frame(
    value: &g::Inner,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let item = g::HistoryItem {
        exact_inner: value.encode_to_vec(),
        exact_original_identity: value.identity.as_ref().ok_or("fixture identity")?.encode_to_vec(),
        ..Default::default()
    };
    let item = item.encode_to_vec();
    let mut bytes = b"NDH1".to_vec();
    bytes.push(2);
    bytes.extend_from_slice(ramflux_protocol::encode_base64url([31; 32]).as_bytes());
    bytes.extend_from_slice(ramflux_protocol::encode_base64url([32; 32]).as_bytes());
    bytes.extend_from_slice(&u32::try_from(item.len())?.to_be_bytes());
    bytes.extend_from_slice(&item);
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    Ok(bytes)
}
pub(in crate::account_db::full_transfer) fn install_source(
    db: &rusqlite::Connection,
    value: &g::Inner,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = value.identity.as_ref().ok_or("fixture identity")?;
    let own = ramflux_protocol::encode_base64url([31; 32]);
    let peer = ramflux_protocol::encode_base64url([32; 32]);
    let id = ramflux_protocol::encode_base64url(&identity.id);
    db.execute_batch("CREATE TABLE runtime_account_identity(singleton INTEGER PRIMARY KEY,principal_commitment TEXT NOT NULL); CREATE TABLE runtime_actor_state(state_kind TEXT PRIMARY KEY,state_json BLOB NOT NULL); CREATE TABLE direct_message_projection(message_id TEXT NOT NULL,conversation_id TEXT NOT NULL,deleted INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS runtime_message_content(message_id TEXT PRIMARY KEY,conversation_id TEXT NOT NULL,body BLOB NOT NULL);")?;
    db.execute("INSERT INTO runtime_account_identity VALUES(1,?1)", [&own])?;
    db.execute(
        "INSERT INTO direct_message_projection VALUES(?1,?2,0)",
        rusqlite::params![&id, &identity.conversation_id],
    )?;
    db.execute(
        "INSERT INTO runtime_message_content VALUES(?1,?2,?3)",
        rusqlite::params![&id, &identity.conversation_id, value.encode_to_vec()],
    )?;
    let capture = ramflux_crypto::native_origin::OwnAuthoredCapture {
        target: identity.id.clone(),
        current: identity.id.clone(),
        original: identity.clone(),
        sent: g::OwnSentMessage {
            exact_inner: value.encode_to_vec(),
            message_id: id.clone(),
            context: Some(g::OwnContext {
                conversation_id: identity.conversation_id.clone(),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    db.execute(
        "INSERT INTO runtime_actor_state VALUES(?1,?2)",
        rusqlite::params![format!("own-history/capture/{id}"), serde_json::to_vec(&capture)?],
    )?;
    db.execute(
        "INSERT INTO runtime_actor_state VALUES(?1,?2)",
        rusqlite::params![
            format!("directory/conversation/{}", identity.conversation_id),
            serde_json::to_vec(
                &serde_json::json!({"kind":"direct","group_id":null,"participant_roots":[own,peer]})
            )?
        ],
    )?;
    Ok(())
}

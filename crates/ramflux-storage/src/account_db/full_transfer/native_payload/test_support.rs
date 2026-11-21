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
            codec: CodecRule::SqlNativePayload { payload: NativePayload::DirectInnerV1 },
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

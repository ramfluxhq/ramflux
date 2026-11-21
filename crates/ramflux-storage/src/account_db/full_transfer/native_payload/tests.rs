// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native physical admission is not original-evidence or whole-transfer acceptance.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn inner(text_bytes: usize) -> Result<g::Inner, Box<dyn std::error::Error>> {
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
#[test]
fn native_direct_payload_keeps_exact_native_text_larger_than_the_metadata_bound() -> TestResult {
    let bytes = inner(g::validation::MAX_TEXT_BYTES)?.encode_to_vec();
    assert!(
        bytes.len() > super::super::fixed_union::MAX_METADATA_BYTES,
        "fixture did not cross the metadata boundary"
    );
    let mut input = bytes.as_slice();
    let mut output = Vec::new();
    NativePayload::DirectInnerV1.copy(bytes.len() as u64, &mut input, &mut output)?;
    assert!(input.is_empty(), "native decoder left bytes unread");
    assert_eq!(output, bytes, "native payload was rewritten");
    Ok(())
}
#[test]
fn native_direct_payload_refuses_oversize_before_reading_or_emitting() -> TestResult {
    let mut output = Vec::new();
    let result = NativePayload::DirectInnerV1.copy(
        g::validation::MAX_INNER_BYTES as u64 + 1,
        &mut std::io::empty(),
        &mut output,
    );
    assert!(
        matches!(result, Err(StorageError::PairingField("UnsupportedRecord"))),
        "native decoder attempted to read an oversized payload: {result:?}"
    );
    assert!(output.is_empty(), "invalid native data escaped admission");
    let too_much_text = inner(g::validation::MAX_TEXT_BYTES + 1)?.encode_to_vec();
    assert!(
        NativePayload::DirectInnerV1.validate(&too_much_text).is_err(),
        "native text semantic bound was replaced by the outer byte cap"
    );
    Ok(())
}
#[test]
fn native_direct_payload_refuses_group_and_control_identity_shapes() -> TestResult {
    for mode in ["group", "control", "changed-id"] {
        let mut value = inner(16)?;
        let identity = value.identity.as_mut().ok_or("fixture identity")?;
        match mode {
            "group" => identity.group_id = Some("foreign-group".into()),
            "control" => {
                identity.device_sequence |= 1 << 63;
                identity.id = g::identity::derive(
                    identity.author.as_ref().ok_or("fixture author")?,
                    &identity.conversation_id,
                    identity.device_sequence,
                )?
                .to_vec();
            }
            "changed-id" => identity.id = vec![1; 32],
            _ => return Err("unknown fixture change".into()),
        }
        assert!(
            NativePayload::DirectInnerV1.validate(&value.encode_to_vec()).is_err(),
            "native direct physical shape accepted {mode}"
        );
    }
    Ok(())
}

#[test]
fn native_sql_payload_preserves_exact_large_bytes_through_independent_stream_admission()
-> TestResult {
    use crate::account_db::full_transfer::{
        CodecRule, FieldRule, MergeRule, full_transfer_catalog,
    };
    use ramflux_protocol::custody::pairing::full_transfer::{Disposition, U64, read_record_header};
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
    let inner = inner(g::validation::MAX_TEXT_BYTES)?;
    let identity = inner.identity.as_ref().ok_or("fixture identity")?;
    let body = inner.encode_to_vec();
    let db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE runtime_message_content(message_id TEXT PRIMARY KEY,conversation_id TEXT NOT NULL,body BLOB NOT NULL);")?;
    db.execute(
        "INSERT INTO runtime_message_content VALUES(?1,?2,?3)",
        rusqlite::params![
            ramflux_protocol::encode_base64url(&identity.id),
            &identity.conversation_id,
            &body,
        ],
    )?;
    let mut encoded = Vec::new();
    let size = db.query_row(
        "SELECT message_id,conversation_id,body FROM runtime_message_content",
        [],
        |row| Ok(super::super::write_full_scalar_sql_row(&rule, row, &mut encoded)),
    )??;
    assert_eq!(size, encoded.len() as u64, "native source byte count differs");
    let mut input = encoded.as_slice();
    let header = read_record_header(&mut input)?.ok_or("native record header")?;
    let mut payload = Vec::new();
    super::super::copy_full_scalar_record(&rule, &header, &mut input, &mut payload)?;
    assert!(input.is_empty(), "native framing left unchecked bytes");
    assert!(payload.ends_with(&body), "source/receiver admission rewrote native bytes");
    assert!(
        payload.len() > super::super::fixed_union::MAX_METADATA_BYTES,
        "native source fixture did not cross the metadata bound"
    );
    rule.id = "sql/foreign_payload";
    assert!(rule.validate().is_err(), "native payload was admitted under a foreign owner");
    Ok(())
}

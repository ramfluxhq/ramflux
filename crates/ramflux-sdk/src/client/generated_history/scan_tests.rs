// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use std::fmt::Write as _;

const CANARIES: [&str; 7] = [
    "retired-message-text-history-canary",
    "retired-reply-conversation-canary",
    "retired-forward-display-name-canary",
    "retired-attachment-key-first-canary",
    "retired-attachment-key-second-canary",
    "retired-thumbnail-first-canary",
    "retired-thumbnail-second-canary",
];
fn original_body() -> g::Message {
    let reply = g::MessageRef {
        id: vec![7; 32],
        conversation_id: CANARIES[1].into(),
        author_anchor: "retired-reply-root-history-canary".into(),
    };
    g::Message {
        text: CANARIES[0].into(),
        reply_to: Some(reply.clone()),
        forward: Some(g::Forward {
            original: Some(reply),
            original_display_name: Some(CANARIES[2].into()),
            origin_assertion: Vec::new(),
        }),
        media: (0..2)
            .map(|index| g::MediaRef {
                object_id: format!("retired-media-{index}-history-canary"),
                manifest_digest: vec![8; 32],
                mime_type: "image/png".into(),
                size: 100,
                key_slots: vec![g::MediaKeySlot {
                    encrypted_key: CANARIES[3 + index].as_bytes().to_vec(),
                    format: 1,
                    ..Default::default()
                }],
                inline_thumbnail: Some(g::Thumbnail {
                    mime_type: "image/png".into(),
                    width: 1,
                    height: 1,
                    encoded_image: CANARIES[5 + index].as_bytes().to_vec(),
                }),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn edited_history_import_has_no_original_body_fields() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let original = original_body();
    let item = item_with_message(&a, &a, now, original.clone())?;
    let identity = g::original_header::decode_identity(&item.exact_original_identity)?;
    let client = import_receiver_with_message(&root, &identity, &original)?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    // Exercise the production any-owner erasure locators for prepared copies, pages and drafts.
    client.account_db()?.write_transaction(|| -> Result<(),SdkError> {
        for key in ["own-copy/prepared/history-canary","history/page/history-canary","self-sync/state/history-canary"] {
            client.account_db()?.persist_message_actor_state(&id,key,&json!({"conversation_id":identity.conversation_id,"value":{"revision":"1"},"original":CANARIES}))?;
        }
        Ok(())
    })?;
    assert!(apply_claim(&client, &item)?);
    assert!(matches!(
        client.selected_franking_evidence_for_direct_message(&identity.conversation_id, &id),
        Err(SdkError::HistoryEvidence(EvidenceError::ReportOpeningRetired))
    ));
    let path = root.0.join("scan.db");
    let snapshot = client.account_db()?.write_backup_snapshot(&path)?;
    let connection = rusqlite::Connection::open(&path)?;
    let mut key = String::with_capacity(64);
    for byte in snapshot.key.bytes() {
        write!(&mut key, "{byte:02x}")?;
    }
    connection.pragma_update(None, "key", format!("x'{key}'"))?;
    scan_cells(&connection, &CANARIES)?;
    let serialized = item.encode_to_vec();
    for canary in CANARIES {
        assert!(
            !serialized.windows(canary.len()).any(|bytes| bytes == canary.as_bytes()),
            "history item retains {canary}"
        );
    }
    Ok(())
}

fn scan_cells(connection: &rusqlite::Connection, canaries: &[&str]) -> TestResult {
    let mut tables = connection.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let names = tables
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for name in names {
        let mut query =
            connection.prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))?;
        let columns = query.column_count();
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            for column in 0..columns {
                if let rusqlite::types::ValueRef::Text(bytes)
                | rusqlite::types::ValueRef::Blob(bytes) = row.get_ref(column)?
                {
                    scan_bytes(bytes, canaries, &format!("{name} column {column}"), 0)?;
                }
            }
        }
    }
    Ok(())
}

fn scan_bytes(bytes: &[u8], canaries: &[&str], location: &str, depth: usize) -> TestResult {
    assert!(depth <= g::validation::MAX_DEPTH, "scan exceeds admitted nesting depth");
    for canary in canaries {
        assert!(
            !bytes.windows(canary.len()).any(|value| value == canary.as_bytes()),
            "retired body in {location}"
        );
    }
    if let Ok(value) = ramflux_protocol::parse_i_json::<Value>(bytes) {
        scan_json(&value, canaries, location, depth + 1)?;
    }
    Ok(())
}
fn scan_json(value: &Value, canaries: &[&str], location: &str, depth: usize) -> TestResult {
    match value {
        Value::String(text) => {
            scan_bytes(text.as_bytes(), canaries, location, depth)?;
            let normalized = text.trim_end_matches('=').replace('+', "-").replace('/', "_");
            if let Ok(bytes) = ramflux_protocol::decode_base64url(&normalized)
                && !bytes.is_empty()
            {
                scan_bytes(&bytes, canaries, location, depth + 1)?;
            }
        }
        Value::Array(items) => {
            let octets = items
                .iter()
                .map(|value| value.as_u64().and_then(|value| u8::try_from(value).ok()))
                .collect::<Option<Vec<u8>>>();
            if let Some(bytes) = octets
                && !bytes.is_empty()
            {
                scan_bytes(&bytes, canaries, location, depth + 1)?;
            }
            for item in items {
                scan_json(item, canaries, location, depth + 1)?;
            }
        }
        Value::Object(items) => {
            for value in items.values() {
                scan_json(value, canaries, location, depth + 1)?;
            }
        }
        _ => (),
    }
    Ok(())
}

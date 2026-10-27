// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stable client projection for deleted direct-message rows.

use ramflux_storage::DirectMessageRecord;
use serde_json::{Value, json};

pub(crate) fn row(message: &DirectMessageRecord) -> Result<Value, serde_json::Error> {
    if message.deleted {
        Ok(json!({
            "deleted": true,
            "created_at": message.created_at,
            "conversation_id": message.conversation_id,
            "is_own": message.is_own,
        }))
    } else {
        serde_json::to_value(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deleted(is_own: bool) -> DirectMessageRecord {
        DirectMessageRecord {
            conversation_id: "thread".to_owned(),
            message_id: "identity-bearing-message-id".to_owned(),
            sender_id: "identity-bearing-sender".to_owned(),
            encrypted_body: b"identity-bearing-body".to_vec(),
            metadata: ramflux_storage::MessageMetadata {
                mentions: vec!["identity-bearing-mention".to_owned()],
                ..ramflux_storage::MessageMetadata::default()
            },
            deleted: true,
            is_own,
            created_at: 42,
            receipts: vec![ramflux_storage::MessageReceiptState {
                device_id: "identity-bearing-receiver".to_owned(),
                principal_commitment: Some("identity-bearing-root".to_owned()),
                state: "read".to_owned(),
                delivered_at: Some(43),
                read_at: Some(44),
            }],
        }
    }

    #[test]
    fn deleted_peer_and_own_rows_have_the_same_narrow_shape() -> Result<(), serde_json::Error> {
        for is_own in [false, true] {
            let record = deleted(is_own);
            assert_eq!(
                row(&record)?,
                json!({
                    "deleted": true,
                    "created_at": 42,
                    "conversation_id": "thread",
                    "is_own": is_own,
                })
            );
            let exported = serde_json::to_value(&record)?;
            assert_eq!(exported["is_own"], is_own);
            for private in ["sender_id", "encrypted_body", "metadata", "receipts"] {
                assert!(exported.get(private).is_none());
            }
        }
        Ok(())
    }
}

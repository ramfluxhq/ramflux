// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Erased revision entropy is private body material, never renderer state.
use super::{Content, MessageUpdate, content, message_update};

/// Remove revision entropy from an ordinary public content projection.
pub fn redact_content(content: &mut Content) {
    match content.value.as_mut() {
        Some(content::Value::Message(message)) => message.erasure_nonce.fill(0),
        Some(content::Value::SelfSync(sync)) => {
            if let Some(message) = sync.draft.as_mut() {
                message.erasure_nonce.fill(0);
            }
        }
        Some(content::Value::Edit(edit)) => {
            if let Some(message) = edit.replacement.as_mut() {
                message.erasure_nonce.fill(0);
            }
        }
        _ => return,
    }
    match content.value.as_mut() {
        Some(content::Value::Message(message)) => message.erasure_nonce.clear(),
        Some(content::Value::SelfSync(sync)) => {
            if let Some(message) = sync.draft.as_mut() {
                message.erasure_nonce.clear();
            }
        }
        Some(content::Value::Edit(edit)) => {
            if let Some(message) = edit.replacement.as_mut() {
                message.erasure_nonce.clear();
            }
        }
        _ => {}
    }
}

/// Public send/edit/draft input cannot choose or preserve revision entropy.
#[must_use]
pub fn public_input_has_nonce(content: &Content) -> bool {
    match content.value.as_ref() {
        Some(content::Value::Message(message)) => !message.erasure_nonce.is_empty(),
        Some(content::Value::Edit(edit)) => {
            edit.replacement.as_ref().is_some_and(|message| !message.erasure_nonce.is_empty())
        }
        Some(content::Value::SelfSync(sync)) => {
            sync.draft.as_ref().is_some_and(|message| !message.erasure_nonce.is_empty())
        }
        _ => false,
    }
}

/// Strip private revision bytes before caching, journaling or publishing an update.
pub fn redact_update(update: &mut MessageUpdate) {
    if let Some(message_update::State::Content(content)) = update.state.as_mut() {
        redact_content(content);
    }
}

macro_rules! private_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl std::fmt::Debug for super::$name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.debug_struct(stringify!($name)).field("private", &"[REDACTED]").finish_non_exhaustive()
            }
        }
    )+};
}
private_debug!(Message, Inner, HistoryItem, OwnSentMessage, HistoryOriginEvidence);

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    #[test]
    fn nonce_is_forbidden_in_drafts_and_public_input_and_redacted_in_debug()
    -> Result<(), Box<dyn std::error::Error>> {
        let message = super::super::Message {
            text: "draft".into(),
            erasure_nonce: vec![85; 32],
            ..Default::default()
        };
        let mut sync = super::super::SelfSync {
            operation: 2,
            revision: 1,
            draft: Some(message.clone()),
            ..Default::default()
        };
        assert!(super::super::self_sync::validate(&sync).is_err());
        assert!(
            super::super::validation::scan_message("SelfSync", &sync.encode_to_vec(), 3).is_err()
        );
        assert!(public_input_has_nonce(&Content {
            value: Some(content::Value::Message(message.clone()))
        }));
        assert!(public_input_has_nonce(&Content {
            value: Some(content::Value::SelfSync(sync.clone()))
        }));
        assert_eq!(format!("{message:?}"), "Message { private: \"[REDACTED]\", .. }");
        sync.draft.as_mut().ok_or("draft")?.erasure_nonce.clear();
        super::super::self_sync::validate(&sync)?;
        assert_eq!(
            super::super::validation::scan_message("SelfSync", &sync.encode_to_vec(), 3)?,
            super::super::validation::ScanOutcome::Supported
        );
        Ok(())
    }

    #[test]
    fn tag17_wire_vector_and_plaintext_revision_grammar() -> Result<(), Box<dyn std::error::Error>>
    {
        let message = super::super::Message {
            text: "yes".into(),
            erasure_nonce: (0..32).collect(),
            ..Default::default()
        };
        // Independent protobuf grammar: text tag1, then tag17 (varint 0x8a 0x01), length32.
        let mut expected = vec![0x0a, 3, b'y', b'e', b's', 0x8a, 1, 32];
        expected.extend(0..32);
        assert_eq!(message.encode_to_vec(), expected);
        assert_eq!(super::super::Message::decode(expected.as_slice())?, message);
        assert_eq!(super::super::registry::field_layer("Message", 17), Some(3));
        assert_eq!(
            super::super::validation::scan_message("Message", &expected, 3)?,
            super::super::validation::ScanOutcome::Supported
        );
        for length in [0, 1, 31, 33, 64] {
            let invalid = super::super::Message {
                text: "yes".into(),
                erasure_nonce: vec![1; length],
                ..Default::default()
            };
            assert!(
                super::super::validation::scan_message("Message", &invalid.encode_to_vec(), 3)
                    .is_err(),
                "nonce length {length}"
            );
        }
        let mut duplicate = expected.clone();
        duplicate.extend_from_slice(&expected[5..]);
        assert!(super::super::validation::scan_message("Message", &duplicate, 3).is_err());
        for wire in [vec![0x88, 1, 1], vec![0x8a, 0x81, 0, 32], vec![0x8a, 1, 0xa0, 0]] {
            let mut invalid = vec![0x0a, 3, b'y', b'e', b's'];
            invalid.extend(wire);
            invalid.extend(0..32);
            assert!(super::super::validation::scan_message("Message", &invalid, 3).is_err());
        }
        let media_only = super::super::Message { erasure_nonce: vec![1; 32], ..Default::default() };
        assert_eq!(
            super::super::validation::scan_message("Message", &media_only.encode_to_vec(), 3)?,
            super::super::validation::ScanOutcome::Supported
        );
        let outer = super::super::Message {
            sealed_group: Some(super::super::GroupSealedContent::default()),
            erasure_nonce: vec![1; 32],
            ..Default::default()
        };
        assert!(
            super::super::validation::scan_message("Message", &outer.encode_to_vec(), 3).is_err()
        );
        Ok(())
    }
}

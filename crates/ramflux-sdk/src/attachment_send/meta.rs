// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable prepare row. The file key is not in this record.

use serde::{Deserialize, Serialize};

pub(crate) const MAX_PLAINTEXT: u64 = 4 << 30;
pub(crate) const CHUNK: u64 = 524_288;
pub(crate) const LEASE: u64 = 3600;
pub(crate) const HARD: u64 = 86_400;
pub(crate) const MAX_ATTACHMENTS: usize = 16;
pub(crate) const MAX_ENTRIES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Accepting,
    Accepted,
    Reserved,
    Sealing,
    Bound,
    Uploading,
    Committed,
    Granted,
    Admitted,
    Cleaning,
    Fenced,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Recipient {
    Dm { peer: String },
    Group { group_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Row {
    pub account: String,
    pub operation_id: String,
    pub prepare_id: String,
    pub recipient: Recipient,
    pub file_name: String,
    pub mime: String,
    pub generation: u64,
    pub phase: Phase,
    pub accepted_through: u64,
    pub plaintext_length: Option<u64>,
    pub plaintext_digest: Option<[u8; 32]>,
    pub begun_at: u64,
    pub expires_at: u64,
    pub hard_deadline: u64,
    pub upload_id: Option<[u8; 32]>,
    pub object_id: Option<[u8; 32]>,
    pub manifest_hash: Option<[u8; 32]>,
    pub payload_generation: u64,
    pub segment_digests: Vec<[u8; 32]>,
    pub message_id: Option<String>,
    pub charged: u64,
    pub retired: bool,
    #[serde(default)]
    pub abandoned: Vec<[u8; 32]>,
    /// `(upload_id, object_id)` of abandoned reservations whose relay Retire is not yet confirmed.
    #[serde(default)]
    pub pending_abandon: Vec<([u8; 32], [u8; 32])>,
}

impl Row {
    #[must_use]
    pub(crate) fn fresh(intent: Intent<'_>, prepare_id: String, now: u64) -> Self {
        Self {
            account: intent.account.to_owned(),
            operation_id: intent.operation_id.to_owned(),
            prepare_id,
            recipient: intent.recipient,
            file_name: intent.file_name.to_owned(),
            mime: intent.mime.to_owned(),
            generation: 1,
            phase: Phase::Accepting,
            accepted_through: 0,
            plaintext_length: None,
            plaintext_digest: None,
            begun_at: now,
            expires_at: now.saturating_add(LEASE),
            hard_deadline: now.saturating_add(HARD),
            upload_id: None,
            object_id: None,
            manifest_hash: None,
            payload_generation: 1,
            segment_digests: Vec::new(),
            message_id: None,
            charged: 0,
            retired: false,
            abandoned: Vec::new(),
            pending_abandon: Vec::new(),
        }
    }
}

pub(crate) struct Intent<'a> {
    pub account: &'a str,
    pub operation_id: &'a str,
    pub recipient: Recipient,
    pub file_name: &'a str,
    pub mime: &'a str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct IndexEntry {
    pub prepare_id: String,
    pub account: String,
    pub operation_id: String,
    pub recipient: Recipient,
    pub file_name: String,
    pub mime: String,
    pub digest: Option<[u8; 32]>,
}

/// One grantee of one prepare. Written durably, with the exact signed grant bytes, BEFORE
/// registration, so a lost response or a crash retries the same grant id and the relay keeps
/// one receipt. The capability and the wrapped slot are filled in as each step completes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GrantRecord {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub grant_id: [u8; 32],
    pub reference_id: [u8; 32],
    #[serde(with = "b64")]
    pub signed_grant: Vec<u8>,
    #[serde(default, with = "b64_opt")]
    pub capability: Option<Vec<u8>>,
    /// Prost encoding of the finished `MediaKeySlot`.
    #[serde(default, with = "b64_opt")]
    pub slot: Option<Vec<u8>>,
    /// The device stopped being a target after this grant was planned. It is never placed
    /// in the Inner and its grant is retired.
    #[serde(default)]
    pub excluded: bool,
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&ramflux_protocol::encode_base64url(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        ramflux_protocol::decode_base64url(&text).map_err(serde::de::Error::custom)
    }
}

mod b64_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)] // the shape serde's `with` requires
    pub(super) fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&ramflux_protocol::encode_base64url(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| ramflux_protocol::decode_base64url(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

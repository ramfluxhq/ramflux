// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local group rows in `mls_kv`. Seeds stay in the account database.

use ramflux_storage::{MlsKvParam, MlsKvStore, MlsKvWrite};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::host::{fail, storage_err};
use crate::SdkError;

const GROUP: &str = "rf/lg/group";
const INVITE: &str = "rf/lg/invite";
const OUTBOX: &str = "rf/lg/outbox";
const HISTORY: &str = "rf/lg/history";
const PENDING: &str = "rf/lg/pending";
const JOIN_SK: &str = "rf/lg/join_sk";
const TOKENS: &str = "rf/lg/tokens";
const ATTACH: &str = "rf/lg/attach";
const PRIVACY_U: &str = "rf/lg/privacy_u";

const UPSERT: &str = "INSERT INTO mls_kv(label,key,value) VALUES(?1,?2,?3) \
    ON CONFLICT(label,key) DO UPDATE SET value=excluded.value";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GroupRow {
    pub group_id: [u8; 32],
    pub name: String,
    pub host_node_id: String,
    pub approval: bool,
    pub created_at_ms: u64,
    pub owner_seed: [u8; 32],
    pub owner_p: [u8; 32],
    pub join_pk: [u8; 32],
    pub join_sk: [u8; 32],
    pub mention_key: [u8; 32],
    pub epoch: u64,
    pub log_seq: u64,
    pub applied_seq: u64,
    pub te: u32,
    pub floor_seq: u64,
    pub leaf_count: u32,
    pub own_leaf: u32,
    pub admin: bool,
    pub read_log_seq: u64,
    pub genesis: Vec<u8>,
    pub token_root_pk: [u8; 32],
    pub warnings: Vec<String>,
    pub open_per_day: u32,
    pub open_spent: u32,
    pub member: bool,
    pub removed: bool,
    pub last_commit_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct InviteRow {
    pub group_id: [u8; 32],
    pub invite_id: [u8; 16],
    pub invite_sk: [u8; 32],
    pub invite_pk: [u8; 32],
    pub max_uses: u32,
    pub expires_at: u64,
    pub link: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OutboxRow {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub bytes: Vec<u8>,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct HistoryRow {
    pub log_seq: Option<u64>,
    pub appended_at: Option<u64>,
    pub post_id: String,
    pub kind: String,
    pub body: String,
    pub author_p: String,
    pub is_me: bool,
    pub state: String,
    pub send: Option<Value>,
    pub attachments: Vec<AttachRef>,
    pub mentions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AttachRef {
    pub blob_ref: String,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PendingRow {
    pub request_id: String,
    pub group_id: [u8; 32],
    pub host_node_id: String,
    pub reason: String,
    pub requested_at: u64,
    pub expires_at: u64,
    pub p: [u8; 32],
    pub seed: [u8; 32],
    pub key_package: Vec<u8>,
    pub link: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RetiredJoinSk {
    pub join_pk: [u8; 32],
    pub join_sk: [u8; 32],
    pub retired_at_ms: u64,
}

mod bytes64 {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub(super) fn serialize<S: Serializer>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(64)?;
        for byte in value {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        struct Bytes;
        impl<'de> Visitor<'de> for Bytes {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("64 bytes")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (index, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                }
                Ok(out)
            }
        }
        deserializer.deserialize_tuple(64, Bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TokenPart {
    pub te: u32,
    pub bucket: u8,
    pub input: [u8; 32],
    #[serde(with = "bytes64")]
    pub output: [u8; 64],
    pub issued_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct Wallet {
    pub te: u32,
    pub post: Vec<TokenPart>,
    pub commit: Vec<TokenPart>,
    pub open: Vec<TokenPart>,
    pub attach: Vec<TokenPart>,
    pub spent_post: u32,
    pub spent_commit: u32,
    pub spent_attach: u32,
    pub day_start_ms: u64,
    pub last_attach_issue_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AttachSecret {
    pub blob_ref: [u8; 32],
    pub key: [u8; 32],
    pub object_id: [u8; 32],
    pub del_secret: [u8; 32],
    pub del_hash: [u8; 32],
    pub plain_len: u64,
    pub cipher_len: u64,
    pub post_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PrivacyU {
    pub u_ms: u64,
    pub roll_appended_at_ms: u64,
    pub te: u32,
}

pub(crate) struct Store {
    kv: MlsKvStore,
}

impl Store {
    pub(crate) fn open(kv: MlsKvStore) -> Self {
        Self { kv }
    }

    pub(crate) fn group(&self, id: &[u8; 32]) -> Result<Option<GroupRow>, SdkError> {
        self.read(GROUP, id)
    }

    pub(crate) fn put_group(&self, row: &GroupRow) -> Result<(), SdkError> {
        self.write(GROUP, &row.group_id, row)
    }

    /// Write `row`, keeping a higher `open_spent` already stored by `open_frame`.
    pub(crate) fn put_group_merged(&self, row: &GroupRow) -> Result<(), SdkError> {
        let mut row = row.clone();
        if let Some(fresh) = self.group(&row.group_id)? {
            if fresh.open_spent > row.open_spent {
                row.open_spent = fresh.open_spent;
            }
        }
        self.put_group(&row)
    }

    pub(crate) fn kv_handle(&self) -> &MlsKvStore {
        &self.kv
    }

    pub(crate) fn invites(&self, group: &[u8; 32]) -> Result<Vec<InviteRow>, SdkError> {
        Ok(self.read(INVITE, group)?.unwrap_or_default())
    }

    pub(crate) fn put_invites(&self, group: &[u8; 32], rows: &[InviteRow]) -> Result<(), SdkError> {
        self.write(INVITE, group, &rows)
    }

    pub(crate) fn outbox(&self, group: &[u8; 32]) -> Result<Option<OutboxRow>, SdkError> {
        self.read(OUTBOX, group)
    }

    pub(crate) fn put_outbox(&self, row: &OutboxRow) -> Result<(), SdkError> {
        self.write(OUTBOX, &row.group_id, row)
    }

    pub(crate) fn clear_outbox(&self, group: &[u8; 32]) -> Result<(), SdkError> {
        self.remove(OUTBOX, group)
    }

    pub(crate) fn history(&self, group: &[u8; 32]) -> Result<Vec<HistoryRow>, SdkError> {
        Ok(self.read(HISTORY, group)?.unwrap_or_default())
    }

    pub(crate) fn put_history(&self, group: &[u8; 32], rows: &[HistoryRow]) -> Result<(), SdkError> {
        self.write(HISTORY, group, &rows)
    }

    pub(crate) fn pending(&self) -> Result<Vec<PendingRow>, SdkError> {
        Ok(self.read(PENDING, b"all")?.unwrap_or_default())
    }

    pub(crate) fn put_pending(&self, rows: &[PendingRow]) -> Result<(), SdkError> {
        self.write(PENDING, b"all", &rows)
    }

    pub(crate) fn retired(&self, group: &[u8; 32]) -> Result<Vec<RetiredJoinSk>, SdkError> {
        Ok(self.read(JOIN_SK, group)?.unwrap_or_default())
    }

    pub(crate) fn put_retired(&self, group: &[u8; 32], rows: &[RetiredJoinSk]) -> Result<(), SdkError> {
        self.write(JOIN_SK, group, &rows)
    }

    pub(crate) fn wallet(&self, group: &[u8; 32]) -> Result<Wallet, SdkError> {
        Ok(self.read(TOKENS, group)?.unwrap_or_default())
    }

    pub(crate) fn put_wallet(&self, group: &[u8; 32], wallet: &Wallet) -> Result<(), SdkError> {
        self.write(TOKENS, group, wallet)
    }

    pub(crate) fn attach(&self, group: &[u8; 32], blob_ref: &[u8; 32]) -> Result<Option<AttachSecret>, SdkError> {
        let mut key = group.to_vec();
        key.extend_from_slice(blob_ref);
        self.read(ATTACH, &key)
    }

    pub(crate) fn put_attach(&self, group: &[u8; 32], secret: &AttachSecret) -> Result<(), SdkError> {
        let mut key = group.to_vec();
        key.extend_from_slice(&secret.blob_ref);
        self.write(ATTACH, &key, secret)
    }

    pub(crate) fn privacy(&self, group: &[u8; 32]) -> Result<PrivacyU, SdkError> {
        Ok(self.read(PRIVACY_U, group)?.unwrap_or_default())
    }

    pub(crate) fn put_privacy(&self, group: &[u8; 32], row: &PrivacyU) -> Result<(), SdkError> {
        self.write(PRIVACY_U, group, row)
    }

    /// Write one JSON row inside an MLS `Staged` transaction.
    pub(crate) fn upsert_sql() -> &'static str {
        UPSERT
    }

    pub(crate) fn json_params(
        label: &str,
        key: &[u8],
        value: &impl Serialize,
    ) -> Result<Vec<MlsKvParam>, SdkError> {
        let bytes = serde_json::to_vec(value).map_err(|error| fail("internal", error.to_string()))?;
        Ok(vec![
            MlsKvParam::Text(label.to_owned()),
            MlsKvParam::Blob(key.to_vec()),
            MlsKvParam::Blob(bytes),
        ])
    }

    pub(crate) fn group_params(row: &GroupRow) -> Result<Vec<MlsKvParam>, SdkError> {
        Self::json_params(GROUP, &row.group_id, row)
    }

    pub(crate) fn history_params(group: &[u8; 32], rows: &[HistoryRow]) -> Result<Vec<MlsKvParam>, SdkError> {
        let bytes = serde_json::to_vec(rows).map_err(|error| fail("internal", error.to_string()))?;
        Ok(vec![
            MlsKvParam::Text(HISTORY.to_owned()),
            MlsKvParam::Blob(group.to_vec()),
            MlsKvParam::Blob(bytes),
        ])
    }

    fn read<T: for<'de> Deserialize<'de>>(&self, label: &str, key: &[u8]) -> Result<Option<T>, crate::SdkError> {
        let raw = self.kv.get(label, key).map_err(storage_err)?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                let value = serde_json::from_slice(&bytes).map_err(|error| fail("internal", error.to_string()))?;
                Ok(Some(value))
            }
        }
    }

    fn write<T: Serialize>(&self, label: &str, key: &[u8], value: &T) -> Result<(), crate::SdkError> {
        let bytes = serde_json::to_vec(value).map_err(|error| fail("internal", error.to_string()))?;
        self.kv
            .commit_batch(
                vec![MlsKvWrite::Put {
                    label: label.to_owned(),
                    key: key.to_vec(),
                    value: zeroize::Zeroizing::new(bytes),
                }],
                false,
                |_| Ok::<(), ramflux_mls::MlsKvError>(()),
            )
            .map_err(|error| match error {
                ramflux_storage::MlsKvCommitError::Storage(error) => storage_err(error),
                ramflux_storage::MlsKvCommitError::Caller(error) => super::host::kv_err(error),
            })
    }

    fn remove(&self, label: &str, key: &[u8]) -> Result<(), crate::SdkError> {
        self.kv
            .commit_batch(
                vec![MlsKvWrite::Delete { label: label.to_owned(), key: key.to_vec() }],
                false,
                |_| Ok::<(), ramflux_mls::MlsKvError>(()),
            )
            .map_err(|error| match error {
                ramflux_storage::MlsKvCommitError::Storage(error) => storage_err(error),
                ramflux_storage::MlsKvCommitError::Caller(error) => super::host::kv_err(error),
            })
    }
}

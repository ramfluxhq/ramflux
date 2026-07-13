// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::Serialize;

pub struct ObjectWrite<'a, T>
where
    T: Serialize,
{
    pub object_id: &'a str,
    pub manifest_hash: &'a str,
    pub nonce: &'a str,
    pub ciphertext: &'a [u8],
    pub plaintext_hash: &'a str,
    pub tombstoned: bool,
    pub backup_excluded: bool,
    pub content_key: Option<&'a [u8; 32]>,
    pub object: &'a T,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ObjectTransferRecord {
    pub transfer_id: String,
    pub object_id: String,
    pub direction: String,
    pub peer_device_id: String,
    pub manifest_hash: String,
    pub relay_endpoint: Option<String>,
    pub resume_token: Option<String>,
    pub missing_chunks: Vec<u32>,
    pub completed_chunks: Vec<u32>,
    pub state: String,
    pub last_error: Option<String>,
    pub chunk_size: u64,
    pub total_bytes: u64,
    pub done_bytes: u64,
    pub total_chunks: u32,
    pub next_chunk_index: Option<u32>,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
}

pub struct ObjectTransferWrite<'a> {
    pub transfer_id: &'a str,
    pub object_id: &'a str,
    pub direction: &'a str,
    pub peer_device_id: &'a str,
    pub manifest_hash: &'a str,
    pub relay_endpoint: Option<&'a str>,
    pub resume_token: Option<&'a str>,
    pub missing_chunks: &'a [u32],
    pub completed_chunks: &'a [u32],
    pub state: &'a str,
    pub last_error: Option<&'a str>,
    pub chunk_size: u64,
    pub total_bytes: u64,
    pub done_bytes: u64,
    pub total_chunks: u32,
    pub next_chunk_index: Option<u32>,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ObjectShareGrantRecord {
    pub object_id: String,
    pub recipient_principal_id: String,
    pub recipient_principal_commitment: Option<String>,
    pub recipient_device_id: Option<String>,
    pub conversation_id: Option<String>,
    pub shared_at: i64,
    pub revoked_at: Option<i64>,
}

pub struct ObjectShareGrantWrite<'a> {
    pub object_id: &'a str,
    pub recipient_principal_id: &'a str,
    pub recipient_principal_commitment: Option<&'a str>,
    pub recipient_device_id: Option<&'a str>,
    pub conversation_id: Option<&'a str>,
    pub shared_at: i64,
}

/// T25-A2 (OBJ-IPC-01): the durable per-`object_id` `object.put` reconciliation record. One row per
/// object (the latest logical PUT); state advances `pending` → `local_committed` → `committed`, or
/// `failed` on a permanent conflict. `terminal_result` is a compact JSON blob (identifiers/hashes/
/// transfer only — never ciphertext or key). `request_hash` binds `object_id` + `plaintext_hash` +
/// `chunk_size` + normalized relay endpoint + `operation_id` + protocol version (no secret).
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ObjectOperationRecord {
    pub object_id: String,
    pub operation_id: String,
    pub state: String,
    pub request_hash: String,
    pub manifest_hash: Option<String>,
    pub plaintext_hash: Option<String>,
    pub terminal_result: Option<serde_json::Value>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct ObjectOperationWrite<'a> {
    pub object_id: &'a str,
    pub operation_id: &'a str,
    pub state: &'a str,
    pub request_hash: &'a str,
    pub manifest_hash: Option<&'a str>,
    pub plaintext_hash: Option<&'a str>,
    pub terminal_result: Option<&'a [u8]>,
    pub last_error: Option<&'a str>,
    pub created_at: i64,
    pub updated_at: i64,
}

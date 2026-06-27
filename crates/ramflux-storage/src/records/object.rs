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

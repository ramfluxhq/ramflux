// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-local request metadata and private wire records, without identity constructors.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ContactRequestRecord {
    pub contact_identity_commitment: String,
    pub direction: String,
    pub request_id: String,
    pub principal_id: String,
    pub link_id: String,
    pub state: String,
    pub request_json: Vec<u8>,
    pub expires_at: i64,
    pub updated_at: i64,
}
#[derive(Clone, Copy)]
pub struct ContactMessageRequestWrite<'a> {
    pub sender: &'a ramflux_crypto::RootQualifiedDeviceRef,
    pub message_id: &'a str,
    pub conversation_id: &'a str,
    pub message_json: &'a [u8],
    pub expires_at: i64,
    pub created_at: i64,
}

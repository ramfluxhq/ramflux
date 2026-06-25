// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BotTrustPinRecord {
    pub bot_identity_commitment: String,
    pub bot_public_key: String,
    pub signing_key_id: String,
    pub trust_source: String,
    pub pinned_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredBotInstallRecord {
    pub bot_identity_commitment: String,
    pub bot_manifest_hash: String,
    pub grant_id: String,
    pub grant_hash: String,
    pub actor_type: String,
    pub trust_source: String,
    pub manifest_body: Vec<u8>,
    pub grant_body: Vec<u8>,
    pub scope: Vec<String>,
    pub consent_member_ids: Vec<String>,
    pub state: String,
    pub revoked_at: Option<i64>,
    pub revocation_event_id: Option<String>,
}

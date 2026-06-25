// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAccountRecord {
    pub local_account_id: String,
    pub principal_commitment: String,
    pub db_relative_path: String,
    pub object_dir_relative_path: String,
    pub account_state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HistoryEventRecord {
    pub event_id: String,
    pub event_type: String,
    pub actor_principal_id: String,
    pub actor_device_id: String,
    pub device_counter: i64,
    pub lamport_time: i64,
    pub created_at: i64,
    pub event_body: Vec<u8>,
    pub signature: String,
    pub source_device_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectionCheckpointRecord {
    pub projection_name: String,
    pub last_event_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HistoryBundle {
    pub source_device_id: String,
    pub target_device_id: String,
    pub encrypted_event_batch: Vec<HistoryEventRecord>,
    pub projection_checkpoints: Vec<ProjectionCheckpointRecord>,
    pub checkpoint_hash: String,
}

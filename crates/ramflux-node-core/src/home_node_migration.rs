// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize};

/// Applied home-node migration state for one identity binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeMigrationRecord {
    pub identity_commitment: String,
    pub old_home_node: String,
    pub new_home_node: String,
    pub new_home_node_key_hash: String,
    pub route_record_hash: String,
    pub effective_at: i64,
    pub issued_at: i64,
    pub migration_proof_hash: String,
    pub migrated_at: i64,
}

impl HomeNodeMigrationRecord {
    #[must_use]
    pub fn is_effective(&self, now: i64) -> bool {
        now >= self.effective_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeMigratedNackDelivery {
    pub target_delivery_id: String,
    pub proof_hash: String,
    pub new_home_node_hint: String,
    pub nack: ramflux_protocol::Nack,
}

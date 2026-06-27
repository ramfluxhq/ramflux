// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceDirectoryRecord {
    pub device_id: String,
    pub principal_commitment: String,
    pub source: String,
    pub verified_at: i64,
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public full-backup job rows and ordered job lifecycle controls.

mod model;
mod registry;

pub use model::*;
pub use registry::{BackupJobRegistry, VerifiedBackup, VerifiedBackupStaging};

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub const CRATE_NAME: &str = "ramflux-storage";
pub const ACCOUNT_DB_FILE: &str = "ramflux_local.sqlite";
pub const ACCOUNT_INDEX_FILE: &str = "account_index.sqlite";
/// Durable per-account hint; the index transaction remains the selection authority.
pub const BACKUP_GENERATION_MARKER: &str = ".backup-generation";
pub const SCHEMA_VERSION: i64 = 1;
pub(crate) const DEFAULT_DELIVERY_RECEIPT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
pub(crate) const MAX_DELIVERY_RECEIPT_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
pub(crate) const DEFAULT_TYPING_TTL_SECONDS: i64 = 10;
pub(crate) const MAX_TYPING_TTL_SECONDS: i64 = 30;
pub(crate) const DEFAULT_CONTACT_PRESENCE_TTL_SECONDS: i64 = 10;
pub(crate) const MAX_CONTACT_PRESENCE_TTL_SECONDS: i64 = 30;

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}

pub(crate) const fn bounded_ttl_seconds(
    ttl_seconds: i64,
    default_seconds: i64,
    max_seconds: i64,
) -> i64 {
    if ttl_seconds <= 0 {
        default_seconds
    } else if ttl_seconds > max_seconds {
        max_seconds
    } else {
        ttl_seconds
    }
}

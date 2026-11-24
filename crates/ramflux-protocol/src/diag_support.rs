// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded public-only diagnostic support keys. The empty catalog disables uploads.
use serde::{Deserialize, Serialize};

pub const MAX_CATALOG_BYTES: usize = 4096;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: String,
    pub active_epoch: Option<u32>,
    pub keys: Vec<Key>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub epoch: u32,
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    pub public_key: String,
    pub encrypt_not_before: String,
    pub encrypt_until: String,
    pub accept_until: String,
}

impl Catalog {
    /// Decode the pinned public catalog, refusing malformed or ambiguous entries.
    /// # Errors
    /// Returns a stable error for malformed, oversized or unsupported catalogs.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err("support_key_unavailable");
        }
        let catalog: Self = crate::parse_i_json(bytes).map_err(|_| "support_key_unavailable")?;
        if catalog.schema != "ramflux.diag.support-keys.v1" || catalog.keys.len() > 8 {
            return Err("support_key_unavailable");
        }
        for (index, key) in catalog.keys.iter().enumerate() {
            key.validate()?;
            if catalog.keys.iter().take(index).any(|old| old.epoch == key.epoch) {
                return Err("support_key_unavailable");
            }
        }
        if let Some(epoch) = catalog.active_epoch {
            if !catalog.keys.iter().any(|key| key.epoch == epoch) {
                return Err("support_key_unavailable");
            }
        } else if !catalog.keys.is_empty() {
            return Err("support_key_unavailable");
        }
        Ok(catalog)
    }
}

impl Key {
    fn validate(&self) -> Result<(), &'static str> {
        let public =
            crate::decode_base64url(&self.public_key).map_err(|_| "support_key_unavailable")?;
        let starts = parse_time(&self.encrypt_not_before).ok_or("support_key_unavailable")?;
        let ends = parse_time(&self.encrypt_until).ok_or("support_key_unavailable")?;
        let accepts = parse_time(&self.accept_until).ok_or("support_key_unavailable")?;
        if self.epoch == 0
            || (self.kem_id, self.kdf_id, self.aead_id) != (32, 1, 3)
            || public.len() != 32
            || public.iter().all(|byte| *byte == 0)
            || crate::encode_base64url(&public) != self.public_key
            || starts >= ends
            || accepts != ends.saturating_add(30 * 86400)
        {
            return Err("support_key_unavailable");
        }
        Ok(())
    }
}

/// UTC RFC3339 at whole-second precision, bounded to the service's supported years.
#[must_use]
pub fn format_time(seconds: u64) -> String {
    let mut days = seconds / 86400;
    let mut year = 1970_u32;
    while year < 9999 {
        let count = if leap(year) { 366 } else { 365 };
        if days < count {
            break;
        }
        days -= count;
        year += 1;
    }
    let mut month = 1_u32;
    while month < 12 {
        let count = month_days(year, month);
        if days < u64::from(count) {
            break;
        }
        days -= u64::from(count);
        month += 1;
    }
    format!(
        "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}Z",
        days + 1,
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// Parse the canonical UTC timestamps used by the embedded key catalog.
#[must_use]
pub fn parse_time(value: &str) -> Option<u64> {
    if value.len() != 20 || !value.is_ascii() {
        return None;
    }
    let year = value.get(..4)?.parse::<u32>().ok()?;
    let month = value.get(5..7)?.parse::<u32>().ok()?;
    let day = value.get(8..10)?.parse::<u32>().ok()?;
    let hour = value.get(11..13)?.parse::<u64>().ok()?;
    let minute = value.get(14..16)?.parse::<u64>().ok()?;
    let second = value.get(17..19)?.parse::<u64>().ok()?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > month_days(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days: u64 = (1970..year).map(|y| if leap(y) { 366 } else { 365 }).sum::<u64>()
        + (1..month).map(|m| u64::from(month_days(year, m))).sum::<u64>()
        + u64::from(day - 1);
    let seconds = days * 86400 + hour * 3600 + minute * 60 + second;
    (format_time(seconds) == value).then_some(seconds)
}

const fn leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}
const fn month_days(year: u32, month: u32) -> u32 {
    match month {
        2 if leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

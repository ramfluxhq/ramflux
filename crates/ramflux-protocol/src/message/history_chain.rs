// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact-item history page transcripts; hashing does not authorize any item.
use super::{identity::lp, validation::ValidationError};

/// Complete history-page transcript, preserving exact received `HistoryItem` bytes.
/// # Errors
/// Refuses invalid fixed-size fields, item counts or the four-MiB page bound.
pub fn transcript(transfer: &[u8], page: u64, previous: &[u8], items: &[&[u8]]) -> Result<Vec<u8>, ValidationError> {
    if transfer.len() != 32 || previous.len() != 32 || items.len() > 32 { return Err(ValidationError::Content); }
    let mut bytes = Vec::new();
    lp(&mut bytes, crate::domain::MESSAGE_HISTORY_PAGE.as_bytes())?;
    lp(&mut bytes, transfer)?;
    bytes.extend_from_slice(&page.to_be_bytes());
    lp(&mut bytes, previous)?;
    bytes.extend_from_slice(&u32::try_from(items.len()).map_err(|_| ValidationError::Limit)?.to_be_bytes());
    for item in items { lp(&mut bytes, item)?; }
    if bytes.len() > 4 * 1024 * 1024 { return Err(ValidationError::Limit); }
    Ok(bytes)
}

/// Hash a page's exact item sequence. Native origin proof is checked separately.
/// # Errors
/// Refuses invalid transcript fields and bounds.
pub fn digest(transfer: &[u8], page: u64, previous: &[u8], items: &[&[u8]]) -> Result<[u8; 32], ValidationError> {
    Ok(*blake3::hash(&transcript(transfer, page, previous, items)?).as_bytes())
}

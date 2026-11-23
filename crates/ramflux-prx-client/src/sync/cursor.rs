// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sync cursors are `"<epoch>:<seq>"`. The epoch is 32 lowercase hex characters.

use crate::error::{PrxError, protocol};

/// A position in one install epoch of the PRX journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCursor {
    /// 32 lowercase hex characters. Stable across a PRX restart.
    pub epoch: String,
    /// Last journal sequence included by this cursor. The next read starts after it.
    pub seq: i64,
}

/// Parses a cursor. A negative sequence, an uppercase epoch, or a non-canonical integer is refused.
///
/// # Errors
/// Returns `PrxError::Protocol` when `raw` is not `"<32 lowercase hex>:<seq>"`.
pub fn parse_cursor(raw: &str) -> Result<SyncCursor, PrxError> {
    let (epoch, seq) = raw.split_once(':').ok_or(protocol("sync cursor is invalid"))?;
    if !epoch_ok(epoch) || !seq_text_ok(seq) {
        return Err(protocol("sync cursor is invalid"));
    }
    let seq = seq.parse::<i64>().map_err(|_| protocol("sync cursor is invalid"))?;
    Ok(SyncCursor { epoch: epoch.to_owned(), seq })
}

/// Formats a cursor. The caller persists this exact string.
///
/// # Errors
/// Returns `PrxError::Protocol` when `epoch` is not 32 lowercase hex or `seq` is negative.
pub fn format_cursor(epoch: &str, seq: i64) -> Result<String, PrxError> {
    if !epoch_ok(epoch) || seq < 0 {
        return Err(protocol("sync cursor is invalid"));
    }
    Ok(format!("{epoch}:{seq}"))
}

pub(super) fn epoch_ok(epoch: &str) -> bool {
    epoch.len() == 32 && epoch.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(super) fn page_token_ok(token: &str) -> bool {
    let Some((id, ordinal)) = token.split_once(':') else {
        return false;
    };
    epoch_ok(id) && seq_text_ok(ordinal)
}

fn seq_text_ok(text: &str) -> bool {
    if text == "0" {
        return true;
    }
    let Some(first) = text.bytes().next() else {
        return false;
    };
    text.len() <= 18
        && first != b'0'
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && text.parse::<i64>().is_ok()
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `GET /api/sync/snapshot`. One page is at most four rows so the body stays inside 8 MiB.

use super::SyncDial;
use super::cursor::{SyncCursor, epoch_ok, page_token_ok, parse_cursor};
use super::op::{MirrorOp, op_from_snapshot};
use crate::capabilities::{SYNC_SNAPSHOT_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, protocol};
use reqwest::Method;
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

/// Rows requested on each snapshot page. Four full payloads fit under [`SNAPSHOT_MAX_BODY`].
pub const SNAPSHOT_PAGE_LIMIT: u16 = 4;
/// Largest snapshot body accepted. A larger page is refused and discarded.
pub const SNAPSHOT_MAX_BODY: usize = 8 * 1024 * 1024;

/// One consistent page of the inventory cut.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotPage {
    /// Install epoch of this cut.
    pub epoch: String,
    /// Journal head fixed by the first page. The WebSocket hello uses it after the last page.
    pub cursor: SyncCursor,
    /// Stable id of this cut. Later pages must repeat it.
    pub snapshot_id: String,
    /// Inventory rows in server order.
    pub rows: Vec<SnapshotRow>,
    /// Opaque token for the next page. `None` means this cut is complete.
    pub next: Option<String>,
}

/// One inventory row, already decoded into a mirror change.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotRow {
    /// Server kind: `session`, `agent`, `child_session`, `approval`, `erase_receipt`, or `turn`.
    pub kind: String,
    /// Server key for the row.
    pub key: String,
    /// The local change. `Skip` is an approval or an unknown kind.
    pub op: MirrorOp,
}

impl PrxClient {
    /// Reads one snapshot page. Pass the previous page's `next` token to resume the same cut.
    ///
    /// # Errors
    /// Returns `PrxError::Unsupported` when `sync_snapshot_v1` is not advertised, a local
    /// `field_invalid` for a bad limit or token, `ApiCode::SnapshotExpired` when the token
    /// died, and `RateLimited` when the owner already has two open cuts.
    pub async fn sync_snapshot_page(
        &self,
        caps: &crate::capabilities::Capabilities,
        page_token: Option<&str>,
        limit: u16,
    ) -> Result<SnapshotPage, PrxError> {
        require(caps, SYNC_SNAPSHOT_V1)?;
        let path = snapshot_query(page_token, limit)?;
        let raw = self.transport.call_capped(Method::GET, &path, SNAPSHOT_MAX_BODY).await?;
        decode_page(&raw.body)
    }

    /// Loopback host and port for `GET /api/sync/ws`.
    ///
    /// # Errors
    /// Returns `PrxError::Config` when the base URL is not loopback.
    pub fn sync_dial(&self) -> Result<SyncDial, PrxError> {
        self.transport.sync_dial()
    }

    /// Re-reads the bearer token for the WebSocket upgrade.
    ///
    /// # Errors
    /// Returns `PrxError::Config` when the token file is unreadable or not a header value.
    pub fn bearer(&self) -> Result<Zeroizing<String>, PrxError> {
        let token = self.transport.bearer()?;
        if token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            Ok(token)
        } else {
            Err(crate::error::config("token is not a valid header value"))
        }
    }
}

fn snapshot_query(token: Option<&str>, limit: u16) -> Result<String, PrxError> {
    if !(1..=500).contains(&limit) {
        return Err(local_refusal(ApiCode::FieldInvalid));
    }
    let mut path = format!("/api/sync/snapshot?limit={limit}");
    if let Some(token) = token.filter(|token| !token.is_empty()) {
        if !page_token_ok(token) {
            return Err(local_refusal(ApiCode::FieldInvalid));
        }
        path.push_str("&page_token=");
        path.push_str(token);
    }
    Ok(path)
}

fn decode_page(body: &[u8]) -> Result<SnapshotPage, PrxError> {
    let wire: WirePage = decode_ok(body)?;
    if !epoch_ok(&wire.epoch) || !epoch_ok(&wire.snapshot_id) || wire.rows.len() > 500 {
        return Err(protocol("sync snapshot page is invalid"));
    }
    let cursor = parse_cursor(&wire.cursor)?;
    if cursor.epoch != wire.epoch {
        return Err(protocol("sync snapshot cursor epoch does not match"));
    }
    let next = match wire.next.as_deref() {
        None => None,
        Some(token) if page_token_ok(token) && token.starts_with(&wire.snapshot_id) => {
            Some(token.to_owned())
        }
        Some(_) => return Err(protocol("sync snapshot page token is invalid")),
    };
    let mut rows = Vec::new();
    for row in wire.rows {
        if !kind_ok(&row.kind) || !key_ok(&row.key) {
            return Err(protocol("sync snapshot row is invalid"));
        }
        let op = op_from_snapshot(&row.kind, &row.key, &row.payload)?;
        rows.push(SnapshotRow { kind: row.kind, key: row.key, op });
    }
    Ok(SnapshotPage { epoch: wire.epoch, cursor, snapshot_id: wire.snapshot_id, rows, next })
}

fn kind_ok(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= 64
        && kind.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
}

fn key_ok(key: &str) -> bool {
    !key.is_empty() && key.len() <= 512 && !key.chars().any(char::is_control)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePage {
    epoch: String,
    cursor: String,
    snapshot_id: String,
    rows: Vec<WireRow>,
    next: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRow {
    kind: String,
    key: String,
    payload: Value,
}

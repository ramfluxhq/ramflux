// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! JSON ownership adapters over the shared, I/O-free client presentations.

use super::super::{CAbiError, RamfluxErrorCode};
use ramflux_client_model::{conversation, receipt};
use serde::Serialize;
use zeroize::Zeroize;

pub(super) const MAX_ROWS: usize = 4096;

#[derive(Clone, Copy, Default)]
pub(super) struct Unsigned(u64);
impl Serialize for Unsigned {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

#[derive(Clone, Copy)]
struct Signed(i64);
impl Serialize for Signed {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct Row {
    id: String,
    title: String,
    preview: Option<String>,
    pinned: bool,
    latest_ms: Option<Signed>,
    unread: u32,
    attention: u32,
}
impl Drop for Row {
    fn drop(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.preview.zeroize();
    }
}

pub(super) struct Directory {
    rows: Vec<Row>,
    visible: bool,
    query: String,
    offset: Unsigned,
    limit: Unsigned,
}
impl Drop for Directory {
    fn drop(&mut self) {
        self.query.zeroize();
    }
}

#[derive(Serialize)]
struct VisibleRow<'a> {
    id: &'a str,
    title: &'a str,
    preview: Option<&'a str>,
    pinned: bool,
    latest_ms: Option<Signed>,
    unread: u32,
    attention: u32,
}

pub(super) fn directory(input: &Directory) -> Result<serde_json::Value, CAbiError> {
    if input.rows.len() > MAX_ROWS {
        return Err(invalid("too many source rows"));
    }
    let rows = input
        .rows
        .iter()
        .map(|row| {
            let mut shared = conversation::Row::new(&row.id, &row.title);
            shared.preview = row.preview.as_deref();
            shared.pinned = row.pinned;
            shared.latest_ms = row.latest_ms.map(|value| value.0);
            shared.unread = row.unread;
            shared.attention = row.attention;
            shared
        })
        .collect::<Vec<_>>();
    let offset = usize::try_from(input.offset.0).map_err(|_| invalid("offset overflow"))?;
    let limit = usize::try_from(input.limit.0).map_err(|_| invalid("limit overflow"))?;
    let page = conversation::page(&rows, input.visible, &input.query, offset, limit)
        .map_err(|_| invalid("query exceeds shared model limit"))?;
    let totals = conversation::totals(&rows, input.visible);
    let projected = page
        .rows
        .iter()
        .map(|row| VisibleRow {
            id: row.id,
            title: row.title,
            preview: row.preview,
            pinned: row.pinned,
            latest_ms: row.latest_ms.map(Signed),
            unread: row.unread,
            attention: row.attention,
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({"rows":projected,"next_offset":page.next_offset,
        "totals":{"unread":totals.unread.to_string(),"attention":totals.attention.to_string()}}))
}

#[derive(Clone, Copy, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Receipt {
    Sending,
    WaitingForNode { retry_at_ms: Unsigned },
    Failed { retryable: bool },
    Sent,
    Delivered,
    Read,
}
impl From<Receipt> for receipt::Receipt {
    fn from(value: Receipt) -> Self {
        match value {
            Receipt::Sending => Self::Sending,
            Receipt::WaitingForNode { retry_at_ms } => {
                Self::WaitingForNode { retry_at_ms: retry_at_ms.0 }
            }
            Receipt::Failed { retryable } => Self::Failed { retryable },
            Receipt::Sent => Self::Sent,
            Receipt::Delivered => Self::Delivered,
            Receipt::Read => Self::Read,
        }
    }
}
impl TryFrom<receipt::Receipt> for Receipt {
    type Error = CAbiError;
    fn try_from(value: receipt::Receipt) -> Result<Self, Self::Error> {
        Ok(match value {
            receipt::Receipt::Sending => Self::Sending,
            receipt::Receipt::WaitingForNode { retry_at_ms } => {
                Self::WaitingForNode { retry_at_ms: Unsigned(retry_at_ms) }
            }
            receipt::Receipt::Failed { retryable } => Self::Failed { retryable },
            receipt::Receipt::Sent => Self::Sent,
            receipt::Receipt::Delivered => Self::Delivered,
            receipt::Receipt::Read => Self::Read,
            _ => {
                return Err(CAbiError::new(
                    RamfluxErrorCode::UnsupportedVersion,
                    "unknown shared receipt state",
                ));
            }
        })
    }
}

pub(super) struct ReceiptRequest {
    outgoing: bool,
    receipt: Receipt,
    now_ms: Unsigned,
}

pub(super) fn present(input: &ReceiptRequest) -> Result<serde_json::Value, CAbiError> {
    let Some(presentation) = receipt::present(input.outgoing, input.receipt.into(), input.now_ms.0)
    else {
        return Ok(serde_json::Value::Null);
    };
    Ok(serde_json::json!({"receipt":Receipt::try_from(presentation.state)?,
        "manual_retry":presentation.manual_retry,"remaining_ms":presentation.remaining_ms.map(|ms| ms.to_string())}))
}

fn invalid(message: &str) -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, message)
}

impl super::input::Decode for Directory {
    fn decode(value: &mut serde_json::Value) -> Result<Self, CAbiError> {
        use super::input as i;
        i::object(value, &["rows", "visible", "query", "offset", "limit"])?;
        let visible = i::boolean(value, "visible", None)?;
        let query = match value.get("query") {
            None => "",
            Some(serde_json::Value::String(s)) => s,
            _ => return Err(i::invalid()),
        };
        let offset = Unsigned(i::unsigned(value, "offset", Some(0))?);
        let limit = Unsigned(i::unsigned(value, "limit", Some(100))?);
        let values =
            value.get("rows").and_then(serde_json::Value::as_array).ok_or_else(i::invalid)?;
        let mut rows = Vec::new();
        for row in values {
            i::object(
                row,
                &["id", "title", "preview", "pinned", "latest_ms", "unread", "attention"],
            )?;
            let id = i::string(row, "id")?;
            let title = i::string(row, "title")?;
            let preview = i::optional(row, "preview")?;
            let pinned = i::boolean(row, "pinned", Some(false))?;
            let latest_ms = match row.get("latest_ms") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(s)) => {
                    Some(Signed(s.parse().map_err(|_| i::invalid())?))
                }
                Some(v) => Some(Signed(v.as_i64().ok_or_else(i::invalid)?)),
            };
            let unread =
                u32::try_from(i::unsigned(row, "unread", Some(0))?).map_err(|_| i::invalid())?;
            let attention =
                u32::try_from(i::unsigned(row, "attention", Some(0))?).map_err(|_| i::invalid())?;
            rows.push(Row {
                id: id.into(),
                title: title.into(),
                preview: preview.map(str::to_owned),
                pinned,
                latest_ms,
                unread,
                attention,
            });
        }
        Ok(Self { rows, visible, query: query.into(), offset, limit })
    }
}
impl super::input::Decode for ReceiptRequest {
    fn decode(value: &mut serde_json::Value) -> Result<Self, CAbiError> {
        use super::input as i;
        i::object(value, &["outgoing", "receipt", "now_ms"])?;
        let outgoing = i::boolean(value, "outgoing", None)?;
        let now_ms = Unsigned(i::unsigned(value, "now_ms", None)?);
        let receipt = value.get("receipt").ok_or_else(i::invalid)?;
        let receipt = match i::string(receipt, "state")? {
            "sending" | "sent" | "delivered" | "read" => {
                i::object(receipt, &["state"])?;
                match i::string(receipt, "state")? {
                    "sending" => Receipt::Sending,
                    "sent" => Receipt::Sent,
                    "delivered" => Receipt::Delivered,
                    _ => Receipt::Read,
                }
            }
            "failed" => {
                i::object(receipt, &["state", "retryable"])?;
                Receipt::Failed { retryable: i::boolean(receipt, "retryable", None)? }
            }
            "waiting_for_node" => {
                i::object(receipt, &["state", "retry_at_ms"])?;
                Receipt::WaitingForNode {
                    retry_at_ms: Unsigned(i::unsigned(receipt, "retry_at_ms", None)?),
                }
            }
            _ => return Err(i::invalid()),
        };
        Ok(Self { outgoing, receipt, now_ms })
    }
}

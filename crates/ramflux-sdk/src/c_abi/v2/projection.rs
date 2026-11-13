// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! JSON ownership adapters over the shared, I/O-free client presentations.

use super::super::{CAbiError, RamfluxErrorCode};
use ramflux_client_model::{conversation, receipt};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub(super) const MAX_ROWS: usize = 4096;

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(try_from = "IntegerInput")]
pub(super) struct Unsigned(u64);
#[derive(Deserialize)]
#[serde(untagged)]
enum IntegerInput {
    Text(String),
    Number(u64),
}
impl TryFrom<IntegerInput> for Unsigned {
    type Error = &'static str;
    fn try_from(value: IntegerInput) -> Result<Self, Self::Error> {
        match value {
            IntegerInput::Text(value) => value.parse().map(Self).map_err(|_| "invalid u64"),
            IntegerInput::Number(value) => Ok(Self(value)),
        }
    }
}
impl Serialize for Unsigned {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(try_from = "SignedInput")]
struct Signed(i64);
#[derive(Deserialize)]
#[serde(untagged)]
enum SignedInput {
    Text(String),
    Number(i64),
}
impl TryFrom<SignedInput> for Signed {
    type Error = &'static str;
    fn try_from(value: SignedInput) -> Result<Self, Self::Error> {
        match value {
            SignedInput::Text(value) => value.parse().map(Self).map_err(|_| "invalid i64"),
            SignedInput::Number(value) => Ok(Self(value)),
        }
    }
}
impl Serialize for Signed {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    id: String,
    title: String,
    preview: Option<String>,
    #[serde(default)]
    pinned: bool,
    latest_ms: Option<Signed>,
    #[serde(default)]
    unread: u32,
    #[serde(default)]
    attention: u32,
}
impl Drop for Row {
    fn drop(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.preview.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Directory {
    rows: Vec<Row>,
    visible: bool,
    #[serde(default)]
    query: String,
    #[serde(default)]
    offset: Unsigned,
    #[serde(default = "default_limit")]
    limit: Unsigned,
}
fn default_limit() -> Unsigned {
    Unsigned(100)
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

#[derive(Clone, Copy, Deserialize, Serialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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

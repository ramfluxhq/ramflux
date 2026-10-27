// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Snapshot directories with opaque scoped keyset cursors and a strict response budget.

use crate::prelude::*;
use serde_json::{Value, json};
mod approvals;
mod budget;
mod capture;
mod rows;
pub(super) use capture::{capture, capture_mcp_event, initialize};
pub(crate) use rows::row;

pub(super) fn handles(method: &str) -> bool {
    matches!(
        method,
        "conversation.directory"
            | "identity.directory"
            | "object.directory"
            | "group.list"
            | "mcp.server.list"
            | "mcp.approval.list"
    )
}

#[derive(serde::Deserialize)]
struct PageRequest {
    cursor: Option<String>,
    limit: Option<u32>,
}

pub(crate) fn read(client: &RamfluxClient, request: &LocalBusFrame) -> Result<Value, SdkError> {
    client.with_profile_read_scope(|| read_inner(client, request))
}

fn read_inner(client: &RamfluxClient, request: &LocalBusFrame) -> Result<Value, SdkError> {
    let (directory, field) = match request.method.as_str() {
        "conversation.directory" => ("conversation", "conversations"),
        "identity.directory" => ("identity", "identities"),
        "object.directory" => ("object", "objects"),
        "group.list" => ("group", "groups"),
        "mcp.server.list" => ("server", "server_details"),
        "mcp.approval.list" => ("approval", "approvals"),
        _ => return Err(invalid("unsupported directory")),
    };
    if matches!(directory, "group" | "server" | "approval")
        && request.body.get("cursor").is_none()
        && request.body.get("limit").is_none()
    {
        return legacy_list(client, request, directory, field);
    }
    let page: PageRequest = serde_json::from_value(request.body.clone())?;
    let limit = page.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(invalid("directory limit must be 1..=100"));
    }
    let account =
        request.account_id.as_deref().ok_or_else(|| invalid("directory requires account_id"))?;
    if directory == "approval" {
        return approvals::page(client, request, &page, limit, account);
    }
    let after = decode_cursor(page.cursor.as_deref(), account, directory)?;
    let ids = client.account_db()?.client_directory_ids(directory, &after, limit + 1)?;
    let mut result: Vec<Value> = Vec::new();
    let mut next = None;
    let mut budget = budget::Budget::new(request, field, 512 * 1024, 4096)?;
    for id in ids.iter().take(limit as usize) {
        let row = rows::row(client, directory, id)?;
        if !budget.admit(&row)? {
            let Some(last) = result
                .last()
                .and_then(|row| {
                    row.get("id").or_else(|| row.get("group_id")).or_else(|| row.get("approval_id"))
                })
                .and_then(Value::as_str)
            else {
                return Err(invalid("directory row exceeds response budget"));
            };
            next = Some(encode_cursor(account, directory, last)?);
            break;
        }
        result.push(row);
    }
    if next.is_none() && ids.len() > limit as usize {
        next = Some(encode_cursor(account, directory, &ids[limit as usize - 1])?);
    }
    let response = body(field, &result, next.as_deref());
    super::io::encode_local_bus_frame(&local_bus_response(request, response.clone()))?;
    Ok(response)
}

fn body(field: &str, rows: &[Value], next: Option<&str>) -> Value {
    let mut value = json!({field:rows,"next_cursor":next});
    if field == "server_details" {
        value["servers"] = json!(rows.iter().filter_map(|row| row.get("id")).collect::<Vec<_>>());
    }
    value
}
fn encode_cursor(account: &str, directory: &str, key: &str) -> Result<String, SdkError> {
    Ok(ramflux_protocol::encode_base64url(serde_json::to_vec(&(1, account, directory, key))?))
}
fn decode_cursor(cursor: Option<&str>, account: &str, directory: &str) -> Result<String, SdkError> {
    let Some(cursor) = cursor else {
        return Ok(String::new());
    };
    if cursor.len() > 4096 {
        return Err(invalid("invalid directory cursor"));
    }
    let bytes = ramflux_protocol::decode_base64url(cursor)
        .map_err(|_| invalid("invalid directory cursor"))?;
    let (version, a, d, key): (u32, String, String, String) =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid directory cursor"))?;
    if version != 1 || a != account || d != directory {
        return Err(invalid("directory cursor scope mismatch"));
    }
    Ok(key)
}
fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(message.to_owned())
}

pub(super) fn validate(request: &LocalBusFrame) -> Result<(), SdkError> {
    for field in ["label", "name", "mime", "title"] {
        if request.body.get(field).and_then(Value::as_str).is_some_and(|text| text.len() > 1024) {
            return Err(invalid("client metadata field exceeds 1024 bytes"));
        }
    }
    match request.method.as_str() {
        "account.create" => {
            let _: LocalBusAccountCreateRequest = serde_json::from_value(request.body.clone())?;
        }
        "message.submit" => {
            let _: LocalBusMessageSubmitRequest = serde_json::from_value(request.body.clone())?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;

fn legacy_list(
    client: &RamfluxClient,
    request: &LocalBusFrame,
    directory: &str,
    field: &str,
) -> Result<Value, SdkError> {
    let db = client.account_db()?;
    let mut after = String::new();
    let mut result: Vec<Value> = Vec::new();
    let mut budget = budget::Budget::new(request, field, super::io::MAX_LOCAL_BUS_FRAME_BYTES, 0)?;
    loop {
        let ids = db.client_directory_ids(directory, &after, 100)?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            let row = if directory == "approval" && id.starts_with("task_approval_") {
                client.task_remote_approval_by_id(id)?
            } else {
                Some(rows::row(client, directory, id)?)
            };
            let Some(row) = row else {
                continue;
            };
            if !budget.admit(&row)? {
                return Err(invalid("legacy list exceeds frame limit; use cursor/limit"));
            }
            result.push(row);
        }
        if let Some(last) = ids.last() {
            after.clone_from(last);
        }
        if ids.len() < 100 {
            break;
        }
    }
    if directory == "approval" {
        approvals::append_legacy(client, &mut result, &mut budget)?;
    }
    let response = body(field, &result, None);
    super::io::encode_local_bus_frame(&local_bus_response(request, response.clone()))?;
    Ok(response)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local approvals followed by bounded remote keyset pages, including skipped keys.
use super::{
    BTreeSet, LocalBusFrame, PageRequest, RamfluxClient, SdkError, Value, body, budget,
    decode_cursor, invalid, local_bus_response, rows,
};
use budget::Budget;
const SCAN: u32 = 101;
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Position {
    local: String,
    remote: String,
    remote_phase: bool,
    // A v1 cursor ordered all public ids together. Preserve its lower bound on upgrade.
    legacy_after: String,
}
impl Position {
    fn decode(cursor: Option<&str>, account: &str) -> Result<Self, SdkError> {
        let Some(cursor) = cursor else {
            return Ok(Self::default());
        };
        if cursor.len() > 4096 {
            return Err(invalid("invalid directory cursor"));
        }
        let bytes = ramflux_protocol::decode_base64url(cursor)
            .map_err(|_| invalid("invalid directory cursor"))?;
        if let Ok((version, scope, directory, position)) =
            serde_json::from_slice::<(u32, String, String, Self)>(&bytes)
        {
            if version != 2 || scope != account || directory != "approval" {
                return Err(invalid("directory cursor scope mismatch"));
            }
            return Ok(position);
        }
        let after = decode_cursor(Some(cursor), account, "approval")?;
        Ok(Self { local: after.clone(), legacy_after: after, ..Self::default() })
    }
    fn encode(&self, account: &str) -> Result<String, SdkError> {
        let value = ramflux_protocol::encode_base64url(serde_json::to_vec(&(
            2, account, "approval", self,
        ))?);
        if value.len() > 4096 {
            return Err(invalid("directory cursor exceeds response budget"));
        }
        Ok(value)
    }
}

pub(super) fn page(
    client: &RamfluxClient,
    request: &LocalBusFrame,
    input: &PageRequest,
    limit: u32,
    account: &str,
) -> Result<Value, SdkError> {
    let db = client.account_db()?;
    let mut position = Position::decode(input.cursor.as_deref(), account)?;
    let mut result = Vec::new();
    // Reserve space for the scoped continuation; rows are serialized once as they enter.
    let mut budget = Budget::new(request, "approvals", 512 * 1024, 4096)?;
    if !position.remote_phase {
        let ids = db.client_directory_ids("approval", &position.local, SCAN)?;
        for id in &ids {
            let row = if id.starts_with("task_approval_") {
                client.task_remote_approval_by_id(id)?
            } else {
                Some(rows::row(client, "approval", id)?)
            };
            if let Some(row) = row {
                if result.len() == limit as usize {
                    return finish(request, account, &position, &result);
                }
                if !budget.admit(&row)? {
                    if result.is_empty() {
                        return Err(invalid("directory row exceeds response budget"));
                    }
                    return finish(request, account, &position, &result);
                }
                result.push(row);
            }
            position.local.clone_from(id);
        }
        if ids.len() == SCAN as usize {
            return finish(request, account, &position, &result);
        }
        position.remote_phase = true;
    }
    let scanned = client.task_remote_approval_page(&position.remote, SCAN)?;
    let scanned_count = scanned.len();
    for (key, row) in scanned {
        if let Some(row) = row {
            let id = row["approval_id"].as_str().ok_or_else(|| invalid("approval id missing"))?;
            let already_local =
                db.client_record("approval", id)?.is_some_and(|value| value["status"] == "pending");
            if !already_local && id > position.legacy_after.as_str() {
                if result.len() == limit as usize {
                    return finish(request, account, &position, &result);
                }
                if !budget.admit(&row)? {
                    if result.is_empty() {
                        return Err(invalid("directory row exceeds response budget"));
                    }
                    return finish(request, account, &position, &result);
                }
                result.push(row);
            }
        }
        position.remote = key;
    }
    if scanned_count == SCAN as usize {
        return finish(request, account, &position, &result);
    }
    Ok(body("approvals", &result, None))
}
fn finish(
    request: &LocalBusFrame,
    account: &str,
    position: &Position,
    result: &[Value],
) -> Result<Value, SdkError> {
    // An empty page is intentional when all scanned keys were expired/decided. Its cursor
    // still advances. An oversized single live row must fail instead of looping forever.
    if result.is_empty() && position.local.is_empty() && position.remote.is_empty() {
        return Err(invalid("directory row exceeds response budget"));
    }
    let response = body("approvals", result, Some(&position.encode(account)?));
    super::super::io::encode_local_bus_frame(&local_bus_response(request, response.clone()))?;
    Ok(response)
}

pub(super) fn append_legacy(
    client: &RamfluxClient,
    result: &mut Vec<Value>,
    budget: &mut Budget,
) -> Result<(), SdkError> {
    let existing = result
        .iter()
        .filter_map(|row| row["approval_id"].as_str().or_else(|| row["id"].as_str()))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut after = String::new();
    let mut count = 0;
    loop {
        let scanned = client.task_remote_approval_page(&after, (1025_u32 - count).min(SCAN))?;
        if scanned.is_empty() {
            break;
        }
        for (key, row) in scanned {
            count += 1;
            if count > 1024 {
                return Err(invalid("legacy approval scan limit; use cursor/limit"));
            }
            after = key;
            if let Some(row) = row
                && row["approval_id"].as_str().is_some_and(|id| !existing.contains(id))
            {
                if !budget.admit(&row)? {
                    return Err(invalid("legacy list exceeds frame limit; use cursor/limit"));
                }
                result.push(row);
            }
        }
    }
    Ok(())
}

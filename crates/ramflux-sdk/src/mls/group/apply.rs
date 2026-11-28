// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Apply the host log: merge or discard our commit, receive everyone else's, then elect.

use ramflux_crypto::large_group::{
    EnvKind, LgReader, ReadReply, ReadRequest, late_roll, parse_void_payload,
};
use serde_json::json;

use super::commit::{self, require_member};
use super::events::{self, GroupEvent};
use super::host::{b64, fail, read_var};
use super::post::{self, draw_u};
use super::session::{member_op, reply_bytes};
use super::store::GroupRow;
use super::Parts;
use crate::SdkError;

pub(crate) async fn apply(parts: &Parts<'_>, group_id: &[u8; 32], now_ms: u64) -> Result<Vec<GroupEvent>, SdkError> {
    let mut group = commit::load_group(parts.store, group_id)?;
    require_member(&group)?;
    let mut events = Vec::new();
    for _ in 0..8 {
        let page = read_page(parts, &group, now_ms).await?;
        if page.entries.is_empty() {
            group.te = page.te;
            group.log_seq = page.last_seq;
            break;
        }
        for entry in &page.entries {
            if entry.seq <= group.applied_seq {
                continue;
            }
            apply_one(parts, &mut group, entry, now_ms, &mut events)?;
            group.applied_seq = entry.seq;
            group.log_seq = entry.seq;
        }
        group.te = page.te;
        group.log_seq = page.last_seq;
        if page.entries.len() < 64 {
            break;
        }
    }
    if let Ok(status) = parts.mls.status(group_id) {
        group.epoch = status.epoch;
        group.own_leaf = status.own_leaf;
        group.leaf_count = u32::try_from(status.leaves).map_err(|_| fail("internal", "leaf count"))?;
    }
    let _ = post::flush_delayed(parts, &group, now_ms).await;
    if let Err(error) = resubmit(parts, &mut group, now_ms).await
        && !soft(&error)
    {
        parts.store.put_group_merged(&group)?;
        return Err(error);
    }
    if let Err(error) = commit::elect(parts, &mut group, now_ms).await
        && !soft(&error)
    {
        parts.store.put_group_merged(&group)?;
        return Err(error);
    }
    parts.store.put_group_merged(&group)?;
    Ok(events)
}

fn apply_one(
    parts: &Parts<'_>,
    group: &mut GroupRow,
    entry: &ramflux_crypto::large_group::LogView,
    now_ms: u64,
    events: &mut Vec<GroupEvent>,
) -> Result<(), SdkError> {
    let header = &entry.envelope.header;
    let encoded = entry.envelope.encode();
    if let Some(out) = parts.store.outbox(&group.group_id)? {
        if out.bytes == encoded {
            if header.kind == EnvKind::Commit {
                commit::merge_own(parts, group, now_ms)?;
            }
            parts.store.clear_outbox(&group.group_id)?;
            note_sent(parts, group, header.post_id, entry.seq, entry.appended_at_ms)?;
            return Ok(());
        }
        if header.kind == EnvKind::Commit && out.kind == "commit" && out.epoch == header.epoch {
            commit::discard_quiet(parts, &group.group_id);
            parts.store.clear_outbox(&group.group_id)?;
        }
    }
    match header.kind {
        EnvKind::Leave | EnvKind::Void | EnvKind::Roll => {
            record_plain(parts, group, entry, now_ms, events)?;
            Ok(())
        }
        EnvKind::Commit | EnvKind::Proposal | EnvKind::Post | EnvKind::State | EnvKind::Tombstone => {
            match parts.mls.receive(&entry.envelope.payload) {
                Ok(staged) => {
                    let output = staged.commit_plain().map_err(super::host::kv_err)?;
                    match output {
                        ramflux_mls::ReceivedMessage::Application { plaintext, .. } => {
                            record_application(parts, group, entry, &plaintext, events)?;
                        }
                        ramflux_mls::ReceivedMessage::Commit { epoch, removed } => {
                            group.epoch = epoch;
                            if removed {
                                group.removed = true;
                                group.member = false;
                            }
                            let changes = header
                                .added_p
                                .iter()
                                .map(|p| json!({ "op": "add", "p": b64(p) }))
                                .collect::<Vec<_>>();
                            let changes = serde_json::Value::Array(changes);
                            events.push(events::membership_event(&group.group_id, &changes, None));
                        }
                        ramflux_mls::ReceivedMessage::Proposal { .. } | ramflux_mls::ReceivedMessage::Own { .. } => {
                            note_sent(parts, group, header.post_id, entry.seq, entry.appended_at_ms)?;
                        }
                    }
                    Ok(())
                }
                Err(error) if header.kind == EnvKind::Commit => Err(error.into()),
                Err(_) => {
                    commit::push_warning(group, "host_unusual");
                    Ok(())
                }
            }
        }
    }
}

fn record_plain(
    parts: &Parts<'_>,
    group: &mut GroupRow,
    entry: &ramflux_crypto::large_group::LogView,
    now_ms: u64,
    events: &mut Vec<GroupEvent>,
) -> Result<(), SdkError> {
    match entry.envelope.header.kind {
        EnvKind::Void => {
            let voided = parse_void_payload(&entry.envelope.payload).unwrap_or(entry.seq);
            events.push(events::void_event(&group.group_id, voided, entry.envelope.header.epoch, None));
        }
        EnvKind::Roll => {
            if late_roll(entry.appended_at_ms, now_ms) {
                commit::push_warning(group, "host_unusual");
            }
            let mut privacy = parts.store.privacy(&group.group_id)?;
            if privacy.roll_appended_at_ms != entry.appended_at_ms {
                draw_u(&mut privacy, entry.appended_at_ms, group.te)?;
                parts.store.put_privacy(&group.group_id, &privacy)?;
            }
        }
        EnvKind::Leave => {
            events.push(events::membership_event(&group.group_id, &json!([{"op": "leave"}]), None));
        }
        _ => {}
    }
    Ok(())
}

fn record_application(
    parts: &Parts<'_>,
    group: &GroupRow,
    entry: &ramflux_crypto::large_group::LogView,
    plaintext: &[u8],
    events: &mut Vec<GroupEvent>,
) -> Result<(), SdkError> {
    let header = &entry.envelope.header;
    if header.kind == EnvKind::Tombstone {
        let post_id = b64(&header.post_id);
        let post_log_seq = parts
            .store
            .history(&group.group_id)?
            .iter()
            .find(|row| row.post_id == post_id)
            .and_then(|row| row.log_seq)
            .unwrap_or(entry.seq);
        events.push(events::post_deleted_event(&group.group_id, &post_id, post_log_seq, entry.seq));
        return Ok(());
    }
    if header.kind != EnvKind::Post {
        return Ok(());
    }
    let (kind, text) = parse_plain(plaintext).map_or(("text", String::new()), |(kind, text)| (kind, text));
    events.push(events::post_event(
        &group.group_id,
        json!({
            "kind": kind,
            "post_id": b64(&header.post_id),
            "text": text,
            "author": { "anchor": "", "display": "", "ai_flag": false, "is_me": false }
        }),
    ));
    Ok(())
}

fn note_sent(
    parts: &Parts<'_>,
    group: &GroupRow,
    post_id: [u8; 16],
    log_seq: u64,
    appended_at: u64,
) -> Result<(), SdkError> {
    let id = b64(&post_id);
    let mut rows = parts.store.history(&group.group_id)?;
    let Some(row) = rows.iter_mut().find(|row| row.post_id == id) else {
        return Ok(());
    };
    row.log_seq = Some(log_seq);
    row.appended_at = Some(appended_at);
    "sent".clone_into(&mut row.state);
    parts.store.put_history(&group.group_id, &rows)
}

async fn read_page(parts: &Parts<'_>, group: &GroupRow, now_ms: u64) -> Result<ReadReply, SdkError> {
    let body = ReadRequest { from_seq: group.applied_seq.saturating_add(1), limit: 64 }.encode();
    let reply = member_op(&group.host_node_id, &parts.root, group.group_id, "read", &body, || {
        commit::open_frame(parts.store, group, &parts.root, now_ms, &group.owner_seed)
    })
    .await?;
    if reply.status != "ok" {
        return Err(fail(super::session::status_code(&reply.status), reply.status));
    }
    ReadReply::decode(&reply_bytes(&reply)?).map_err(|error| fail("bad_request", error.to_string()))
}

async fn resubmit(parts: &Parts<'_>, group: &mut GroupRow, now_ms: u64) -> Result<(), SdkError> {
    let Some(out) = parts.store.outbox(&group.group_id)? else {
        return Ok(());
    };
    let bucket = if out.kind == "commit" || out.kind == "state" { "commit" } else { "post" };
    let receipt = commit::submit(parts, group, &out.bytes, bucket, now_ms).await?;
    if out.kind == "commit" {
        commit::merge_own(parts, group, now_ms)?;
    }
    parts.store.clear_outbox(&group.group_id)?;
    let _ = receipt;
    Ok(())
}

fn parse_plain(bytes: &[u8]) -> Option<(&'static str, String)> {
    let mut dec = LgReader::new(bytes);
    let kind = dec.u8().ok()?;
    let content = read_var(&mut dec, 64 * 1024).ok()?;
    let name = match kind {
        1 => "text",
        2 => "card",
        3 => "attachment",
        4 => "application",
        _ => return None,
    };
    Some((name, String::from_utf8_lossy(content).into_owned()))
}

fn soft(error: &SdkError) -> bool {
    match error {
        SdkError::Mls { code, .. } => matches!(*code, "rate_limited" | "internal" | "queued"),
        _ => true,
    }
}

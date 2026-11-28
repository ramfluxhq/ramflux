// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Posts, cards, attachments and tombstones. Privacy delay uses the caller's `now_ms`.

#![allow(clippy::too_many_arguments)]

use ramflux_crypto::large_group::{
    CARD_JSON_MAX, EnvKind, LgWriter, ROLL_U_MAX_MS, TokenBucket, privacy_delay_applies, random_array,
    settle_at_ms,
};
use serde_json::{Value, json};

use super::attach::{self, too_many};
use super::commit::{self, require_member};
use super::host::{b64, b64_fixed, fail, put_var, random_bytes};
use super::store::{AttachRef, GroupRow, HistoryRow, PrivacyU};
use super::tokens::take;
use super::{Parts, SendState};
use crate::SdkError;

const KIND_TEXT: u8 = 1;
const KIND_CARD: u8 = 2;
const KIND_ATTACH: u8 = 3;
const KIND_APP: u8 = 4;

pub(crate) fn privacy_skips(leaf_count: u32) -> bool {
    !privacy_delay_applies(leaf_count)
}

pub(crate) async fn post_text(parts: &Parts<'_>, group_id: &[u8; 32], text: &str, now_ms: u64) -> Result<SendState, SdkError> {
    let group = commit::load_group(parts.store, group_id)?;
    require_member(&group)?;
    deliver(parts, &group, KIND_TEXT, "text", random_bytes()?, text.as_bytes(), &[], Vec::new(), None, now_ms, false).await
}

pub(crate) async fn post_card(
    parts: &Parts<'_>,
    group_id: &[u8; 32],
    card_json: &str,
    now_ms: u64,
) -> Result<SendState, SdkError> {
    let group = commit::load_group(parts.store, group_id)?;
    require_member(&group)?;
    if card_json.len() > CARD_JSON_MAX {
        return Err(fail("bad_request", "card_json exceeds 64 KiB"));
    }
    deliver(parts, &group, KIND_CARD, "card", random_bytes()?, card_json.as_bytes(), &[], Vec::new(), None, now_ms, false).await
}

pub(crate) async fn post_attachments(
    parts: &Parts<'_>,
    group_id: &[u8; 32],
    files: &[&[u8]],
    now_ms: u64,
) -> Result<SendState, SdkError> {
    let group = commit::load_group(parts.store, group_id)?;
    require_member(&group)?;
    too_many(files.len())?;
    if let Some(held) = privacy_hold(parts, &group, now_ms)? {
        return Ok(held);
    }
    let post_id = random_bytes::<16>()?;
    let mut refs = Vec::new();
    let mut stored = Vec::new();
    let mut del_hash = None;
    for file in files {
        let sealed = attach::seal(&b64(&post_id), file)?;
        if del_hash.is_none() {
            del_hash = Some(sealed.secret.del_hash);
        }
        attach::upload(parts.store, &group, &parts.root, &sealed, now_ms, &group.owner_seed).await?;
        refs.push(sealed.secret.blob_ref);
        stored.push(AttachRef { blob_ref: b64(&sealed.secret.blob_ref), state: "available".to_owned() });
    }
    deliver(parts, &group, KIND_ATTACH, "attachment", post_id, b"", &refs, stored, del_hash, now_ms, false).await
}

pub(crate) async fn submit_application(
    parts: &Parts<'_>,
    group_id: &[u8; 32],
    bytes: &[u8],
    now_ms: u64,
) -> Result<SendState, SdkError> {
    let group = commit::load_group(parts.store, group_id)?;
    require_member(&group)?;
    deliver(parts, &group, KIND_APP, "application", random_bytes()?, bytes, &[], Vec::new(), None, now_ms, false).await
}

pub(crate) async fn delete_own(
    parts: &Parts<'_>,
    group_id: &[u8; 32],
    post_id: &str,
    now_ms: u64,
) -> Result<SendState, SdkError> {
    let group = commit::load_group(parts.store, group_id)?;
    require_member(&group)?;
    let rows = parts.store.history(group_id)?;
    let Some(row) = rows.iter().find(|row| row.post_id == post_id && row.is_me) else {
        return Err(fail("not_found", "post"));
    };
    for attach in &row.attachments {
        let blob = b64_fixed::<32>(&attach.blob_ref)?;
        if let Some(secret) = parts.store.attach(group_id, &blob)? {
            attach::delete(parts.store, &group, &parts.root, &secret, now_ms, &group.owner_seed).await?;
        }
    }
    if row.log_seq.is_none() {
        mark_deleted(parts, group_id, post_id)?;
        return Ok(SendState::Sent { log_seq: 0 });
    }
    let id = b64_fixed::<16>(post_id)?;
    let plain = commit::padded(Vec::new())?;
    let mut secrets = take(parts.store, &group, &parts.root, TokenBucket::Post, 1, now_ms, &group.owner_seed).await?;
    let Some(secret) = secrets.pop() else {
        return Ok(super::rate_limited_state("post"));
    };
    let envelope = commit::seal_application(parts, &group, EnvKind::Tombstone, id, &plain, &secret, None)?;
    commit::remember_outbox(parts.store, &group, envelope.clone(), "tombstone")?;
    match commit::submit(parts, &group, &envelope, "post", now_ms).await {
        Ok(receipt) => {
            parts.store.clear_outbox(group_id)?;
            mark_deleted(parts, group_id, post_id)?;
            Ok(SendState::Sent { log_seq: receipt.log_seq })
        }
        Err(error) => Ok(super::send_state_of(Err(error))),
    }
}

pub(crate) async fn load_attachment(
    parts: &Parts<'_>,
    group_id: &[u8; 32],
    blob_ref: &[u8; 32],
    now_ms: u64,
) -> Result<Vec<u8>, SdkError> {
    let group = commit::load_group(parts.store, group_id)?;
    require_member(&group)?;
    let secret = parts.store.attach(group_id, blob_ref)?.ok_or_else(|| fail("not_found", "attachment"))?;
    attach::download(parts.store, &group, &parts.root, &secret, now_ms, &group.owner_seed).await
}

pub(crate) async fn flush_delayed(parts: &Parts<'_>, group: &GroupRow, now_ms: u64) -> Result<(), SdkError> {
    let rows = parts.store.history(&group.group_id)?;
    let due: Vec<HistoryRow> = rows.into_iter().filter(|row| delayed_due(row, now_ms)).collect();
    for row in due {
        let id = b64_fixed::<16>(&row.post_id)?;
        let code = kind_code(&row.kind);
        let mut refs = Vec::new();
        for attach in &row.attachments {
            refs.push(b64_fixed::<32>(&attach.blob_ref)?);
        }
        let _ = deliver(
            parts,
            group,
            code,
            &row.kind,
            id,
            row.body.as_bytes(),
            &refs,
            row.attachments.clone(),
            None,
            now_ms,
            true,
        )
        .await?;
    }
    Ok(())
}

async fn deliver(
    parts: &Parts<'_>,
    group: &GroupRow,
    kind_code: u8,
    kind_name: &str,
    post_id: [u8; 16],
    content: &[u8],
    refs: &[[u8; 32]],
    attachments: Vec<AttachRef>,
    del_hash: Option<[u8; 32]>,
    now_ms: u64,
    existing: bool,
) -> Result<SendState, SdkError> {
    if !existing && let Some(held) = privacy_hold(parts, group, now_ms)? {
        store_pending(parts, group, &post_id, kind_name, content, attachments, &held)?;
        return Ok(held);
    }
    let mut secrets = match take(parts.store, group, &parts.root, TokenBucket::Post, 1, now_ms, &group.owner_seed).await {
        Ok(secrets) => secrets,
        Err(error) => return as_send(error),
    };
    let Some(secret) = secrets.pop() else {
        return Ok(super::rate_limited_state("post"));
    };
    let plain = commit::padded(framed(kind_code, content, refs)?)?;
    let envelope = commit::seal_application(parts, group, EnvKind::Post, post_id, &plain, &secret, del_hash)?;
    commit::remember_outbox(parts.store, group, envelope.clone(), "post")?;
    match commit::submit(parts, group, &envelope, "post", now_ms).await {
        Ok(receipt) => {
            parts.store.clear_outbox(&group.group_id)?;
            store_sent(parts, group, &post_id, kind_name, content, attachments, receipt.log_seq, receipt.appended_at_ms)?;
            Ok(SendState::Sent { log_seq: receipt.log_seq })
        }
        Err(error) => {
            if rate_limited(&error) {
                parts.store.clear_outbox(&group.group_id)?;
            } else {
                store_queued(parts, group, &post_id, kind_name, content, attachments, &error)?;
            }
            as_send(error)
        }
    }
}

fn privacy_hold(parts: &Parts<'_>, group: &GroupRow, now_ms: u64) -> Result<Option<SendState>, SdkError> {
    if privacy_skips(group.leaf_count) {
        return Ok(None);
    }
    let mut row = parts.store.privacy(&group.group_id)?;
    if row.roll_appended_at_ms == 0 {
        draw_u(&mut row, group.created_at_ms.max(1), group.te)?;
        parts.store.put_privacy(&group.group_id, &row)?;
    }
    let settle = settle_at_ms(now_ms, row.roll_appended_at_ms, row.u_ms);
    if now_ms < settle {
        let delay_s = settle.saturating_sub(now_ms).div_ceil(1000);
        return Ok(Some(SendState::DelayedPrivacy { send_after: settle, delay_s }));
    }
    Ok(None)
}

pub(crate) fn draw_u(row: &mut PrivacyU, roll_at: u64, te: u32) -> Result<(), SdkError> {
    let raw = random_array::<8>().map_err(|error| fail("internal", error.to_string()))?;
    row.u_ms = u64::from_be_bytes(raw) % (ROLL_U_MAX_MS + 1);
    row.roll_appended_at_ms = roll_at.max(1);
    row.te = te;
    Ok(())
}

fn framed(kind: u8, content: &[u8], refs: &[[u8; 32]]) -> Result<Vec<u8>, SdkError> {
    let mut enc = LgWriter::default();
    enc.u8(kind);
    put_var(&mut enc, content);
    let count = u32::try_from(refs.len()).map_err(|_| fail("too_many_attachments", "refs"))?;
    enc.u32(count);
    for item in refs {
        enc.fixed(item);
    }
    Ok(enc.finish())
}

fn store_pending(
    parts: &Parts<'_>,
    group: &GroupRow,
    post_id: &[u8; 16],
    kind_name: &str,
    content: &[u8],
    attachments: Vec<AttachRef>,
    state: &SendState,
) -> Result<(), SdkError> {
    let SendState::DelayedPrivacy { send_after, .. } = state else {
        return Ok(());
    };
    upsert(
        parts,
        &group.group_id,
        HistoryRow {
            log_seq: None,
            appended_at: None,
            post_id: b64(post_id),
            kind: kind_name.to_owned(),
            body: String::from_utf8_lossy(content).into_owned(),
            author_p: b64(&group.owner_p),
            is_me: true,
            state: "pending".to_owned(),
            send: Some(json!({ "state": "delayed_privacy", "send_after": send_after })),
            attachments,
            mentions: Vec::new(),
        },
    )
}

fn store_queued(
    parts: &Parts<'_>,
    group: &GroupRow,
    post_id: &[u8; 16],
    kind_name: &str,
    content: &[u8],
    attachments: Vec<AttachRef>,
    error: &SdkError,
) -> Result<(), SdkError> {
    upsert(
        parts,
        &group.group_id,
        HistoryRow {
            log_seq: None,
            appended_at: None,
            post_id: b64(post_id),
            kind: kind_name.to_owned(),
            body: String::from_utf8_lossy(content).into_owned(),
            author_p: b64(&group.owner_p),
            is_me: true,
            state: "pending".to_owned(),
            send: Some(json!({ "state": "queued", "reason": error.to_string() })),
            attachments,
            mentions: Vec::new(),
        },
    )
}

fn store_sent(
    parts: &Parts<'_>,
    group: &GroupRow,
    post_id: &[u8; 16],
    kind_name: &str,
    content: &[u8],
    attachments: Vec<AttachRef>,
    log_seq: u64,
    appended_at: u64,
) -> Result<(), SdkError> {
    upsert(
        parts,
        &group.group_id,
        HistoryRow {
            log_seq: Some(log_seq),
            appended_at: Some(appended_at),
            post_id: b64(post_id),
            kind: kind_name.to_owned(),
            body: String::from_utf8_lossy(content).into_owned(),
            author_p: b64(&group.owner_p),
            is_me: true,
            state: "sent".to_owned(),
            send: Some(json!({ "state": "sent" })),
            attachments,
            mentions: Vec::new(),
        },
    )
}

fn upsert(parts: &Parts<'_>, group_id: &[u8; 32], row: HistoryRow) -> Result<(), SdkError> {
    let mut rows = parts.store.history(group_id)?;
    if let Some(existing) = rows.iter_mut().find(|item| item.post_id == row.post_id) {
        *existing = row;
    } else {
        rows.push(row);
    }
    parts.store.put_history(group_id, &rows)
}

fn mark_deleted(parts: &Parts<'_>, group_id: &[u8; 32], post_id: &str) -> Result<(), SdkError> {
    let mut rows = parts.store.history(group_id)?;
    if let Some(row) = rows.iter_mut().find(|row| row.post_id == post_id) {
        "deleted".clone_into(&mut row.state);
    }
    parts.store.put_history(group_id, &rows)
}

fn delayed_due(row: &HistoryRow, now_ms: u64) -> bool {
    let Some(send) = &row.send else {
        return false;
    };
    send.get("state").and_then(Value::as_str) == Some("delayed_privacy")
        && send.get("send_after").and_then(Value::as_u64).is_some_and(|at| now_ms >= at)
}

fn kind_code(name: &str) -> u8 {
    match name {
        "card" => KIND_CARD,
        "attachment" => KIND_ATTACH,
        "application" => KIND_APP,
        _ => KIND_TEXT,
    }
}

fn rate_limited(error: &SdkError) -> bool {
    matches!(error, SdkError::Mls { code, .. } if *code == "rate_limited")
}

fn as_send(error: SdkError) -> Result<SendState, SdkError> {
    if let SdkError::Mls { code, detail } = &error {
        if *code == "rate_limited" {
            return Ok(super::rate_limited_state(detail));
        }
        if *code == "internal" {
            return Ok(SendState::Queued { reason: error.to_string() });
        }
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::privacy_skips;

    #[test]
    fn privacy_delay_skips_under_50() {
        assert!(privacy_skips(0));
        assert!(privacy_skips(49));
        assert!(!privacy_skips(50));
        assert!(!privacy_skips(3_000));
    }
}

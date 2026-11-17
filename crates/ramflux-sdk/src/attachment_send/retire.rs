// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retirement end to end: bind registered grants to the sent message, revoke with a durable
//! tombstone before any wipe, deliver per-grant retirements through the source plane, and
//! report `relay_erased` only after every grant is retired and the source erased the bytes.
//! Retiring one grant never touches another recipient's grant.

// The bind, sweep and subset entry points are called from the send path in
// bus/dispatch/attachment_prepare.rs and from account unlock; remove this once both callers land.
#![cfg_attr(
    not(test),
    allow(dead_code, reason = "bind/sweep/subset callers are wired by the send path")
)]

use prost::Message as _;
use ramflux_protocol::large_attachment::AttachmentRegistrationReceipt;
use ramflux_protocol::message::MediaRef;
use ramflux_storage::{AccountDb, AccountIndex, ObjectReferenceAdmission, ObjectReferenceOwner};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::SdkError;
use crate::attachment_retirement::{
    AttachmentRetirementOutbox, RetirementDeliveryStatus, RetirementSource,
};
use crate::bus::state::LocalBusAccountState;
use crate::custody::{BornAccount, PrimaryVault};

use super::codes::{
    CODE_ATTACHMENT_DELETED, CODE_CANCELLED, CODE_LAYOUT_INVALID, CODE_NOT_OWNER,
    CODE_RETIREMENT_PENDING, CODE_STALE_GENERATION, Refusal,
};
use super::handles::{self, RETIREMENT, TOMBSTONE};
use super::meta::{Phase, Row};
use super::owner_wire::{decode_hex, encode_hex};
use super::plane::{Plane, RetireCall};
use super::store::Store;

/// Per-message record of what was bound and what the source has retired.
const GRANTS: &str = "attachment-grants";
const INNER: &str = "attachment-inner";

/// The pinned source authority a capability and a retirement must name.
pub(crate) struct Source<'a> {
    pub authority: &'a str,
    pub generation: u64,
    pub public_key: &'a [u8; 32],
}

/// One prepared file of a message: its prepare and the media entry that carries every grant.
pub(crate) struct Sent<'a> {
    pub prepare_id: &'a str,
    pub media: &'a MediaRef,
}

/// The grants to retire before admission: `only` names a subset of the files' grants.
pub(crate) struct Subset<'a> {
    pub message_id: &'a str,
    pub files: &'a [Sent<'a>],
    pub only: &'a [[u8; 32]],
}

/// Everything retirement needs from the account.
pub(crate) struct RetireCtx<'a> {
    pub db: &'a AccountDb,
    pub index: &'a AccountIndex,
    pub account: &'a BornAccount,
    pub vault: &'a dyn PrimaryVault,
    pub store: &'a Store,
}

/// What one delivery pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Delivery {
    pub retired: usize,
    pub pending: usize,
    pub unreachable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MessageRecord {
    message_id: String,
    revoked: bool,
    files: Vec<FileRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileRecord {
    prepare_id: String,
    object_id: String,
    reference_hash: String,
    grants: Vec<GrantRow>,
    erased: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GrantRow {
    grant_id: String,
    reference_id: String,
    retired: bool,
}

#[derive(Deserialize)]
struct RetireReply {
    state: String,
    #[serde(default)]
    object_erased: bool,
}

/// Builds the context from a live bus account.
/// # Errors
/// Returns an error when custody, the account database or the index is not available.
pub(crate) fn with_ctx<T>(
    account: &LocalBusAccountState,
    action: impl FnOnce(&RetireCtx<'_>) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    let custody = account.gateway_config.custody.as_ref().ok_or(SdkError::NetworkingPending)?;
    let born = crate::custody::load_account(
        &custody.account_root,
        &custody.account_id,
        crate::custody::network_now()?,
    )?;
    let store = super::open_store(&account.client, &custody.account_id)?;
    action(&RetireCtx {
        db: account.client.account_db()?,
        index: account.client.account_index()?,
        account: &born,
        vault: custody.vault.as_ref(),
        store: &store,
    })
}

/// Binds every grant of the message to its object reference and the retirement outbox.
/// Call after all grants are registered and wrapped and BEFORE any envelope is admitted.
/// Idempotent for the same message.
/// # Errors
/// Refuses a capability that does not decode against `source`, a foreign owner, or storage failure.
pub(crate) fn bind_message(
    ctx: &RetireCtx<'_>,
    message_id: &str,
    files: &[Sent<'_>],
    source: &Source<'_>,
    now: u64,
) -> Result<(), SdkError> {
    bind(ctx, message_id, files, source, now, None).map(|_| ())
}

/// Signs and delivers retirements for `only`, a subset of a prepare's grants, for devices that
/// stopped being targets before the message was admitted. The message is not tombstoned.
/// # Errors
/// As [`bind_message`], plus signing failures.
pub(crate) fn retire_grants(
    ctx: &RetireCtx<'_>,
    plane: Option<&dyn Plane>,
    subset: &Subset<'_>,
    source: &Source<'_>,
    now: u64,
) -> Result<Delivery, SdkError> {
    let record = bind(ctx, subset.message_id, subset.files, source, now, Some(subset.only))?;
    begin_all(ctx, &record, Some(subset.only), now)?;
    deliver(ctx, plane, source, now)
}

/// A cancel after Commit: retires every registered grant of an unadmitted prepare. The local
/// key was already wiped by the cancel itself.
/// # Errors
/// As [`retire_grants`]. A prepare with no stored media entry has no grant to retire.
pub(crate) fn cancel_registered(
    ctx: &RetireCtx<'_>,
    plane: Option<&dyn Plane>,
    prepare_id: &str,
    source: &Source<'_>,
    now: u64,
) -> Result<Delivery, SdkError> {
    let Ok(stored) = ctx.store.read_named(prepare_id, "media.bin") else {
        return Ok(Delivery::default());
    };
    let media =
        MediaRef::decode(stored.as_slice()).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let message_id = format!("unadmitted:{prepare_id}");
    let files = [Sent { prepare_id, media: &media }];
    let ids = grant_ids(&media)?;
    retire_grants(
        ctx,
        plane,
        &Subset { message_id: &message_id, files: &files, only: &ids },
        source,
        now,
    )
}

/// Revokes a sent message. The retirement intent and the terminal tombstone are durable before
/// any key is wiped or any retirement is signed. Returns `relay_erased` or `retirement_pending`.
/// # Errors
/// `not_owner` for a message this account did not send, or a storage failure.
pub(crate) fn revoke(
    ctx: &RetireCtx<'_>,
    plane: Option<&dyn Plane>,
    message_id: &str,
    source: &Source<'_>,
    now: u64,
) -> Result<&'static str, SdkError> {
    let mut record = load_record(ctx.db, message_id)?
        .ok_or_else(|| SdkError::from(Refusal::new(CODE_NOT_OWNER)))?;
    if !record.revoked {
        let existing = ctx.db.client_record(RETIREMENT, message_id)?;
        if handles::revoke_state(existing.as_ref()) != "relay_erased" {
            ctx.db.persist_client_record(
                RETIREMENT,
                message_id,
                &json!({ "relay_erased": false }),
            )?;
        }
        record.revoked = true;
        save_record(ctx.db, &record)?;
        ctx.db.persist_client_record(TOMBSTONE, message_id, &json!({ "revoked_at": now }))?;
    }
    handles::fence_message(message_id);
    ctx.db.persist_client_record(INNER, message_id, &json!({ "retired": true }))?;
    for file in &record.files {
        ctx.store.retire_and_wipe(&file.prepare_id)?;
    }
    begin_all(ctx, &record, None, now)?;
    deliver(ctx, plane, source, now)?;
    let row = ctx.db.client_record(RETIREMENT, message_id)?;
    Ok(handles::revoke_state(row.as_ref()))
}

/// Re-delivers every queued retirement and finishes interrupted local wipes. Call when the
/// account unlocks, and again whenever the source may be reachable.
/// # Errors
/// Returns a storage or signing failure. An unreachable source is not an error.
pub(crate) fn sweep(
    ctx: &RetireCtx<'_>,
    plane: Option<&dyn Plane>,
    source: &Source<'_>,
    now: u64,
) -> Result<Delivery, SdkError> {
    ctx.store.cleanup_cancelled()?;
    deliver(ctx, plane, source, now)
}

/// Import and publication barrier. `attachment_deleted` once tombstoned, `retirement_pending`
/// while a revoke is recorded and not yet confirmed.
/// # Errors
/// Returns the stable refusal above.
pub(crate) fn barrier(client: &crate::RamfluxClient, message_id: &str) -> Result<(), SdkError> {
    barrier_db(client.account_db()?, message_id)
}

/// [`barrier`] on a database handle.
/// # Errors
/// As [`barrier`].
pub(crate) fn barrier_db(db: &AccountDb, message_id: &str) -> Result<(), SdkError> {
    if db.client_record(TOMBSTONE, message_id)?.is_some() {
        return Err(Refusal::new(CODE_ATTACHMENT_DELETED).into());
    }
    if let Some(row) = db.client_record(RETIREMENT, message_id)?
        && handles::revoke_state(Some(&row)) != "relay_erased"
    {
        return Err(Refusal::new(CODE_RETIREMENT_PENDING).into());
    }
    Ok(())
}

/// Seal-checkpoint and publication barrier for one prepare generation.
/// # Errors
/// `stale_generation` for another generation, `cancelled` for a fenced or cleaning prepare.
pub(crate) fn barrier_prepare(row: &Row, generation: u64) -> Result<(), Refusal> {
    if row.generation != generation {
        return Err(Refusal::new(CODE_STALE_GENERATION));
    }
    if matches!(row.phase, Phase::Fenced | Phase::Cleaning) {
        return Err(Refusal::new(CODE_CANCELLED));
    }
    Ok(())
}

/// Deleting or revoking the last local reference to a prepare removes its key, snapshot and
/// segment cache. It retires no grant and asks the source for no erasure.
/// # Errors
/// Returns `seal_failed` when the record or a file cannot be written or removed.
pub(crate) fn release_local(store: &Store, prepare_id: &str) -> Result<(), Refusal> {
    store.retire_and_wipe(prepare_id).map(|_| ())
}

fn bind(
    ctx: &RetireCtx<'_>,
    message_id: &str,
    files: &[Sent<'_>],
    source: &Source<'_>,
    now: u64,
    only: Option<&[[u8; 32]]>,
) -> Result<MessageRecord, SdkError> {
    let outbox = AttachmentRetirementOutbox::new(ctx.db, ctx.index, ctx.account)?;
    let retirement_source = RetirementSource {
        authority: source.authority,
        generation: source.generation,
        signing_public_key: source.public_key,
    };
    let mut record = load_record(ctx.db, message_id)?.unwrap_or_else(|| MessageRecord {
        message_id: message_id.to_owned(),
        revoked: false,
        files: Vec::new(),
    });
    for sent in files {
        let (object_hex, relay_hex) = identity(sent.media)?;
        let reference_hash = reference_hash(message_id, &object_hex)?;
        ctx.db.register_object_reference(
            ObjectReferenceAdmission::FreshMessage,
            &ObjectReferenceOwner {
                reference_hash: &reference_hash,
                wire_id: &object_hex,
                manifest_hash: &relay_hex,
                selector: &object_hex,
                message_id,
                reference: &json!({}),
                metadata: &json!({}),
            },
        )?;
        let at = if let Some(at) =
            record.files.iter().position(|file| file.prepare_id == sent.prepare_id)
        {
            at
        } else {
            record.files.push(FileRecord {
                prepare_id: sent.prepare_id.to_owned(),
                object_id: object_hex.clone(),
                reference_hash: reference_hash.clone(),
                grants: Vec::new(),
                erased: false,
            });
            record.files.len() - 1
        };
        for slot in &sent.media.key_slots {
            let grant_id = hash32(&slot.grant_id)?;
            if only.is_some_and(|ids| !ids.contains(&grant_id)) {
                continue;
            }
            let (grant, _) = AttachmentRegistrationReceipt::decode_capability(
                &slot.read_capability,
                source.authority,
                source.generation,
                source.public_key,
                now,
            )
            .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
            if grant.grant().grant_id != grant_id {
                return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
            }
            outbox.bind_registered(
                message_id,
                &reference_hash,
                &slot.read_capability,
                &retirement_source,
                now,
            )?;
            let id = encode_hex(&grant_id);
            if !record.files[at].grants.iter().any(|row| row.grant_id == id) {
                record.files[at].grants.push(GrantRow {
                    grant_id: id,
                    reference_id: encode_hex(&grant.grant().reference_id),
                    retired: false,
                });
            }
        }
    }
    save_record(ctx.db, &record)?;
    Ok(record)
}

fn begin_all(
    ctx: &RetireCtx<'_>,
    record: &MessageRecord,
    only: Option<&[[u8; 32]]>,
    now: u64,
) -> Result<(), SdkError> {
    let outbox = AttachmentRetirementOutbox::new(ctx.db, ctx.index, ctx.account)?;
    for file in &record.files {
        for grant in file.grants.iter().filter(|row| !row.retired) {
            if only
                .is_some_and(|ids| !ids.contains(&decode_hex(&grant.grant_id).unwrap_or([0; 32])))
            {
                continue;
            }
            outbox.begin(&decode_hex(&grant.reference_id)?, ctx.vault, now)?;
        }
    }
    Ok(())
}

/// Delivers queued retirements. A timeout, an unreachable source or a `pending` answer keeps
/// the work queued; only `retired` settles it.
fn deliver(
    ctx: &RetireCtx<'_>,
    plane: Option<&dyn Plane>,
    source: &Source<'_>,
    now: u64,
) -> Result<Delivery, SdkError> {
    let outbox = AttachmentRetirementOutbox::new(ctx.db, ctx.index, ctx.account)?;
    let retirement_source = RetirementSource {
        authority: source.authority,
        generation: source.generation,
        signing_public_key: source.public_key,
    };
    let mut out = Delivery::default();
    let mut after: Option<[u8; 32]> = None;
    loop {
        let page = outbox.pending(after.as_ref(), 64, ctx.vault, now)?;
        let Some(last) = page.last() else { break };
        after = Some(last.signed.request().operation_id);
        for item in &page {
            let request = item.signed.request();
            let Some(plane) = plane else {
                out.pending = out.pending.saturating_add(1);
                out.unreachable = true;
                continue;
            };
            let canonical =
                request.canonical_bytes().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
            let reply = plane
                .retire(&RetireCall { retirement: &canonical, signature: item.signed.signature() });
            let parsed =
                reply.ok().and_then(|bytes| serde_json::from_slice::<RetireReply>(&bytes).ok());
            let Some(parsed) = parsed else {
                out.pending = out.pending.saturating_add(1);
                out.unreachable = true;
                continue;
            };
            if parsed.state == "retired" {
                let message = ctx.db.native_reference_message(&request.reference_id)?;
                outbox.apply_authenticated_response(
                    request,
                    &retirement_source,
                    RetirementDeliveryStatus::Retired,
                )?;
                if let Some(message) = message {
                    note_retired(ctx, &message, &request.grant_id, parsed.object_erased)?;
                }
                out.retired = out.retired.saturating_add(1);
            } else {
                outbox.apply_authenticated_response(
                    request,
                    &retirement_source,
                    RetirementDeliveryStatus::RevocationPending,
                )?;
                out.pending = out.pending.saturating_add(1);
            }
        }
        if page.len() < 64 {
            break;
        }
    }
    Ok(out)
}

fn note_retired(
    ctx: &RetireCtx<'_>,
    message_id: &str,
    grant_id: &[u8; 32],
    erased: bool,
) -> Result<(), SdkError> {
    let Some(mut record) = load_record(ctx.db, message_id)? else {
        return Ok(());
    };
    let id = encode_hex(grant_id);
    for file in &mut record.files {
        if let Some(row) = file.grants.iter_mut().find(|row| row.grant_id == id) {
            row.retired = true;
            if erased {
                file.erased = true;
            }
        }
    }
    save_record(ctx.db, &record)?;
    finish(ctx, &record)
}

/// ACK cleanup: once every grant of the message is retired, the capabilities kept for
/// delivery are wiped, and a revoked message becomes `relay_erased` when the source also
/// erased every object.
fn finish(ctx: &RetireCtx<'_>, record: &MessageRecord) -> Result<(), SdkError> {
    let all_retired = record.files.iter().all(|file| file.grants.iter().all(|row| row.retired));
    if !all_retired {
        return Ok(());
    }
    for file in &record.files {
        ctx.store.wipe_grant_material(&file.prepare_id)?;
    }
    if record.revoked && record.files.iter().all(|file| file.erased) {
        ctx.db.persist_client_record(
            RETIREMENT,
            &record.message_id,
            &json!({ "relay_erased": true }),
        )?;
    }
    Ok(())
}

fn load_record(db: &AccountDb, message_id: &str) -> Result<Option<MessageRecord>, SdkError> {
    let Some(value) = db.client_record(GRANTS, message_id)? else {
        return Ok(None);
    };
    serde_json::from_value(value).map(Some).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID).into())
}

fn save_record(db: &AccountDb, record: &MessageRecord) -> Result<(), SdkError> {
    let value: Value =
        serde_json::to_value(record).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    db.persist_client_record(GRANTS, &record.message_id, &value)?;
    Ok(())
}

fn identity(media: &MediaRef) -> Result<(String, String), Refusal> {
    let object = decode_hex(&media.object_id)?;
    let manifest = media.large_manifest.as_ref().ok_or(Refusal::new(CODE_LAYOUT_INVALID))?;
    let relay = hash32(&manifest.manifest_id)?;
    Ok((encode_hex(&object), encode_hex(&relay)))
}

fn grant_ids(media: &MediaRef) -> Result<Vec<[u8; 32]>, Refusal> {
    media.key_slots.iter().map(|slot| hash32(&slot.grant_id)).collect()
}

fn reference_hash(message_id: &str, object_hex: &str) -> Result<String, SdkError> {
    Ok(ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.sent_reference.v1",
        &ramflux_protocol::canonical_json_bytes(&(message_id, object_hex))?,
    ))
}

fn hash32(bytes: &[u8]) -> Result<[u8; 32], Refusal> {
    bytes.try_into().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))
}

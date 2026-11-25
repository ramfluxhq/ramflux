// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local bus methods for prepare and import. They do not allocate an object.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::SdkError;
use crate::bus::daemon::LocalBusDispatchResult;
use crate::bus::dispatch::{local_bus_account_mut, local_bus_ok};
use crate::bus::io::request_account_id;
use crate::bus::protocol::LocalBusFrame;

use super::codes::{
    CODE_AUTHORITY_UNAVAILABLE, CODE_DISABLED, CODE_DUPLICATE, CODE_LAYOUT_INVALID,
    CODE_SEAL_FAILED, Refusal,
};
use super::handles;
use super::meta::{CHUNK, Intent, Phase, Recipient, Row};
use super::owner_wire::decode_hex;
use super::store::Store;
use super::upload::{self, AckRecord, journal_key};
use super::{CONFIG_DIRECTORY, CONFIG_ID, enabled_value};

/// # Errors
/// Returns a stable refusal or a local-bus decode error.
pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut crate::bus::state::LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, request_account_id(request)?)?;
    match request.method.as_str() {
        "attachment.prepare.begin" => begin(account, request),
        "attachment.prepare.chunk" => chunk(account, request),
        "attachment.prepare.finish" => finish(account, request),
        "attachment.prepare.status" => status(account, request),
        "attachment.prepare.cancel" => cancel(account, request).await,
        "attachment.prepare.renew" => renew(account, request),
        "attachment.import.begin" => handles::begin(account, request),
        "attachment.import.status" => handles::status(account, request),
        "attachment.import.read" => handles::read(account, request),
        "attachment.import.finish" => handles::finish(account, request),
        "attachment.import.cancel" => handles::cancel(account, request),
        "attachment.revoke" => revoke(account, request).await,
        "attachment.enable" => enable(account, request).await,
        _ => Err(SdkError::LocalBus(format!("unsupported local bus method: {}", request.method))),
    }
}

fn begin(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: BeginBody = serde_json::from_value(request.body.clone())?;
    let id = request_account_id(request)?;
    let store = open_store(&account.client, id)?;
    let enabled = flag(&account.client)?;
    let now = unix_now()?;
    let recipient = recipient(&body)?;
    let intent = Intent {
        account: id,
        operation_id: &body.operation_id,
        recipient,
        file_name: &body.file_name,
        mime: &body.mime,
    };
    let relative = body.path.as_deref().map(std::path::Path::new);
    let row = store.begin(intent, enabled, now, relative)?;
    Ok(local_bus_ok(json!({
        "prepare_id": row.prepare_id,
        "generation": row.generation,
        "max_chunk": CHUNK,
        "expires_at": row.expires_at,
        "state": phase_name(&row.phase),
        "accepted_through": row.accepted_through,
        "plaintext_length": row.plaintext_length,
        "plaintext_digest": row.plaintext_digest.map(|digest| super::owner_wire::encode_hex(&digest)),
    })))
}

fn chunk(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: ChunkBody = serde_json::from_value(request.body.clone())?;
    let store = open_store(&account.client, request_account_id(request)?)?;
    let bytes = ramflux_protocol::decode_base64url(&body.data_base64)
        .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let row = store.chunk(&body.prepare_id, body.generation, body.offset, &bytes, unix_now()?)?;
    Ok(local_bus_ok(progress(&row)))
}

fn finish(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: FinishBody = serde_json::from_value(request.body.clone())?;
    let store = open_store(&account.client, request_account_id(request)?)?;
    let digest =
        decode_hex(&body.plaintext_digest).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let row = store.finish(
        &body.prepare_id,
        body.generation,
        body.plaintext_length,
        super::metadata::Finished {
            digest,
            metadata: super::metadata::Metadata {
                width: body.width,
                height: body.height,
                duration_ms: body.duration_ms,
                animated: body.animated,
            },
            thumbnail: body.thumbnail.map(super::thumbnail::Input::decode).transpose()?,
        },
        unix_now()?,
    )?;
    Ok(local_bus_ok(progress(&row)))
}

fn status(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: IdBody = serde_json::from_value(request.body.clone())?;
    let store = open_store(&account.client, request_account_id(request)?)?;
    Ok(local_bus_ok(progress(&store.status(&body.prepare_id)?)))
}

async fn cancel(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: GenerationBody = serde_json::from_value(request.body.clone())?;
    let store = open_store(&account.client, request_account_id(request)?)?;
    let before = store.load(&body.prepare_id)?;
    let row = store.cancel(&body.prepare_id, body.generation)?;
    // A cancel after commit retires every grant it registered, off the actor.
    if matches!(before.phase, Phase::Committed | Phase::Granted)
        && let Ok(pin) = authority(&account.client)
    {
        {
            let source = super::retire::Source {
                authority: &pin.source,
                generation: pin.generation,
                public_key: &pin.public_key,
            };
            let now = unix_now()?;
            super::retire::with_ctx(account, |ctx| {
                super::retire::cancel_registered(ctx, None, &body.prepare_id, &source, now)
            })?;
            if let Ok(plane) = plane_for(account) {
                let _ = super::hooks::deliver_pending(account, plane, &pin).await;
            }
        }
    }
    Ok(local_bus_ok(progress(&row)))
}

async fn revoke(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: MessageBody = serde_json::from_value(request.body.clone())?;
    if body.message_id.is_empty() || body.message_id.len() > 256 {
        return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
    }
    let pin = authority(&account.client)?;
    let now = unix_now()?;
    super::retire::with_ctx(account, |ctx| {
        super::retire::revoke_local(ctx, &body.message_id, now)
    })?;
    // Delivery runs on workers; an unreachable relay leaves the retirement queued and the
    // answer `retirement_pending`.
    if let Ok(plane) = plane_for(account) {
        let _ = super::hooks::deliver_pending(account, plane, &pin).await;
    }
    let state = super::retire::with_ctx(account, |ctx| {
        super::retire::revoke_state_of(ctx, &body.message_id)
    })?;
    Ok(local_bus_ok(json!({ "message_id": body.message_id, "state": state })))
}

/// Turns the feature on for this account by pinning one source authority. With `from_node`
/// the pin is read from the home relay through the gateway; otherwise the caller supplies
/// source, generation and the 64-hex public key. The pin is explicit account state: nothing
/// else ever writes it, and a later pin must equal it.
async fn enable(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: EnableBody = serde_json::from_value(request.body.clone())?;
    let row = if body.from_node {
        let reply = node_authority(account).await?;
        let key = ramflux_protocol::decode_base64url(&reply.signing_public_key)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)))?;
        json!({
            "enabled": true,
            "source": reply.source,
            "authority_generation": reply.generation,
            "authority_public_key": super::owner_wire::encode_hex(&key),
            "home_node_id": reply.home_node_id,
        })
    } else {
        let key = decode_hex(body.public_key_hex.as_deref().unwrap_or_default())
            .map_err(|_| Refusal::new(CODE_AUTHORITY_UNAVAILABLE))?;
        json!({
            "enabled": true,
            "source": body.source.unwrap_or_default(),
            "authority_generation": body.generation.unwrap_or(0),
            "authority_public_key": super::owner_wire::encode_hex(&key),
            "home_node_id": body.home_node_id.unwrap_or_default(),
        })
    };
    let db = account.client.account_db()?;
    if let Some(existing) = db.client_record(CONFIG_DIRECTORY, CONFIG_ID)?
        && enabled_value(Some(&existing))
        && existing != row
    {
        return Err(Refusal::new(CODE_DUPLICATE).into());
    }
    db.persist_client_record(CONFIG_DIRECTORY, CONFIG_ID, &row)?;
    Ok(local_bus_ok(json!({
        "enabled": true,
        "source": row["source"],
        "authority_generation": row["authority_generation"],
    })))
}

async fn node_authority(
    account: &mut crate::bus::state::LocalBusAccountState,
) -> Result<ramflux_protocol::attachment_wire::AttachmentAuthorityReply, SdkError> {
    let bytes = if let Some(plane) = account.client.attachment_plane.clone() {
        tokio::task::spawn_blocking(move || plane.authority())
            .await
            .map_err(|_| SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)))??
    } else {
        crate::bus::attachment_plane::authority(account).await?
    };
    serde_json::from_slice(&bytes)
        .map_err(|_| SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)))
}

fn renew(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: GenerationBody = serde_json::from_value(request.body.clone())?;
    let store = open_store(&account.client, request_account_id(request)?)?;
    Ok(local_bus_ok(progress(&store.renew(&body.prepare_id, body.generation, unix_now()?)?)))
}

/// The unlocked account's own data directory: the folder that holds its database.
/// # Errors
/// Returns `AccountDbNotUnlocked` when no database is open.
pub(crate) fn account_dir(client: &crate::RamfluxClient) -> Result<std::path::PathBuf, SdkError> {
    client
        .account_db()?
        .path
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or(SdkError::AccountDbNotUnlocked)
}

pub(crate) fn open_store(
    client: &crate::RamfluxClient,
    account_id: &str,
) -> Result<Store, SdkError> {
    let root = account_dir(client)?;
    let secret = client.vault_secret_source()?.vault_secret(account_id)?;
    let store = Store::open(&root, account_id, secret)?;
    store.recover_once(unix_now()?)?;
    Ok(store)
}

pub(crate) fn flag(client: &crate::RamfluxClient) -> Result<bool, SdkError> {
    let row = client.account_db()?.client_record(CONFIG_DIRECTORY, CONFIG_ID)?;
    Ok(enabled_value(row.as_ref()))
}

/// Source pin stored on the account. Absent fields are `authority_unavailable`.
pub(crate) struct AuthorityPin {
    pub source: String,
    pub generation: u64,
    pub public_key: [u8; 32],
    pub home: String,
}

/// # Errors
/// Returns `authority_unavailable` when the feature record has no source pin.
pub(crate) fn authority(client: &crate::RamfluxClient) -> Result<AuthorityPin, SdkError> {
    let row = client
        .account_db()?
        .client_record(CONFIG_DIRECTORY, CONFIG_ID)?
        .ok_or_else(|| SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)))?;
    if !enabled_value(Some(&row)) {
        return Err(Refusal::new(CODE_DISABLED).into());
    }
    let source = text(&row, "source")?;
    let generation = row
        .get("authority_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)))?;
    let public_key = decode_hex(&text(&row, "authority_public_key")?)
        .map_err(|_| Refusal::new(CODE_AUTHORITY_UNAVAILABLE))?;
    let home = match row.get("home_node_id").and_then(Value::as_str) {
        Some(home) if !home.is_empty() => home.to_owned(),
        _ => source.clone(),
    };
    Ok(AuthorityPin { source, generation, public_key, home })
}

fn text(row: &Value, field: &str) -> Result<String, SdkError> {
    row.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)))
}

/// The production plane rides the account's live gateway session; a test installs its own.
/// # Errors
/// Returns `authority_unavailable` when no plane and no live connection exist.
pub(crate) fn plane_for(
    account: &crate::bus::state::LocalBusAccountState,
) -> Result<std::sync::Arc<dyn super::plane::Plane>, SdkError> {
    if let Some(plane) = account.client.attachment_plane.clone() {
        return Ok(plane);
    }
    let handle = account.connection.clone().ok_or_else(|| {
        super::because(CODE_AUTHORITY_UNAVAILABLE, "the account has no live gateway connection")
    })?;
    Ok(std::sync::Arc::new(crate::bus::attachment_plane::GatewayPlane::new(
        handle,
        tokio::runtime::Handle::current(),
    )))
}

pub(crate) fn unix_now() -> Result<u64, SdkError> {
    u64::try_from(crate::time::now_unix_timestamp()).map_err(|_| SdkError::LocalBus("clock".into()))
}

fn recipient(body: &BeginBody) -> Result<Recipient, Refusal> {
    match body.kind.as_str() {
        "dm" if !body.peer.is_empty() => Ok(Recipient::Dm { peer: body.peer.clone() }),
        "group" if !body.group_id.is_empty() => {
            Ok(Recipient::Group { group_id: body.group_id.clone() })
        }
        _ => Err(Refusal::new(CODE_LAYOUT_INVALID)),
    }
}

fn progress(row: &Row) -> Value {
    json!({
        "prepare_id": row.prepare_id,
        "generation": row.generation,
        "state": phase_name(&row.phase),
        "accepted_through": row.accepted_through,
        "plaintext_length": row.plaintext_length,
        "expires_at": row.expires_at,
    })
}

fn phase_name(phase: &super::meta::Phase) -> &'static str {
    use super::meta::Phase::{
        Accepted, Accepting, Admitted, Bound, Cleaning, Committed, Fenced, Granted, Reserved,
        Sealing, Uploading,
    };
    match phase {
        Accepting => "accepting",
        Accepted => "accepted",
        Reserved => "reserved",
        Sealing => "sealing",
        Bound => "bound",
        Uploading => "uploading",
        Committed => "committed",
        Granted => "granted",
        Admitted => "admitted",
        Cleaning => "cleaning",
        Fenced => "fenced",
    }
}

#[derive(Deserialize)]
struct EnableBody {
    #[serde(default)]
    from_node: bool,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    generation: Option<u64>,
    #[serde(default)]
    public_key_hex: Option<String>,
    #[serde(default)]
    home_node_id: Option<String>,
}

#[derive(Deserialize)]
struct BeginBody {
    operation_id: String,
    kind: String,
    #[serde(default)]
    peer: String,
    #[serde(default)]
    group_id: String,
    file_name: String,
    mime: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Deserialize)]
struct ChunkBody {
    prepare_id: String,
    generation: u64,
    offset: u64,
    data_base64: String,
}

#[derive(Deserialize)]
struct FinishBody {
    prepare_id: String,
    generation: u64,
    plaintext_length: u64,
    plaintext_digest: String,
    thumbnail: Option<super::thumbnail::Input>,
    width: Option<u32>,
    height: Option<u32>,
    #[serde(default, deserialize_with = "super::metadata::duration::deserialize")]
    duration_ms: Option<u64>,
    animated: Option<bool>,
}

#[derive(Deserialize)]
struct IdBody {
    prepare_id: String,
}

#[derive(Deserialize)]
struct GenerationBody {
    prepare_id: String,
    generation: u64,
}

#[derive(Deserialize)]
struct MessageBody {
    message_id: String,
}

/// `attachment.transfer.list` as a reader: running uploads in this process, merged with the
/// pending sends that the durable rows and the encrypted account-DB ACK journal still hold.
/// Readers run beside the account actor, so the list answers while an upload is in flight.
/// # Errors
/// Returns a local-bus error when the request is malformed or the account store cannot open.
pub(crate) fn transfer_list(
    client: &crate::RamfluxClient,
    request: &LocalBusFrame,
) -> Result<Value, SdkError> {
    let account = request_account_id(request)?;
    let root = account_dir(client)?;
    let secret = client.vault_secret_source()?.vault_secret(account)?;
    let store = Store::open(&root, account, secret)?;
    let db = client.account_db()?;
    let mut durable = Vec::new();
    for mut row in store.pending_rows()? {
        let Some(upload) = row.upload_id else { continue };
        let acks = db
            .load_actor_state::<AckRecord>(&journal_key(&row.prepare_id, upload))
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        row.upload_acks = acks.map_or_else(Vec::new, |record| record.acks);
        durable.push(super::transfer::Snapshot {
            prepare_id: row.prepare_id.clone(),
            paused: false,
            total_bytes: upload::ciphertext_total(&row)?,
            unique_bytes: upload::ack_unique(&row)?,
        });
    }
    let transfers: Vec<Value> = super::transfer::listed(account, durable)
        .into_iter()
        .map(|row| {
            json!({
                "prepare_id": row.prepare_id,
                "paused": row.paused,
                "total_bytes": row.total_bytes,
                "unique_bytes": row.unique_bytes,
            })
        })
        .collect();
    Ok(json!({ "transfers": transfers }))
}

/// Transfer control of this process's running uploads. Served beside the account actor, so it
/// answers while an upload holds that actor; it never waits on the upload itself.
/// # Errors
/// Returns a local-bus error for a missing or oversized `prepare_id`, and `not_ready` when the
/// prepare has no running upload.
pub(crate) fn transfer_body(request: &LocalBusFrame) -> Result<Value, SdkError> {
    let account = request_account_id(request)?;
    match request.method.as_str() {
        "attachment.transfer.pause" | "attachment.transfer.resume" => {
            let prepare = request
                .body
                .get("prepare_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty() && id.len() <= 256)
                .ok_or_else(|| {
                    SdkError::LocalBus("prepare_id must contain 1 to 256 bytes".into())
                })?;
            let paused = request.method == "attachment.transfer.pause";
            super::transfer::set_paused(account, prepare, paused)?;
            Ok(json!({ "prepare_id": prepare, "paused": paused }))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

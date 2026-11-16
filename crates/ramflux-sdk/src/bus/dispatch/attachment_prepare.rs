// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One authored Inner for an ordered prepare list. Card devices are not targets.

use prost::Message as _;
use ramflux_protocol::large_attachment::QualifiedOwner;
use ramflux_protocol::message::outer::{MAX_INNER_BYTES, MAX_UNPADDED_PLAINTEXT_BYTES};
use serde_json::{Value, json};

use crate::attachment_send::{
    AuthorityPin, CODE_AUTHORITY_UNAVAILABLE, CODE_CANCELLED, CODE_DUPLICATE, CODE_LAYOUT_INVALID,
    CODE_MANIFEST_TOO_LARGE, CODE_STREAM_CLOSED, MAX_ATTACHMENTS, MediaDevice, MediaScope, Phase,
    PublishInput, Recipient, Refusal, Row, Store, authority, choose_targets, open_store,
    publish_all, remember_inner, unix_now,
};
use crate::prekey::SdkDeviceManifestEntry;
use crate::prelude::*;

pub(in crate::bus) struct PrepareSend<'a> {
    pub prepares: &'a [String],
    pub caption: &'a str,
    pub message_id: &'a str,
    pub thread: &'a Value,
    pub principal: &'a str,
    pub account_id: &'a str,
    pub conversation_id: &'a str,
}

/// Publishes every prepare and returns the one content body.
/// # Errors
/// Returns a stable refusal before Reserve when the roster or the Inner does not fit,
/// and `authority_unavailable` when the source pin is absent.
pub(in crate::bus) async fn publish_prepares(
    account: &mut LocalBusAccountState,
    request: PrepareSend<'_>,
) -> Result<ramflux_protocol::message::Content, SdkError> {
    let PrepareSend {
        prepares,
        caption,
        message_id,
        thread,
        principal,
        account_id,
        conversation_id,
    } = request;
    if prepares.is_empty() || prepares.len() > MAX_ATTACHMENTS {
        return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
    }
    let pin = authority(&account.client)?;
    let store = open_store(&account.client, account_id)?;
    let rows = load_rows(&store, prepares, thread, principal, conversation_id)?;
    let targets = roster(account, thread, principal, &pin).await?;
    let scope = if thread.get("group_id").is_some() { MediaScope::Group } else { MediaScope::Dm };
    let targets = choose_targets(scope, &targets)?;
    remember_roster(&account.client, message_id, &targets)?;
    let branch = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let anchor = account.client.own_account_anchor()?;
    let owner = QualifiedOwner {
        account_anchor: anchor,
        device_id: branch.device_id.clone(),
        device_epoch: branch.device_epoch,
        signing_public_key: branch.signing_key.verifying_key().to_bytes(),
        home_node_id: pin.home.clone(),
    };
    let key = branch.signing_key.clone();
    let now = unix_now()?;
    let plane = account
        .client
        .attachment_plane
        .as_deref()
        .ok_or_else(|| SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)))?;
    let wrapped = publish_all(
        &PublishInput {
            store: &store,
            plane,
            owner: &owner,
            owner_key: &key,
            targets: &targets,
            audience: &pin.source,
            authority_generation: pin.generation,
            source: &pin.source,
            now,
            caption,
        },
        &rows,
    )?;
    let media: Vec<_> = wrapped.into_iter().map(|item| item.media).collect();
    let inner = ramflux_protocol::message::Message {
        text: caption.to_owned(),
        media: media.clone(),
        ..Default::default()
    }
    .encode_to_vec();
    if inner.len() > MAX_INNER_BYTES
        || inner.len().saturating_add(36) > MAX_UNPADDED_PLAINTEXT_BYTES
    {
        return Err(Refusal::new(CODE_MANIFEST_TOO_LARGE).into());
    }
    remember_inner(&account.client, message_id, &inner, prepares)?;
    for reference in &media {
        account.client.account_db()?.persist_client_record(
            "attachment-object",
            &reference.object_id,
            &serde_json::json!({ "message_id": message_id }),
        )?;
    }
    RamfluxClient::attachment_message_content(caption, &media)
}

/// # Errors
/// Returns a storage error when a granted row cannot be marked admitted.
pub(in crate::bus) fn note_admitted(
    client: &RamfluxClient,
    account_id: &str,
    prepares: &[String],
) -> Result<(), SdkError> {
    let store = open_store(client, account_id)?;
    Ok(store.admit_granted(prepares)?)
}

fn remember_roster(
    client: &RamfluxClient,
    message_id: &str,
    targets: &[MediaDevice],
) -> Result<(), SdkError> {
    let devices: Vec<_> = targets
        .iter()
        .map(|device| json!([device.account_anchor, device.device_id, device.device_epoch]))
        .collect();
    let row = json!({ "devices": devices });
    let db = client.account_db()?;
    if let Some(stored) = db.client_record("attachment-roster", message_id)? {
        if stored.get("devices") != row.get("devices") {
            return Err(Refusal::new(CODE_DUPLICATE).into());
        }
        return Ok(());
    }
    db.persist_client_record("attachment-roster", message_id, &row)?;
    Ok(())
}

fn load_rows(
    store: &Store,
    prepares: &[String],
    thread: &Value,
    principal: &str,
    conversation: &str,
) -> Result<Vec<Row>, SdkError> {
    let group = thread.get("group_id").and_then(Value::as_str);
    let peer = if group.is_none() {
        thread
            .get("participants")
            .and_then(Value::as_array)
            .and_then(|ids| ids.iter().filter_map(Value::as_str).find(|id| *id != principal))
    } else {
        None
    };
    let mut rows = Vec::with_capacity(prepares.len());
    for (index, id) in prepares.iter().enumerate() {
        if prepares[..index].iter().any(|earlier| earlier == id) {
            return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
        }
        let row = store.load(id)?;
        ready(&row)?;
        if !recipient_ok(&row.recipient, group, peer, conversation) {
            return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
        }
        rows.push(row);
    }
    Ok(rows)
}

fn ready(row: &Row) -> Result<(), Refusal> {
    match row.phase {
        Phase::Accepting => Err(Refusal::new(CODE_STREAM_CLOSED)),
        Phase::Fenced | Phase::Cleaning => Err(Refusal::new(CODE_CANCELLED)),
        _ if row.plaintext_length.is_none() || row.plaintext_digest.is_none() => {
            Err(Refusal::new(CODE_STREAM_CLOSED))
        }
        _ => Ok(()),
    }
}

fn recipient_ok(
    recipient: &Recipient,
    group: Option<&str>,
    peer: Option<&str>,
    conversation: &str,
) -> bool {
    match (recipient, group) {
        (Recipient::Group { group_id }, Some(group)) => group_id == group,
        (Recipient::Dm { peer: label }, None) => {
            Some(label.as_str()) == peer || label == conversation
        }
        _ => false,
    }
}

async fn roster(
    account: &mut LocalBusAccountState,
    thread: &Value,
    principal: &str,
    pin: &AuthorityPin,
) -> Result<Vec<MediaDevice>, SdkError> {
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let sender = (local.device_id.clone(), local.device_epoch);
    if let Some(group) = thread.get("group_id").and_then(Value::as_str) {
        return group_roster(account, group).await;
    }
    let (peer, root) = super::conversation_send::peer_root(account, thread, principal)?;
    let peer_home = home_of(&account.client, &peer)?;
    let own_root = account.client.own_account_anchor()?;
    let engine = account.session_client().await?;
    let peers =
        account.client.cache_verified_device_manifest(engine.config(), &root, "attachment_peer");
    let own =
        account.client.cache_verified_device_manifest(engine.config(), &own_root, "attachment_own");
    let (peers, own) = (peers.await, own.await);
    account.apply_session_metadata(engine);
    let mut devices = devices_of(&peers?, &peer_home, false, None)?;
    devices.extend(devices_of(&own?, &pin.home, true, Some(&sender))?);
    Ok(devices)
}

async fn group_roster(
    account: &mut LocalBusAccountState,
    group: &str,
) -> Result<Vec<MediaDevice>, SdkError> {
    let rows = super::super::group_delivery::directory(&account.client, group)?;
    let engine = account.session_client().await?;
    let mut devices = Vec::new();
    let mut failure = None;
    for row in &rows {
        let Some(root) = row.get("member_principal_commitment").and_then(Value::as_str) else {
            failure = Some(SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)));
            break;
        };
        let Some(member_principal) = row.get("principal_id").and_then(Value::as_str) else {
            failure = Some(SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)));
            break;
        };
        let Some(member) = row.get("member_id").and_then(Value::as_str) else {
            failure = Some(SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE)));
            break;
        };
        let home = match home_of(&account.client, member_principal) {
            Ok(home) => home,
            Err(error) => {
                failure = Some(error);
                break;
            }
        };
        match account
            .client
            .cache_verified_device_manifest(engine.config(), root, "attachment_group")
            .await
        {
            Ok(manifest) => match devices_of(&manifest, &home, false, None) {
                Ok(found) => {
                    devices.extend(found.into_iter().filter(|device| device.device_id == member));
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            },
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    account.apply_session_metadata(engine);
    failure.map_or(Ok(devices), Err)
}

fn devices_of(
    manifest: &crate::prekey::SdkDeviceManifestResponse,
    home: &str,
    own: bool,
    skip: Option<&(String, u64)>,
) -> Result<Vec<MediaDevice>, SdkError> {
    let mut devices = Vec::new();
    for entry in &manifest.devices {
        if skip.is_some_and(|(id, epoch)| entry.device_id == *id && entry.device_epoch == *epoch) {
            continue;
        }
        devices.push(one_device(entry, home, own)?);
    }
    Ok(devices)
}

fn one_device(
    entry: &SdkDeviceManifestEntry,
    home: &str,
    own: bool,
) -> Result<MediaDevice, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(&entry.branch_public_key)
        .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let signing_public: [u8; 32] =
        bytes.try_into().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    if home.is_empty() {
        return Err(Refusal::new(CODE_AUTHORITY_UNAVAILABLE).into());
    }
    Ok(MediaDevice {
        account_anchor: entry.principal_commitment.clone(),
        device_id: entry.device_id.clone(),
        device_epoch: entry.device_epoch,
        signing_public,
        home_node_id: home.to_owned(),
        hpke_public: entry.prekey_bundle.device_agreement_x25519_public,
        layer: entry.message_layer.as_ref().map_or(0, |signed| signed.declaration.max_layer),
        own,
    })
}

fn home_of(client: &RamfluxClient, principal: &str) -> Result<String, SdkError> {
    let row = client.account_db()?.client_record("identity", principal)?;
    row.as_ref()
        .and_then(|row| row.get("home_node_id"))
        .and_then(Value::as_str)
        .filter(|home| !home.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new(CODE_AUTHORITY_UNAVAILABLE).into())
}

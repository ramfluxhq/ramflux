// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One authored Inner for an ordered prepare list. Card devices are not targets.
//!
//! The send runs in four steps. Upload (reserve, seal, bind, PUT, commit) needs no roster
//! identity beyond a size bound. Before any key is wrapped the roster is read again from the
//! verified cache, so a recipient that changed while the bytes were uploading is replanned
//! rather than granted. Wrapping registers the grants. A last read just before admission
//! retires the grant of any device that stopped being a target and refuses the message.
//! Blocking relay calls run on a blocking worker, never on the account actor.

use std::collections::BTreeMap;
use std::sync::Arc;

use prost::Message as _;
use ramflux_protocol::large_attachment::QualifiedOwner;
use ramflux_protocol::message::outer::{MAX_INNER_BYTES, MAX_UNPADDED_PLAINTEXT_BYTES};
use serde_json::{Value, json};

use crate::attachment_send::upload::{AckRecord, JournalCall, JournalSink};
use crate::attachment_send::{
    AuthorityPin, CODE_AUTHORITY_UNAVAILABLE, CODE_CANCELLED, CODE_LAYOUT_INVALID,
    CODE_MANIFEST_TOO_LARGE, CODE_SEAL_FAILED, CODE_STREAM_CLOSED, MAX_ATTACHMENTS, Phase, Plane,
    PublishInput, Recipient, Refusal, Row, Store, authority, open_store, unix_now, upload_all,
    wrap_all,
};
use crate::client::attachment_roster::{MediaRoster, RosterScope};
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

/// What the account actor owns and a blocking worker needs, copied out before the await.
struct Job {
    store: Store,
    plane: Arc<dyn Plane>,
    owner: QualifiedOwner,
    key: ed25519_dalek::SigningKey,
    pin: AuthorityPin,
    caption: String,
    journal: JournalSink,
}

impl Job {
    fn input<'a>(&'a self, targets: &'a [crate::attachment_send::MediaDevice]) -> PublishInput<'a> {
        PublishInput {
            journal: &self.journal,
            store: &self.store,
            plane: self.plane.as_ref(),
            owner: &self.owner,
            owner_key: &self.key,
            targets,
            audience: &self.pin.source,
            authority_generation: self.pin.generation,
            source: &self.pin.source,
            now: unix_now().unwrap_or(0),
            caption: &self.caption,
        }
    }
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
    crate::attachment_send::hooks::sweep(account, &pin).await;
    let store = open_store(&account.client, account_id)?;
    let rows = load_rows(&store, prepares, thread, principal, conversation_id)?;
    // A retry of a send that already reached admission replays what it left behind and
    // touches neither the relay nor the roster.
    if let Some(media) = retained(&store, &rows)? {
        return RamfluxClient::attachment_message_content(caption, &media);
    }
    let plane = crate::attachment_send::plane_for(account)?;
    let branch = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let owner = QualifiedOwner {
        account_anchor: account.client.own_account_anchor()?,
        device_id: branch.device_id.clone(),
        device_epoch: branch.device_epoch,
        signing_public_key: branch.signing_key.verifying_key().to_bytes(),
        home_node_id: pin.home.clone(),
    };
    let key = branch.signing_key.clone();
    let (journal, mut calls) = JournalSink::channel();
    let job = Arc::new(Job { store, plane, owner, key, pin, caption: caption.to_owned(), journal });
    let scope = Scope::of(account, thread, principal, &job.pin)?;

    let planned = scope.plan(account, &job.pin).await?;
    remember_roster(&account.client, message_id, &planned)?;
    // The worker blocks on relay I/O; the account task serves its journal calls meanwhile.
    let mut upload = tokio::task::spawn_blocking({
        let job = Arc::clone(&job);
        let targets = planned.targets.clone();
        let rows = rows.clone();
        move || upload_all(&job.input(&targets), &rows)
    });
    let rows = serve_journal(account, &mut calls, &mut upload).await?;

    // The upload may have taken long enough for a device to join, leave or lose its layer.
    let current = scope.plan(account, &job.pin).await?;
    if current.keys() != planned.keys() {
        remember_roster(&account.client, message_id, &current)?;
    }
    let wrapped = blocking({
        let job = Arc::clone(&job);
        let targets = current.targets.clone();
        move || wrap_all(&job.input(&targets), &rows)
    })
    .await?;
    for (item, prepare) in wrapped.iter().zip(prepares) {
        if !item.excluded.is_empty() {
            crate::attachment_send::hooks::retire_excluded(
                account,
                &job.pin,
                job.plane.as_ref(),
                prepare,
                &item.media,
                &item.excluded,
            )?;
        }
    }
    let media: Vec<_> = wrapped.iter().map(|item| item.media.clone()).collect();

    // The last read before admission compares against the entries actually in the Inner.
    let last = scope.plan(account, &job.pin).await?;
    let granted = entry_keys(&media);
    let departed: Vec<_> =
        granted.iter().filter(|key| !last.keys().contains(key)).cloned().collect();
    if !departed.is_empty() {
        retire_departed(account, &job, prepares, &media, &departed)?;
        return Err(Refusal::new(CODE_AUTHORITY_UNAVAILABLE).into());
    }

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
    let db = account.client.account_db()?;
    for (reference, prepare) in media.iter().zip(prepares) {
        db.persist_client_record(
            "attachment-object",
            &reference.object_id,
            &json!({ "message_id": message_id, "prepare_id": prepare }),
        )?;
    }
    RamfluxClient::attachment_message_content(caption, &media)
}

/// Answers journal calls until the upload worker finishes. Calls are served in order on the
/// account task, so each ACK is durable before the worker sends the next slice.
async fn serve_journal<T>(
    account: &LocalBusAccountState,
    calls: &mut tokio::sync::mpsc::Receiver<JournalCall>,
    upload: &mut tokio::task::JoinHandle<Result<T, Refusal>>,
) -> Result<T, SdkError> {
    loop {
        tokio::select! {
            biased;
            Some(call) = calls.recv() => answer(account, call),
            joined = &mut *upload => {
                return match joined {
                    Ok(result) => result.map_err(SdkError::from),
                    Err(_) => Err(Refusal::new(CODE_CANCELLED).into()),
                };
            }
        }
    }
}

/// Every call gets exactly one reply, so the worker never waits on a dropped account task.
fn answer(account: &LocalBusAccountState, call: JournalCall) {
    let db = account.client.account_db().map_err(|_| Refusal::new(CODE_SEAL_FAILED));
    match (call, db) {
        (JournalCall::Load { reply, .. }, Err(refusal)) => {
            let _ = reply.send(Err(refusal));
        }
        (JournalCall::Save { reply, .. }, Err(refusal)) => {
            let _ = reply.send(Err(refusal));
        }
        (JournalCall::Load { key, reply }, Ok(db)) => {
            let loaded = db
                .load_actor_state::<AckRecord>(&key)
                .map(|record| record.map(|record| record.acks))
                .map_err(|_| Refusal::new(CODE_SEAL_FAILED));
            let _ = reply.send(loaded);
        }
        (JournalCall::Save { key, acks, reply }, Ok(db)) => {
            let saved = db
                .persist_actor_state(&key, &AckRecord { acks })
                .map_err(|_| Refusal::new(CODE_SEAL_FAILED));
            let _ = reply.send(saved);
        }
    }
}

/// # Errors
/// Returns a storage error when a granted row cannot be marked admitted.
pub(in crate::bus) fn note_admitted(
    client: &RamfluxClient,
    account_id: &str,
    prepares: &[String],
    message_id: &str,
) -> Result<(), SdkError> {
    let store = open_store(client, account_id)?;
    // Persist the sender's import binding before admission authorizes plaintext removal.
    crate::attachment_send::remember_sent(client, message_id, prepares)?;
    store.admit_granted(prepares, message_id).map_err(SdkError::from)
}

async fn blocking<T, F>(work: F) -> Result<T, SdkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Refusal> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result.map_err(SdkError::from),
        Err(_) => Err(Refusal::new(CODE_CANCELLED).into()),
    }
}

fn retained(
    store: &Store,
    rows: &[Row],
) -> Result<Option<Vec<ramflux_protocol::message::MediaRef>>, SdkError> {
    if !rows.iter().all(|row| row.phase == Phase::Admitted) {
        return Ok(None);
    }
    let mut media = Vec::with_capacity(rows.len());
    for row in rows {
        match crate::attachment_send::stored_media(store, &row.prepare_id)? {
            Some(reference) => media.push(reference),
            None => return Ok(None),
        }
    }
    Ok(Some(media))
}

fn entry_keys(media: &[ramflux_protocol::message::MediaRef]) -> Vec<(String, String, u64)> {
    let mut keys: Vec<_> = media
        .first()
        .map(|reference| {
            reference
                .key_slots
                .iter()
                .filter_map(|slot| slot.recipient.as_ref())
                .map(|device| {
                    (device.account_anchor.clone(), device.device_id.clone(), device.device_epoch)
                })
                .collect()
        })
        .unwrap_or_default();
    keys.sort();
    keys
}

/// Retires the grants of devices that left the roster after the Inner was built. The Inner is
/// not admitted; the caller sends again under a new operation id.
fn retire_departed(
    account: &LocalBusAccountState,
    job: &Job,
    prepares: &[String],
    media: &[ramflux_protocol::message::MediaRef],
    departed: &[(String, String, u64)],
) -> Result<(), SdkError> {
    for (prepare, reference) in prepares.iter().zip(media) {
        let gone: Vec<_> = crate::attachment_send::grants_of(&job.store, prepare)?
            .into_iter()
            .filter(|grant| {
                departed.contains(&(
                    grant.account_anchor.clone(),
                    grant.device_id.clone(),
                    grant.device_epoch,
                ))
            })
            .collect();
        crate::attachment_send::hooks::retire_excluded(
            account,
            &job.pin,
            job.plane.as_ref(),
            prepare,
            reference,
            &gone,
        )?;
    }
    Ok(())
}

fn remember_roster(
    client: &RamfluxClient,
    message_id: &str,
    roster: &MediaRoster,
) -> Result<(), SdkError> {
    let devices: Vec<_> = roster.keys().iter().map(|(a, d, e)| json!([a, d, e])).collect();
    client.account_db()?.persist_client_record(
        "attachment-roster",
        message_id,
        &json!({ "devices": devices, "epoch": roster.epoch }),
    )?;
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

/// Where the roster comes from: the roots to refresh, the homes, and the membership.
struct Scope {
    roots: Vec<String>,
    homes: BTreeMap<String, String>,
    kind: ScopeKind,
}

enum ScopeKind {
    Dm { peer_root: String },
    Group { group_id: String, members: Vec<(String, String)> },
}

impl Scope {
    fn of(
        account: &mut LocalBusAccountState,
        thread: &Value,
        principal: &str,
        pin: &AuthorityPin,
    ) -> Result<Self, SdkError> {
        let own_root = account.client.own_account_anchor()?;
        let mut homes = BTreeMap::from([(own_root.clone(), pin.home.clone())]);
        if let Some(group) = thread.get("group_id").and_then(Value::as_str) {
            let rows = super::super::group_delivery::directory(&account.client, group)?;
            let mut members = Vec::new();
            for row in &rows {
                let root = text(row, "member_principal_commitment")?;
                let member = text(row, "member_id")?;
                // The route row carries the principal only once its device set was observed; the
                // contact commitment record, written when the contact's root was pinned, names it
                // for every root this account holds a contact for.
                let member_principal = match text(row, "principal_id") {
                    Ok(principal) => principal,
                    Err(_) => account
                        .client
                        .account_db()?
                        .client_record("commitment", &root)?
                        .as_ref()
                        .and_then(|record| record.get("principal_id"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            crate::attachment_send::because(
                                CODE_AUTHORITY_UNAVAILABLE,
                                "a group member's principal is not known",
                            )
                        })?,
                };
                // This account's own home is the one its pin names; every other root needs the
                // home pinned when that contact's card was accepted.
                if root != own_root {
                    homes.insert(root.clone(), home_of(&account.client, &member_principal)?);
                }
                members.push((root, member));
            }
            let mut roots: Vec<_> = members.iter().map(|(root, _)| root.clone()).collect();
            roots.sort();
            roots.dedup();
            return Ok(Self {
                roots,
                homes,
                kind: ScopeKind::Group { group_id: group.to_owned(), members },
            });
        }
        let (peer, root) = super::conversation_send::peer_root(account, thread, principal)?;
        homes.insert(root.clone(), home_of(&account.client, &peer)?);
        Ok(Self {
            roots: vec![root.clone(), own_root],
            homes,
            kind: ScopeKind::Dm { peer_root: root },
        })
    }

    /// Refreshes every manifest, then plans from the verified cache. The two reads are one
    /// step so a plan is never made from an older roster than the one just fetched.
    async fn plan(
        &self,
        account: &mut LocalBusAccountState,
        _pin: &AuthorityPin,
    ) -> Result<MediaRoster, SdkError> {
        let engine = account.session_client().await?;
        let mut failure = None;
        for root in &self.roots {
            if let Err(error) = account
                .client
                .cache_verified_device_manifest(engine.config(), root, "attachment_roster")
                .await
            {
                failure = Some(error);
                break;
            }
        }
        account.apply_session_metadata(engine);
        if let Some(error) = failure {
            return Err(error);
        }
        match &self.kind {
            ScopeKind::Dm { peer_root } => {
                account.client.plan_media_roster(&RosterScope::Dm { peer_root }, &self.homes, 0)
            }
            ScopeKind::Group { group_id, members } => {
                let epoch = account
                    .client
                    .account_db()?
                    .shared_group_state(group_id)?
                    .map_or(0, |state| state.view().epoch);
                account.client.plan_media_roster(
                    &RosterScope::Group { members },
                    &self.homes,
                    epoch,
                )
            }
        }
    }
}

fn text(row: &Value, field: &str) -> Result<String, SdkError> {
    row.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            crate::attachment_send::because(
                CODE_AUTHORITY_UNAVAILABLE,
                &format!("a group member row has no {field}"),
            )
        })
}

/// The home node pinned for a contact when its card was accepted. Nothing else names it: a
/// contact with no pinned home is `authority_unavailable`, never this node by assumption.
fn home_of(client: &RamfluxClient, principal: &str) -> Result<String, SdkError> {
    let row = client.account_db()?.client_record("identity", principal)?;
    row.as_ref()
        .and_then(|row| row.get("home_node_id"))
        .and_then(Value::as_str)
        .filter(|home| !home.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            crate::attachment_send::because(
                CODE_AUTHORITY_UNAVAILABLE,
                "no home node is pinned for this contact",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Result<(tempfile::TempDir, LocalBusAccountState), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let account = crate::bus::runtime_tests::account(
            root.path(),
            "sender",
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        Ok((root, account))
    }

    #[test]
    fn a_peer_with_no_pinned_home_is_refused_and_a_pinned_home_is_used()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, account) = account()?;
        let db = account.client.account_db()?;
        db.persist_client_record("identity", "peer", &json!({"principal_id": "peer"}))?;
        let refused = home_of(&account.client, "peer").unwrap_err();
        assert!(
            refused.to_string().contains("authority_unavailable"),
            "a contact without a pinned home is a typed refusal, got {refused}"
        );
        assert!(home_of(&account.client, "unknown").is_err(), "an unknown principal has no home");
        account.client.pin_contact_home("peer", "node-a")?;
        assert_eq!(home_of(&account.client, "peer")?, "node-a");
        account.client.pin_contact_home("peer", "node-a")?;
        assert!(
            account.client.pin_contact_home("peer", "node-b").is_err(),
            "a pinned home is never overwritten by another one"
        );
        assert_eq!(home_of(&account.client, "peer")?, "node-a", "the pin is unchanged");
        Ok(())
    }
}

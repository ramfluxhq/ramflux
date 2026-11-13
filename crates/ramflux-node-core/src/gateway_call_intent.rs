// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable call-intent admission. A cancel tombstone is never reopened.

use super::{GatewayRedbStore, NodeCoreError};
use ramflux_protocol::CallResolutionState as State;
use ramflux_protocol::{CallIntentAction, CallIntentV1, SignedCallIntentV1};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

#[path = "gateway_call_authority.rs"]
mod authority;
#[path = "gateway_call_ciphertext.rs"]
mod ciphertext;
#[path = "gateway_call_retention.rs"]
mod retention;

const CALL_INTENT: TableDefinition<&str, &[u8]> = TableDefinition::new("gateway_call_intent_v1");

pub(super) fn ensure_call_intent_table(db: &redb::Database) -> Result<(), NodeCoreError> {
    let tx = db.begin_write().map_err(redb_error)?;
    let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
    tx.open_table(retention::DUE).map_err(redb_error)?;
    drop(table);
    tx.commit().map_err(redb_error)?;
    Ok(())
}

/// What an offline wake may do for one envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallGrant {
    /// No admitted intent. A message wake is allowed.
    Message,
    /// A cancel or an expired start. Send nothing.
    Silent,
    /// An open, unexpired start. The digest authorizes `call_wake`.
    Wake {
        /// Digest of the signed start.
        digest: String,
        /// Original call creation time.
        created_at: u64,
        /// Absolute deadline from the signed start.
        expires_at: u64,
    },
}

/// Result of admitting one verified intent beside an accepted envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallIntentEffect {
    /// The start is open. The invite envelope may send a call wake.
    Authorized,
    /// The call is terminal. `wake_id` is set only when a call wake was already committed.
    Cancelled {
        /// Wake id to cancel, when one was already sent.
        wake_id: Option<String>,
    },
}

/// Verified intent plus the authenticated source that admitted it.
pub struct CallIntentAdmission<'a> {
    /// Caller-signed intent.
    pub signed: &'a SignedCallIntentV1,
    /// Digest of the signed start.
    pub start_digest: &'a str,
    /// Envelope id accepted with this submit.
    pub envelope_id: &'a str,
    /// Authenticated source storage key.
    pub source_identity: &'a str,
    /// Authenticated source device epoch.
    pub source_epoch: u64,
    /// Ciphertext of the invite envelope. It is stored, not parsed.
    pub encrypted_invite: &'a [u8],
}

/// Owner lookup. The id alone is not authority.
pub struct WakeOwnerLookup<'a> {
    /// Session device storage key.
    pub owner_device: &'a str,
    /// Session device epoch.
    pub owner_epoch: u64,
    /// Wake id from the provider payload, when the caller has one.
    pub wake_id: Option<&'a str>,
    /// Call reference from the decrypted control, when the caller has one.
    pub call_ref: Option<&'a str>,
    /// Server clock.
    pub now: u64,
}

/// What an authenticated owner may learn about one wake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeResolution {
    /// Original signed start.
    pub signed_start: SignedCallIntentV1,
    /// Invite ciphertext bound before the wake was sent.
    pub encrypted_invite: Vec<u8>,
    /// The call is cancelled, answered, rejected, or ended.
    pub terminal: bool,
    /// Absolute deadline from the signed start.
    pub expires_at: u64,
    /// Media may start while the start is open and unexpired, and stays allowed after answer.
    pub media_allowed: bool,
    /// Wake id, when one was committed.
    pub wake_id: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct IntentRow {
    state: IntentState,
    start_digest: String,
    source_event_id: String,
    target_delivery_id: String,
    target_owner_epoch: u64,
    created_at: u64,
    expires_at: u64,
    wake_id: Option<String>,
    signed_start: Option<SignedCallIntentV1>,
    #[serde(default)]
    source_identity: String,
    #[serde(default)]
    source_epoch: u64,
    #[serde(default)]
    sender_device: String,
    #[serde(default)]
    target_device: String,
    #[serde(default, with = "ciphertext")]
    encrypted_invite: Vec<u8>,
    #[serde(default)]
    call_ref: String,
    #[serde(default)]
    pending_cancel: Option<SignedCallIntentV1>,
    #[serde(default)]
    terminal_at: Option<u64>,
    max_request_expires_at: u64,
    collect_after: Option<u64>,
    #[serde(default)]
    silenced_envelopes: std::collections::BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum IntentState {
    Open,
    Cancelled,
    Answered,
    Rejected,
    Ended,
    Expired,
}

impl GatewayRedbStore {
    /// Resolve an exact stored Start or closed cancel-before-start for one participant.
    ///
    /// # Errors
    /// Refuses missing or mismatched call authority; never manufactures positive state.
    pub fn resolve_call_context(
        &self,
        context: &ramflux_protocol::CallSubmitContext,
        participant: &str,
        epoch: u64,
        now: u64,
    ) -> Result<ramflux_protocol::CallResolution, NodeCoreError> {
        context.validate().map_err(|_| rejected())?;
        if let Some(client) = self.call_authority.get() {
            let scope = crate::send_authority::AuthorityScope::Call {
                start_digest: context.start_digest.clone(),
            };
            if !client.scope_ready(&scope) {
                return Err(rejected());
            }
        } else {
            return Err(rejected());
        }

        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let row = load_row(&table, &digest_key(&context.start_digest))?.ok_or_else(rejected)?;
        if row.call_ref != context.call_ref || !owner_matches(&row, participant, epoch) {
            return Err(rejected());
        }
        let state = match row.state {
            IntentState::Open if row.signed_start.is_some() && now < row.expires_at => {
                State::Ringing
            }
            IntentState::Answered if row.signed_start.is_some() => State::Answered,
            IntentState::Rejected => State::Rejected,
            IntentState::Ended => State::Ended,
            IntentState::Open
            | IntentState::Answered
            | IntentState::Cancelled
            | IntentState::Expired => State::Cancelled,
        };
        Ok(ramflux_protocol::CallResolution {
            context: context.clone(),
            state,
            media_allowed: matches!(state, State::Ringing | State::Answered),
            wake_resolved: state != State::Ringing,
        })
    }

    /// Persist one verified intent. Cancel before start stays cancelled.
    ///
    /// # Errors
    /// Returns an error when the row conflicts or the commit fails.
    pub fn admit_verified_call_intent(
        &self,
        admission: &CallIntentAdmission<'_>,
    ) -> Result<CallIntentEffect, NodeCoreError> {
        self.admit_verified_call_intent_with_expiry(admission, 0)
    }

    /// # Errors
    /// Persists the authenticated submit's actual signed-request expiry before terminal retention.
    pub fn admit_verified_call_intent_with_expiry(
        &self,
        admission: &CallIntentAdmission<'_>,
        request_expires_at: u64,
    ) -> Result<CallIntentEffect, NodeCoreError> {
        self.recover_call_scope(admission.start_digest)?;
        self.prune_call_authority(crate::now_unix_seconds())?;
        if admission.encrypted_invite.len() > 32768 {
            return Err(NodeCoreError::PayloadTooLarge);
        }
        let body = &admission.signed.body;
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let mut row = load_row(&table, &digest_key(admission.start_digest))?;
        let previous = row.clone();
        let effect = match body.action {
            CallIntentAction::Start => admit_start(&mut row, admission)?,
            CallIntentAction::Cancel => admit_cancel(&mut row, admission)?,
        };
        let mut stored = row.ok_or_else(rejected)?;
        if stored.collect_after.is_none() {
            stored.max_request_expires_at = stored.max_request_expires_at.max(request_expires_at);
        }
        let silence = if matches!(effect, CallIntentEffect::Cancelled { .. }) {
            stored.terminal_at.get_or_insert(crate::now_unix_seconds());
            let key = silence_key(admission.envelope_id, &body.target_delivery_id);
            if stored.silenced_envelopes.len() >= 32 && !stored.silenced_envelopes.contains(&key) {
                return Err(crate::send_authority::SendAuthorityError::Capacity.into());
            }
            stored.silenced_envelopes.insert(key.clone());
            Some(key)
        } else {
            None
        };
        drop(table);
        drop(tx);
        retention::fix_horizon(&mut stored)?;
        self.sync_call_row(previous.as_ref(), &stored, silence)?;
        Ok(effect)
    }

    /// Remember the wake id for an open start. A cancel or a missing row does not bind.
    ///
    /// # Errors
    /// Returns `call wake cancelled` when the start is already terminal and
    /// `call intent rejected` when the row is missing.
    pub fn bind_call_wake_id(
        &self,
        source_identity: &str,
        source_epoch: u64,
        source_event_id: &str,
        target_delivery_id: &str,
        wake_id: &str,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let event = event_key(source_identity, source_epoch, source_event_id, target_delivery_id);
        let digest = load_text(&table, &event)?.ok_or_else(rejected)?;
        let mut row = load_row(&table, &digest_key(&digest))?.ok_or_else(rejected)?;
        if row.state != IntentState::Open {
            return Err(NodeCoreError::InvalidConfiguration("call wake cancelled".into()));
        }
        if row.wake_id.as_deref() == Some(wake_id) {
            return Ok(());
        }
        if row.wake_id.is_some() {
            return Err(rejected());
        }
        let previous = row.clone();
        row.wake_id = Some(wake_id.into());
        drop(table);
        drop(tx);
        self.sync_call_row(Some(&previous), &row, None)
    }

    /// Wake authorization for one accepted envelope.
    ///
    /// # Errors
    /// Returns an error when the read fails.
    pub fn call_grant(
        &self,
        source_identity: &str,
        source_epoch: u64,
        envelope_id: &str,
        target_delivery_id: &str,
        now: u64,
    ) -> Result<CallGrant, NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        if load_bytes(&table, &silence_key(envelope_id, target_delivery_id))?.is_some() {
            return Ok(CallGrant::Silent);
        }
        let event = event_key(source_identity, source_epoch, envelope_id, target_delivery_id);
        let Some(digest) = load_text(&table, &event)? else {
            return Ok(CallGrant::Message);
        };
        let Some(row) = load_row(&table, &digest_key(&digest))? else {
            return Ok(CallGrant::Message);
        };
        if row.state != IntentState::Open || now >= row.expires_at {
            return Ok(CallGrant::Silent);
        }
        Ok(CallGrant::Wake {
            digest: row.start_digest,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }

    /// Return the start to an authenticated participant. Anyone else gets `None`.
    ///
    /// # Errors
    /// Returns an error when the read fails.
    pub fn resolve_wake_for_owner(
        &self,
        lookup: &WakeOwnerLookup<'_>,
    ) -> Result<Option<WakeResolution>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let Some(row) = find_row(&table, lookup.wake_id, lookup.call_ref)? else {
            return Ok(None);
        };
        if !owner_matches(&row, lookup.owner_device, lookup.owner_epoch) {
            return Ok(None);
        }
        let Some(signed_start) = row.signed_start.clone() else {
            return Ok(None);
        };
        let terminal = row.state != IntentState::Open;
        let media_allowed = media_allowed_for(row.state, lookup.now, row.expires_at);
        Ok(Some(WakeResolution {
            signed_start,
            encrypted_invite: row.encrypted_invite,
            terminal,
            expires_at: row.expires_at,
            media_allowed,
            wake_id: row.wake_id,
        }))
    }

    /// Answer, reject, or end one call. A repeat is idempotent and does not reopen it.
    ///
    /// # Errors
    /// Returns `call resolution refused` when the caller may not take that action.
    /// Returns `Ok(None)` when the id does not belong to this owner.
    pub fn apply_owner_terminal(
        &self,
        lookup: &WakeOwnerLookup<'_>,
        action: &str,
    ) -> Result<Option<String>, NodeCoreError> {
        self.apply_owner_terminal_with_expiry(lookup, action, 0)
    }

    /// # Errors
    /// The first terminal transition fixes its horizon over all previously admitted requests.
    pub fn apply_owner_terminal_with_expiry(
        &self,
        lookup: &WakeOwnerLookup<'_>,
        action: &str,
        request_expires_at: u64,
    ) -> Result<Option<String>, NodeCoreError> {
        if !matches!(action, "answer" | "reject" | "end") {
            return Err(NodeCoreError::InvalidConfiguration("call resolution refused".to_owned()));
        }
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let Some(mut row) = find_row(&table, lookup.wake_id, lookup.call_ref)? else {
            return Ok(None);
        };
        if !owner_matches(&row, lookup.owner_device, lookup.owner_epoch) {
            return Ok(None);
        }
        let target = lookup.owner_device == row.target_device
            && lookup.owner_epoch == row.target_owner_epoch;
        if matches!(action, "answer" | "reject") && !target {
            return Err(NodeCoreError::InvalidConfiguration("call resolution refused".to_owned()));
        }
        let previous = row.clone();
        if row.collect_after.is_none() {
            row.max_request_expires_at = row.max_request_expires_at.max(request_expires_at);
        }
        row.state = resolution_transition(&row, action, lookup.now)?;
        if matches!(row.state, IntentState::Open | IntentState::Answered) {
            row.terminal_at = None;
        } else {
            row.terminal_at.get_or_insert(lookup.now);
        }
        retention::fix_horizon(&mut row)?;
        let wake_id = row.wake_id.clone();
        drop(table);
        drop(tx);
        self.sync_call_row(Some(&previous), &row, None)?;
        Ok(wake_id)
    }

    /// Read-only preview of an owner action. `Ok(None)` is not this owner.
    ///
    /// # Errors
    /// Returns `call resolution refused` when the action is not allowed.
    /// Returns an error when the read fails.
    pub fn owner_terminal_permitted(
        &self,
        lookup: &WakeOwnerLookup<'_>,
        action: Option<&str>,
    ) -> Result<Option<()>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let Some(row) = find_row(&table, lookup.wake_id, lookup.call_ref)? else {
            return Ok(None);
        };
        if !owner_matches(&row, lookup.owner_device, lookup.owner_epoch) {
            return Ok(None);
        }
        if let Some(action) = action {
            let target = lookup.owner_device == row.target_device
                && lookup.owner_epoch == row.target_owner_epoch;
            if matches!(action, "answer" | "reject") && !target {
                return Err(NodeCoreError::InvalidConfiguration(
                    "call resolution refused".to_owned(),
                ));
            }
            resolution_transition(&row, action, lookup.now)?;
        } else if !media_allowed_for(row.state, lookup.now, row.expires_at) {
            return Err(NodeCoreError::InvalidConfiguration("call resolution refused".to_owned()));
        }
        Ok(Some(()))
    }
}

fn admit_start(
    row: &mut Option<IntentRow>,
    admission: &CallIntentAdmission<'_>,
) -> Result<CallIntentEffect, NodeCoreError> {
    let signed = admission.signed;
    if let Some(existing) = row.as_mut() {
        if existing.state == IntentState::Cancelled {
            if let Some(cancel) = existing.pending_cancel.as_ref()
                && !cancel.body.matches_start(&signed.body, admission.start_digest)
            {
                return Err(rejected());
            }
            existing.signed_start = Some(signed.clone());
            return Ok(CallIntentEffect::Cancelled { wake_id: None });
        }
        if existing.source_event_id != signed.body.source_event_id
            || !same_call(&existing_body(existing), &signed.body)
        {
            return Err(rejected());
        }
        if existing.state != IntentState::Open {
            return Ok(CallIntentEffect::Cancelled { wake_id: existing.wake_id.clone() });
        }
        return Ok(CallIntentEffect::Authorized);
    }
    *row = Some(row_from_signed(admission, IntentState::Open));
    Ok(CallIntentEffect::Authorized)
}

fn admit_cancel(
    row: &mut Option<IntentRow>,
    admission: &CallIntentAdmission<'_>,
) -> Result<CallIntentEffect, NodeCoreError> {
    let signed = admission.signed;
    if let Some(existing) = row.as_mut() {
        if let Some(start) = existing.signed_start.as_ref()
            && !signed.body.matches_start(&start.body, admission.start_digest)
        {
            return Err(rejected());
        }
        if existing.signed_start.is_none()
            && let Some(pending) = existing.pending_cancel.as_ref()
            && !same_call(&pending.body, &signed.body)
        {
            return Err(rejected());
        }
        let wake_id = existing.wake_id.clone();
        existing.state = IntentState::Cancelled;
        existing.pending_cancel = Some(signed.clone());
        return Ok(CallIntentEffect::Cancelled { wake_id });
    }
    let mut created = row_from_signed(admission, IntentState::Cancelled);
    created.pending_cancel = Some(signed.clone());
    created.signed_start = None;
    *row = Some(created);
    Ok(CallIntentEffect::Cancelled { wake_id: None })
}

fn row_from_signed(admission: &CallIntentAdmission<'_>, state: IntentState) -> IntentRow {
    let body = &admission.signed.body;
    IntentRow {
        max_request_expires_at: body.expires_at,
        collect_after: None,
        silenced_envelopes: std::collections::BTreeSet::new(),
        terminal_at: if state == IntentState::Cancelled {
            Some(crate::now_unix_seconds())
        } else {
            None
        },
        state,
        start_digest: admission.start_digest.to_owned(),
        source_event_id: body.source_event_id.clone(),
        target_delivery_id: body.target_delivery_id.clone(),
        target_owner_epoch: body.target_epoch,
        created_at: body.created_at,
        expires_at: body.expires_at,
        wake_id: None,
        signed_start: (state == IntentState::Open).then(|| admission.signed.clone()),
        source_identity: admission.source_identity.to_owned(),
        source_epoch: admission.source_epoch,
        sender_device: body.sender_device.clone(),
        target_device: body.target_device.clone(),
        encrypted_invite: admission.encrypted_invite.to_vec(),
        call_ref: body.call_ref.clone(),
        pending_cancel: None,
    }
}

fn existing_body(row: &IntentRow) -> CallIntentV1 {
    row.signed_start.as_ref().map_or_else(
        || CallIntentV1 {
            version: 1,
            signing_key_id: String::new(),
            signature_alg: ramflux_protocol::WakeSignatureAlg::Ed25519,
            audience: String::new(),
            sender_device: row.sender_device.clone(),
            sender_epoch: row.source_epoch,
            target_device: row.target_device.clone(),
            target_epoch: row.target_owner_epoch,
            target_delivery_id: row.target_delivery_id.clone(),
            call_ref: row.call_ref.clone(),
            source_event_id: row.source_event_id.clone(),
            kind: ramflux_protocol::CallIntentKind::OneToOne,
            action: CallIntentAction::Start,
            seq: 0,
            created_at: row.created_at,
            issued_at: row.created_at,
            expires_at: row.expires_at,
            start_digest: None,
        },
        |signed| signed.body.clone(),
    )
}

fn same_call(left: &CallIntentV1, right: &CallIntentV1) -> bool {
    left.sender_device == right.sender_device
        && left.sender_epoch == right.sender_epoch
        && left.target_device == right.target_device
        && left.target_epoch == right.target_epoch
        && left.target_delivery_id == right.target_delivery_id
        && left.call_ref == right.call_ref
        && left.source_event_id == right.source_event_id
        && left.created_at == right.created_at
        && left.expires_at == right.expires_at
}

fn media_allowed_for(state: IntentState, now: u64, expires_at: u64) -> bool {
    match state {
        IntentState::Open => now < expires_at,
        IntentState::Answered => true,
        IntentState::Rejected
        | IntentState::Ended
        | IntentState::Cancelled
        | IntentState::Expired => false,
    }
}

fn resolution_transition(
    row: &IntentRow,
    action: &str,
    now: u64,
) -> Result<IntentState, NodeCoreError> {
    let unexpired = now < row.expires_at;
    let next = match (row.state, action) {
        (IntentState::Open, "answer") if unexpired => IntentState::Answered,
        (IntentState::Answered, "answer") => IntentState::Answered,
        (IntentState::Open, "reject") if unexpired => IntentState::Rejected,
        (IntentState::Rejected, "reject") => IntentState::Rejected,
        (IntentState::Open, "end") if unexpired => IntentState::Ended,
        (IntentState::Answered | IntentState::Ended, "end") => IntentState::Ended,
        (IntentState::Cancelled, "end" | "reject") => IntentState::Cancelled,
        _ => {
            return Err(NodeCoreError::InvalidConfiguration("call resolution refused".to_owned()));
        }
    };
    Ok(next)
}

fn owner_matches(row: &IntentRow, device: &str, epoch: u64) -> bool {
    (device == row.sender_device && epoch == row.source_epoch)
        || (device == row.target_device && epoch == row.target_owner_epoch)
}

fn find_row(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    wake_id: Option<&str>,
    call_ref: Option<&str>,
) -> Result<Option<IntentRow>, NodeCoreError> {
    let digest = if let Some(wake_id) = wake_id {
        load_text(table, &wake_key(wake_id))?
    } else if let Some(call_ref) = call_ref {
        load_text(table, &call_ref_key(call_ref))?
    } else {
        None
    };
    let Some(digest) = digest else {
        return Ok(None);
    };
    load_row(table, &digest_key(&digest))
}

fn digest_key(digest: &str) -> String {
    format!("d:{digest}")
}

fn event_key(
    source_identity: &str,
    source_epoch: u64,
    source_event_id: &str,
    target_delivery_id: &str,
) -> String {
    format!("e:{source_identity}\n{source_epoch}\n{source_event_id}\n{target_delivery_id}")
}

fn silence_key(envelope_id: &str, target_delivery_id: &str) -> String {
    format!("s:{envelope_id}\n{target_delivery_id}")
}

fn wake_key(wake_id: &str) -> String {
    format!("w:{wake_id}")
}

fn call_ref_key(call_ref: &str) -> String {
    format!("c:{call_ref}")
}

fn save_row(
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
    key: &str,
    row: &IntentRow,
) -> Result<(), NodeCoreError> {
    let bytes = serde_json::to_vec(row)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    table.insert(key, bytes.as_slice()).map_err(redb_error)?;
    Ok(())
}

fn load_row(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<IntentRow>, NodeCoreError> {
    let Some(bytes) = load_bytes(table, key)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn load_text(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<String>, NodeCoreError> {
    let Some(bytes) = load_bytes(table, key)? else {
        return Ok(None);
    };
    String::from_utf8(bytes).map(Some).map_err(|_source| rejected())
}

fn load_bytes(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<Vec<u8>>, NodeCoreError> {
    let Some(value) = table.get(key).map_err(redb_error)? else {
        return Ok(None);
    };
    Ok(Some(value.value().to_vec()))
}

fn rejected() -> NodeCoreError {
    NodeCoreError::InvalidConfiguration("call intent rejected".to_owned())
}

fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

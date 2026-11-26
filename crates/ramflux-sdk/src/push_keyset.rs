// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Central push key set on the device side: the pinned centre, the verified key sets held with
//! their sequence fence per centre, and the sealing of a push route registration to the active key.
//!
//! The pin is explicit provisioning (`RAMFLUX_PUSH_CENTRE_ID`, `RAMFLUX_PUSH_KEYSET_VERIFY_KEYS`,
//! or a `rfc-centre-pin-1` bundle), with no compiled-in default. A registration in central mode is
//! never sent unsealed: when no usable key set exists, the registration is refused locally as
//! `push_keyset_unavailable`.

use crate::gateway::{
    GatewayPushProvider, GatewayPushRouteEnvironment, GatewayPushRouteRefusal,
    GatewayPushRouteRegistration, GatewaySessionConfig,
};
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::push_keyset::verify_keyset;
use ramflux_crypto::push_token::{
    PushTokenPlaintext, PushTokenProvider, SealInput, encode_sealed_token, seal_push_token,
};
use sha2::{Digest, Sha256};

/// Environment variable naming the centre (one identifier shared with the node report).
pub const PUSH_CENTRE_ID_ENV: &str = "RAMFLUX_PUSH_CENTRE_ID";
/// Environment variable with one or two `kid:base64url(32 bytes)` verify keys, comma separated.
pub const PUSH_KEYSET_VERIFY_KEYS_ENV: &str = "RAMFLUX_PUSH_KEYSET_VERIFY_KEYS";
/// Largest serialised key set document.
pub const MAX_KEYSET_DOC_BYTES: usize = 6144;
/// Checkpoint holding the held key set records (one per centre: document, fence and expiry).
pub(crate) const PUSH_KEYSET_CHECKPOINT: &str = "gateway.push.keyset.v1";

/// The pinned centre: its identifier and one or two verify keys by `kid`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PushCentrePin {
    pub(crate) centre_id: String,
    pub(crate) keys: Vec<(String, [u8; 32])>,
}

/// A key set document as the node relays it: `{key_id, body, sig}` with base64url strings.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushKeysetDoc {
    pub key_id: String,
    pub body: String,
    pub sig: String,
}

/// A key set this device holds: the verified document and what the fence and sealing need.
/// Every field except `doc` is derived from `doc` and is re-derived on restore.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct PushKeysetRecord {
    pub(crate) centre_id: String,
    pub(crate) seq: u64,
    pub(crate) body_sha256_hex: String,
    /// Unix milliseconds; past it no new seal is made.
    pub(crate) expires_at: u64,
    pub(crate) active_kid: String,
    /// Unpadded base64url of the active X25519 public key.
    pub(crate) active_pk: String,
    pub(crate) doc: PushKeysetDoc,
}

/// Environment variable naming an unsigned `rfc-centre-pin-1` bundle file. When set, the bundle is
/// the pin source; the two variables above are the fallback.
pub const CENTRE_PIN_FILE_ENV: &str = "RAMFLUX_CENTRE_PIN_FILE";

/// The one owner of an account's central push key set state. Every copy of the account's session
/// config shares it, so the engine that adopts a key set, the sealer and the local read all see the
/// same records. The engine saves the records at the moment it adopts them (the fence is durable
/// from establishment on); a failed save is logged and retried on the next session tick, and it
/// never blocks sealing.
#[derive(Clone, Debug, Default)]
pub(crate) struct PushKeysetStore {
    inner: std::sync::Arc<std::sync::Mutex<PushKeysetState>>,
}

#[derive(Debug, Default)]
struct PushKeysetState {
    /// Push mode the gateway echoed at the last establishment (`direct` or `central`).
    mode: Option<String>,
    /// The held key sets: at most one per `centre_id`, each with its own fence.
    keysets: Vec<PushKeysetRecord>,
    /// The pinned home node identity key (unpadded base64url) that sealed tokens carry as `nk`.
    node_public_key: Option<String>,
    /// Cause of the last refused offer, for diagnostics (A3.3).
    last_refusal: Option<&'static str>,
    /// True while the held records changed and the last save attempt failed.
    save_pending: bool,
    /// Account checkpoint writer; absent when the config has no account behind it.
    writer: Option<ramflux_storage::ProjectionCheckpointWriter>,
}

/// What the sealer and the local read take from the store, copied out under the lock.
#[derive(Clone, Debug, Default)]
pub(crate) struct PushKeysetSnapshot {
    pub(crate) mode: Option<String>,
    pub(crate) held: Option<PushKeysetRecord>,
    pub(crate) node_public_key: Option<String>,
    pub(crate) last_refusal: Option<&'static str>,
    pub(crate) save_pending: bool,
}

impl PushKeysetStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, PushKeysetState> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Binds the store to its account: the checkpoint writer and the restored records.
    pub(crate) fn attach(
        &self,
        writer: ramflux_storage::ProjectionCheckpointWriter,
        keysets: Vec<PushKeysetRecord>,
    ) {
        let mut state = self.lock();
        state.writer = Some(writer);
        state.keysets = keysets;
        state.save_pending = false;
    }

    /// Sets the pinned home node key that sealed tokens carry as `nk`.
    pub(crate) fn set_node_public_key(&self, key: String) {
        self.lock().node_public_key = Some(key);
    }

    /// Records the push mode the gateway echoed.
    fn set_mode(&self, mode: Option<&str>) {
        self.lock().mode = mode.map(str::to_owned);
    }

    /// Whether the last establishment echoed central mode.
    pub(crate) fn is_central(&self) -> bool {
        self.lock().mode.as_deref() == Some("central")
    }

    /// Copies out the state for one centre.
    pub(crate) fn snapshot(&self, centre_id: Option<&str>) -> PushKeysetSnapshot {
        let state = self.lock();
        PushKeysetSnapshot {
            mode: state.mode.clone(),
            held: centre_id.and_then(|centre| held_for(&state.keysets, centre).cloned()),
            node_public_key: state.node_public_key.clone(),
            last_refusal: state.last_refusal,
            save_pending: state.save_pending,
        }
    }

    /// Applies one offered document: adopts it (replacing this centre's record and saving at
    /// once) or refuses it (keeping the held record and recording the cause).
    fn adopt(&self, pin: &PushCentrePin, doc: &PushKeysetDoc, now_ms: u64) {
        let mut state = self.lock();
        let record = match offer(pin, doc, held_for(&state.keysets, &pin.centre_id), now_ms) {
            Ok(record) => record,
            Err(cause) => {
                tracing::warn!(cause, centre_id = %pin.centre_id, "push key set refused");
                state.last_refusal = Some(cause);
                return;
            }
        };
        if held_for(&state.keysets, &pin.centre_id) == Some(&record) {
            return;
        }
        tracing::info!(seq = record.seq, centre_id = %record.centre_id, "push key set adopted");
        state.keysets.retain(|held| held.centre_id != pin.centre_id);
        state.keysets.push(record);
        state.save_pending = true;
        save_locked(&mut state);
    }

    /// Retries a failed save. A no-op when nothing is pending.
    pub(crate) fn retry_save(&self) {
        save_locked(&mut self.lock());
    }
}

/// Saves the held records when a save is pending. A failure is logged with its cause and stays
/// pending for the next retry.
fn save_locked(state: &mut PushKeysetState) {
    if !state.save_pending {
        return;
    }
    let Some(writer) = state.writer.as_ref() else {
        return;
    };
    let result = serde_json::to_string(&state.keysets)
        .map_err(|error| error.to_string())
        .and_then(|encoded| writer.write(&encoded).map_err(|error| error.to_string()));
    match result {
        Ok(()) => state.save_pending = false,
        Err(error) => {
            tracing::warn!(%error, "push key set save failed; retried at the next session tick");
        }
    }
}

/// Reads the pin from the bundle file when named, else from the environment. `None` when the
/// source is missing or malformed (fail closed).
#[must_use]
pub(crate) fn configured_push_centre() -> Option<PushCentrePin> {
    if let Some(path) = std::env::var_os(CENTRE_PIN_FILE_ENV) {
        return pin_from_bundle(&std::fs::read(path).ok()?);
    }
    pin_from_env()
}

/// A key id is `^[a-z0-9-]{1,32}$`.
#[must_use]
pub(crate) fn valid_key_id(kid: &str) -> bool {
    (1..=32).contains(&kid.len())
        && kid
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Builds a pin from parsed entries: one or two keys, each with a valid and unique `kid`.
fn build_pin(centre_id: String, entries: Vec<(String, [u8; 32])>) -> Option<PushCentrePin> {
    if centre_id.is_empty() || entries.is_empty() || entries.len() > 2 {
        return None;
    }
    for (index, (kid, _)) in entries.iter().enumerate() {
        if !valid_key_id(kid) || entries[..index].iter().any(|(other, _)| other == kid) {
            return None;
        }
    }
    Some(PushCentrePin { centre_id, keys: entries })
}

/// Reads `push_keyset_verify` and `centre_id` from a `rfc-centre-pin-1` bundle.
fn pin_from_bundle(bytes: &[u8]) -> Option<PushCentrePin> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("kind")?.as_str()? != "rfc-centre-pin-1" {
        return None;
    }
    let centre_id = value.get("centre_id")?.as_str()?.to_owned();
    let mut entries = Vec::new();
    for entry in value.get("push_keyset_verify")?.as_array()? {
        let kid = entry.get("key_id")?.as_str()?.to_owned();
        let raw = ramflux_protocol::decode_base64url(entry.get("public_key")?.as_str()?).ok()?;
        entries.push((kid, <[u8; 32]>::try_from(raw.as_slice()).ok()?));
    }
    build_pin(centre_id, entries)
}

fn pin_from_env() -> Option<PushCentrePin> {
    let centre_id = std::env::var(PUSH_CENTRE_ID_ENV).ok().filter(|value| !value.is_empty())?;
    let raw = std::env::var(PUSH_KEYSET_VERIFY_KEYS_ENV).ok()?;
    let mut entries = Vec::new();
    for part in raw.split(',') {
        let (kid, encoded) = part.split_once(':')?;
        let bytes = ramflux_protocol::decode_base64url(encoded).ok()?;
        entries.push((kid.to_owned(), <[u8; 32]>::try_from(bytes.as_slice()).ok()?));
    }
    build_pin(centre_id, entries)
}

/// The held record for one centre.
fn held_for<'a>(keysets: &'a [PushKeysetRecord], centre_id: &str) -> Option<&'a PushKeysetRecord> {
    keysets.iter().find(|record| record.centre_id == centre_id)
}

/// Verifies a document against the pin and derives its record. Checks everything except the
/// clock and the fence: size, pinned key id, signature, body rules, centre, and an active key.
///
/// # Errors
/// Returns a short cause name for every refusal.
pub(crate) fn derive_record(
    pin: &PushCentrePin,
    doc: &PushKeysetDoc,
) -> Result<PushKeysetRecord, &'static str> {
    let doc_len = serde_json::to_vec(doc).map_err(|_| "doc_encode")?.len();
    if doc_len > MAX_KEYSET_DOC_BYTES {
        return Err("doc_size");
    }
    let verify_key = pin
        .keys
        .iter()
        .find(|(kid, _)| kid == &doc.key_id)
        .map(|(_, key)| *key)
        .ok_or("unknown_key_id")?;
    let body = ramflux_protocol::decode_base64url(&doc.body).map_err(|_| "body_encoding")?;
    let sig_bytes = ramflux_protocol::decode_base64url(&doc.sig).map_err(|_| "sig_encoding")?;
    let sig = <[u8; 64]>::try_from(sig_bytes.as_slice()).map_err(|_| "sig_length")?;
    let parsed =
        verify_keyset(&body, &sig, &pin.centre_id, &verify_key).map_err(|_| "keyset_rejected")?;
    let active = parsed.active().ok_or("no_active")?;
    Ok(PushKeysetRecord {
        centre_id: pin.centre_id.clone(),
        seq: parsed.seq,
        body_sha256_hex: hex_of(Sha256::digest(&body).as_slice()),
        expires_at: parsed.expires_at,
        active_kid: active.kid.clone(),
        active_pk: ramflux_protocol::encode_base64url(active.pk),
        doc: doc.clone(),
    })
}

/// Verifies an offered document and applies the expiry and the sequence fence for its centre: a
/// higher `seq` is adopted; the same `seq` with the same body keeps the held record; the same `seq`
/// with other bytes, or a lower `seq`, is refused. A missing or zero clock refuses.
///
/// # Errors
/// Returns a short cause name for every refusal, which the caller keeps for diagnostics.
pub(crate) fn offer(
    pin: &PushCentrePin,
    doc: &PushKeysetDoc,
    held: Option<&PushKeysetRecord>,
    now_ms: u64,
) -> Result<PushKeysetRecord, &'static str> {
    if now_ms == 0 {
        return Err("no_clock");
    }
    let record = derive_record(pin, doc)?;
    if record.expires_at <= now_ms {
        return Err("expired");
    }
    let Some(held) = held.filter(|held| held.centre_id == pin.centre_id) else {
        return Ok(record);
    };
    match record.seq.cmp(&held.seq) {
        std::cmp::Ordering::Greater => Ok(record),
        // Same body: the fresh verified record (its document may carry another pinned signature).
        std::cmp::Ordering::Equal if held.body_sha256_hex == record.body_sha256_hex => Ok(record),
        std::cmp::Ordering::Equal => Err("conflict"),
        std::cmp::Ordering::Less => Err("rollback"),
    }
}

/// Registers the key set relayed at establishment (central mode only). A refused document keeps
/// the held record.
pub(crate) fn adopt_establishment(
    config: &GatewaySessionConfig,
    mode: Option<&str>,
    doc: Option<&PushKeysetDoc>,
    now_ms: Option<u64>,
) {
    config.push.set_mode(mode);
    if mode != Some("central") {
        return;
    }
    let (Some(pin), Some(doc), Some(now_ms)) = (configured_push_centre(), doc, now_ms) else {
        return;
    };
    config.push.adopt(&pin, doc, now_ms);
}

/// Adopts a key set the node relays mid-session (`push_keyset` frame) under the same rules.
pub(crate) fn adopt_mid_session(
    config: &GatewaySessionConfig,
    doc: &PushKeysetDoc,
    now_ms: Option<u64>,
) {
    if !config.push.is_central() {
        return;
    }
    let (Some(pin), Some(now_ms)) = (configured_push_centre(), now_ms) else {
        return;
    };
    config.push.adopt(&pin, doc, now_ms);
}

/// Re-verifies the held record and seals a registration to the active key of that verified
/// document. The registration leaves with `sealed: true`, the sealed token as `token`, and no
/// `app` (it is sealed only).
///
/// # Errors
/// Returns [`SdkError::PushRouteRefused`] with `push_keyset_unavailable` when no usable key set,
/// pin, node key or clock exists; `rejected` for a registration that cannot be sealed as given.
pub(crate) fn seal_registration(
    config: &GatewaySessionConfig,
    registration: GatewayPushRouteRegistration,
    app: Option<String>,
    now_ms: Option<u64>,
) -> Result<GatewayPushRouteRegistration, SdkError> {
    let unavailable = || SdkError::PushRouteRefused(GatewayPushRouteRefusal::PushKeysetUnavailable);
    let rejected = || SdkError::PushRouteRefused(GatewayPushRouteRefusal::Rejected);
    let pin = configured_push_centre().ok_or_else(unavailable)?;
    let snapshot = config.push.snapshot(Some(&pin.centre_id));
    let held = snapshot.held.as_ref().ok_or_else(unavailable)?;
    let now_ms = now_ms.ok_or_else(unavailable)?;
    // Every sealing input comes from this verified document, never from the stored fields.
    let verified = offer(&pin, &held.doc, None, now_ms).map_err(|_| unavailable())?;
    let node_key = snapshot.node_public_key.as_deref().ok_or_else(unavailable)?;
    let nk_bytes = ramflux_protocol::decode_base64url(node_key).map_err(|_| unavailable())?;
    <[u8; 32]>::try_from(nk_bytes.as_slice()).map_err(|_| unavailable())?;
    let recipient_bytes =
        ramflux_protocol::decode_base64url(&verified.active_pk).map_err(|_| unavailable())?;
    let recipient = <[u8; 32]>::try_from(recipient_bytes.as_slice()).map_err(|_| unavailable())?;
    let provider = match registration.provider {
        GatewayPushProvider::Apns => PushTokenProvider::Apns,
        GatewayPushProvider::ApnsVoip => PushTokenProvider::ApnsVoip,
        GatewayPushProvider::Fcm => PushTokenProvider::Fcm,
        GatewayPushProvider::WebPush => return Err(rejected()),
    };
    let env = match registration.environment {
        GatewayPushRouteEnvironment::Sandbox => "sandbox",
        GatewayPushRouteEnvironment::Production => "production",
    };
    let plaintext = PushTokenPlaintext {
        tv: 1,
        p: provider,
        tok: registration.token.clone(),
        app: app.ok_or_else(rejected)?,
        env,
        nk: node_key.to_owned(),
        rt: registration.route_tag.clone(),
        iat: now_ms,
        cap: None,
    };
    let sealed = seal_push_token(&SealInput {
        centre_id: &verified.centre_id,
        kid: &verified.active_kid,
        recipient_pk: &recipient,
        plaintext: &plaintext,
    })
    .map_err(|_| unavailable())?;
    let mut out = registration;
    out.token = encode_sealed_token(&sealed);
    out.sealed = Some(true);
    Ok(out)
}

/// Current wall clock in Unix milliseconds. `None` when the clock is before the epoch or the
/// value does not fit; callers refuse rather than use a zero time.
#[must_use]
pub(crate) fn unix_millis_now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .filter(|now| *now > 0)
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Restores the held key set records from the account checkpoint (absent or empty is none) and
/// binds the store to the account's checkpoint writer. Each record for the pinned centre is
/// re-derived from its own document, so stored derived fields are not trusted. A record whose
/// document no longer verifies (for example after a verify key change in the pin) is kept as a
/// fence only: its `seq` and body hash still refuse a rollback, and it is never sealed to, since
/// every seal re-verifies the document.
///
/// # Errors
/// Returns [`SdkError::PushKeysetCheckpointMalformed`] when the checkpoint is present and is not a
/// record list (no earlier format is read before v1), or the storage error.
pub(crate) fn restore_keyset(
    client: &RamfluxClient,
    config: &GatewaySessionConfig,
) -> Result<(), SdkError> {
    let writer = client.account_db()?.projection_checkpoint_writer(PUSH_KEYSET_CHECKPOINT);
    let stored: Vec<PushKeysetRecord> =
        match client.projection_checkpoint(PUSH_KEYSET_CHECKPOINT)? {
            Some(value) if !value.is_empty() => serde_json::from_str(&value)
                .map_err(|error| SdkError::PushKeysetCheckpointMalformed(error.to_string()))?,
            _ => Vec::new(),
        };
    let pin = configured_push_centre();
    let keysets = stored
        .into_iter()
        .map(|record| match &pin {
            Some(pin) if pin.centre_id == record.centre_id => {
                derive_record(pin, &record.doc).unwrap_or(record)
            }
            _ => record,
        })
        .collect();
    config.push.attach(writer, keysets);
    Ok(())
}

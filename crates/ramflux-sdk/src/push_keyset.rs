// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Central push key set on the device side: the pinned centre, the verified key set held with its
//! sequence fence, and the sealing of a push route registration to the active key.
//!
//! The pin is explicit provisioning (`RAMFLUX_PUSH_CENTRE_ID`, `RAMFLUX_PUSH_KEYSET_VERIFY_KEYS`),
//! with no compiled-in default. A registration in central mode is never sent unsealed: when no
//! usable key set exists the registration is refused locally as `push_keyset_unavailable`.

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
/// Checkpoint holding the held key set record (document, fence and expiry).
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

/// The key set this device holds: the verified document plus what the fence and sealing need.
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

/// Central push state kept behind one pointer in the session config, so the connection futures
/// stay small: the echoed mode, the held verified key set, and the pinned node key that seals `nk`.
#[derive(Clone, Debug, Default)]
pub(crate) struct PushSessionState {
    /// Push mode the gateway echoed at establishment (`direct` or `central`).
    pub(crate) mode: Option<String>,
    /// The held, verified key set (document and sequence fence).
    pub(crate) keyset: Option<PushKeysetRecord>,
    /// The pinned home node identity key (unpadded base64url) that sealed tokens carry as `nk`.
    pub(crate) node_public_key: Option<String>,
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

/// Reads `push_keyset_verify` and `centre_id` from a `rfc-centre-pin-1` bundle.
fn pin_from_bundle(bytes: &[u8]) -> Option<PushCentrePin> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("kind")?.as_str()? != "rfc-centre-pin-1" {
        return None;
    }
    let centre_id = value.get("centre_id")?.as_str()?.to_owned();
    let entries = value.get("push_keyset_verify")?.as_array()?;
    if entries.is_empty() || entries.len() > 2 {
        return None;
    }
    let mut keys = Vec::new();
    for entry in entries {
        let kid = entry.get("key_id")?.as_str()?.to_owned();
        let raw = ramflux_protocol::decode_base64url(entry.get("public_key")?.as_str()?).ok()?;
        keys.push((kid, <[u8; 32]>::try_from(raw.as_slice()).ok()?));
    }
    if centre_id.is_empty() {
        return None;
    }
    Some(PushCentrePin { centre_id, keys })
}

fn pin_from_env() -> Option<PushCentrePin> {
    let centre_id = std::env::var(PUSH_CENTRE_ID_ENV).ok().filter(|value| !value.is_empty())?;
    let raw = std::env::var(PUSH_KEYSET_VERIFY_KEYS_ENV).ok()?;
    let mut keys = Vec::new();
    for part in raw.split(',') {
        let (kid, encoded) = part.split_once(':')?;
        let bytes = ramflux_protocol::decode_base64url(encoded).ok()?;
        let key = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;
        keys.push((kid.to_owned(), key));
    }
    if keys.is_empty() || keys.len() > 2 {
        return None;
    }
    Some(PushCentrePin { centre_id, keys })
}

/// Verifies an offered document against the pin and the held record, and applies the sequence
/// fence: a higher `seq` is adopted; the same `seq` with the same body keeps the held record;
/// the same `seq` with other bytes, or a lower `seq`, is refused.
///
/// # Errors
/// Returns a short cause name for every refusal, which the caller keeps for diagnostics.
pub(crate) fn offer(
    pin: &PushCentrePin,
    doc: &PushKeysetDoc,
    held: Option<&PushKeysetRecord>,
    now_ms: u64,
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
    if parsed.expires_at <= now_ms {
        return Err("expired");
    }
    let active = parsed.active().ok_or("no_active")?;
    let body_sha256_hex = hex_of(Sha256::digest(&body).as_slice());
    let record = PushKeysetRecord {
        centre_id: pin.centre_id.clone(),
        seq: parsed.seq,
        body_sha256_hex: body_sha256_hex.clone(),
        expires_at: parsed.expires_at,
        active_kid: active.kid.clone(),
        active_pk: ramflux_protocol::encode_base64url(active.pk),
        doc: doc.clone(),
    };
    let Some(held) = held else {
        return Ok(record);
    };
    match parsed.seq.cmp(&held.seq) {
        std::cmp::Ordering::Greater => Ok(record),
        std::cmp::Ordering::Equal if held.body_sha256_hex == body_sha256_hex => Ok(held.clone()),
        std::cmp::Ordering::Equal => Err("conflict"),
        std::cmp::Ordering::Less => Err("rollback"),
    }
}

/// Registers the key set relayed at establishment (central mode only). A refused document keeps
/// the held record.
pub(crate) fn adopt_establishment(
    config: &mut GatewaySessionConfig,
    mode: Option<&str>,
    doc: Option<&PushKeysetDoc>,
    now_ms: u64,
) {
    config.push.mode = mode.map(str::to_owned);
    if mode != Some("central") {
        return;
    }
    let (Some(pin), Some(doc)) = (configured_push_centre(), doc) else {
        return;
    };
    if let Ok(record) = offer(&pin, doc, config.push.keyset.as_ref(), now_ms) {
        config.push.keyset = Some(record);
    }
}

/// Re-verifies the held record and seals a registration to its active key. The registration
/// leaves with `sealed: true`, the sealed token as `token`, and no `app` (it is sealed only).
///
/// # Errors
/// Returns [`SdkError::PushRouteRefused`] with `push_keyset_unavailable` when no usable key set
/// or pin exists, and `rejected` for a registration that cannot be sealed as given.
pub(crate) fn seal_registration(
    config: &GatewaySessionConfig,
    registration: GatewayPushRouteRegistration,
    app: Option<String>,
    now_ms: u64,
) -> Result<GatewayPushRouteRegistration, SdkError> {
    let unavailable = || SdkError::PushRouteRefused(GatewayPushRouteRefusal::PushKeysetUnavailable);
    let rejected = || SdkError::PushRouteRefused(GatewayPushRouteRefusal::Rejected);
    let pin = configured_push_centre().ok_or_else(unavailable)?;
    let record = config.push.keyset.as_ref().ok_or_else(unavailable)?;
    if record.centre_id != pin.centre_id {
        return Err(unavailable());
    }
    offer(&pin, &record.doc, None, now_ms).map_err(|_| unavailable())?;
    let node_key = config.push.node_public_key.as_deref().ok_or_else(unavailable)?;
    let nk_bytes = ramflux_protocol::decode_base64url(node_key).map_err(|_| unavailable())?;
    <[u8; 32]>::try_from(nk_bytes.as_slice()).map_err(|_| unavailable())?;
    let recipient_bytes =
        ramflux_protocol::decode_base64url(&record.active_pk).map_err(|_| unavailable())?;
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
        centre_id: &pin.centre_id,
        kid: &record.active_kid,
        recipient_pk: &recipient,
        plaintext: &plaintext,
    })
    .map_err(|_| unavailable())?;
    let mut out = registration;
    out.token = encode_sealed_token(&sealed);
    out.sealed = Some(true);
    Ok(out)
}

/// Current wall clock in Unix milliseconds (zero before the epoch).
#[must_use]
pub(crate) fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Restores the held key set record from the account checkpoint (absent or empty is none).
///
/// # Errors
/// Returns an error when the checkpoint is present and is not a record.
pub(crate) fn restore_keyset(
    client: &RamfluxClient,
    config: &mut GatewaySessionConfig,
) -> Result<(), SdkError> {
    let Some(value) = client.projection_checkpoint(PUSH_KEYSET_CHECKPOINT)? else {
        return Ok(());
    };
    if value.is_empty() {
        return Ok(());
    }
    config.push.keyset = Some(serde_json::from_str(&value)?);
    Ok(())
}

/// Persists the held key set record so the fence survives expiry and restarts.
///
/// # Errors
/// Returns an error when the checkpoint cannot be written.
pub(crate) fn persist_keyset(
    client: &RamfluxClient,
    config: &GatewaySessionConfig,
) -> Result<(), SdkError> {
    let Some(record) = &config.push.keyset else {
        return Ok(());
    };
    client.set_projection_checkpoint(PUSH_KEYSET_CHECKPOINT, &serde_json::to_string(record)?)?;
    Ok(())
}

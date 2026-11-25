// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline node key helpers for the central beta allowlist (NN-CENTRAL-NODE-ALLOWLIST-01 sections 2 and 8.1).
//! Reads the node signing seed like custody provisioning does and never prints a private key.

use crate::RfError;
use crate::cli::{CentreAction, CentreCommand, CentreEnrolRequest, CentreKey};
use ed25519_dalek::SigningKey;
use ramflux_crypto::node_enrolment::{enrolment_message, node_key_fingerprint};
use ramflux_protocol::encode_base64url;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use super::node_custody::read_seed;

/// Prefix of the one-line enrolment request (section 2.1).
const REQUEST_PREFIX: &str = "rfc-enrol-1.";
/// Version of the enrolment body (`ev`).
const ENROL_VERSION: u64 = 1;
const MAX_JSON_INT: u64 = (1 << 53) - 1;
const MAX_CENTRE_ID_BYTES: usize = 128;
const MAX_NAME_BYTES: usize = 64;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;
const NONCE_BYTES: usize = 16;

fn invalid(message: impl Into<String>) -> RfError {
    RfError::Message(message.into())
}

pub(crate) fn handle(command: &CentreCommand) -> Result<(), RfError> {
    match &command.action {
        CentreAction::Key(options) => key(options),
        CentreAction::EnrolRequest(options) => enrol_request(options),
    }
}

fn key(options: &CentreKey) -> Result<(), RfError> {
    check_key_gen(options.key_gen)?;
    let seed = read_seed(&options.node_signing_seed)?;
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    println!("node public key: {}", encode_base64url(public));
    println!("key_gen: {}", options.key_gen);
    println!("fingerprint: {}", node_key_fingerprint(&public));
    Ok(())
}

fn enrol_request(options: &CentreEnrolRequest) -> Result<(), RfError> {
    validate_centre_id(&options.centre)?;
    validate_name(&options.name)?;
    validate_domain(&options.domain)?;
    let seed = read_seed(&options.node_signing_seed)?;
    let new_key = SigningKey::from_bytes(&seed);
    let new_public = new_key.verifying_key().to_bytes();
    let (key_gen, replaces, old_seed) = if options.rotate {
        let old_path = options
            .old_node_signing_seed
            .as_deref()
            .ok_or_else(|| invalid("--rotate requires --old-node-signing-seed"))?;
        let old_seed = read_seed(old_path)?;
        let old_public = SigningKey::from_bytes(&old_seed).verifying_key().to_bytes();
        if old_public == new_public {
            return Err(invalid("rotation needs two different keys"));
        }
        check_key_gen(options.old_key_gen)?;
        let next = options.old_key_gen.checked_add(1).ok_or_else(|| invalid("key_gen overflow"))?;
        check_key_gen(next)?;
        (next, Some(encode_base64url(old_public)), Some(old_seed))
    } else {
        check_key_gen(options.key_gen)?;
        (options.key_gen, None, None)
    };
    let ts = now_ms()?;
    let nonce = ramflux_crypto::random_32().map_err(|error| invalid(error.to_string()))?;
    let body = serde_json::json!({
        "ev": ENROL_VERSION,
        "centre_id": options.centre,
        "domain": options.domain,
        "node_key": encode_base64url(new_public),
        "key_gen": key_gen,
        "operator_name": options.name,
        "ts": ts,
        "nonce": encode_base64url(nonce.iter().take(NONCE_BYTES).copied().collect::<Vec<u8>>()),
        "replaces": replaces,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let message = enrolment_message(&options.centre, &body_bytes)
        .map_err(|error| invalid(error.to_string()))?;
    let mut request = format!(
        "{REQUEST_PREFIX}{}.{}",
        encode_base64url(&body_bytes),
        ramflux_crypto::sign_canonical_bytes_with_seed(&message, *seed)
    );
    if let Some(old_seed) = old_seed {
        request.push('.');
        request.push_str(&ramflux_crypto::sign_canonical_bytes_with_seed(&message, *old_seed));
    }
    println!("{request}");
    eprintln!("key_gen: {key_gen}");
    eprintln!("fingerprint: {}", node_key_fingerprint(&new_public));
    Ok(())
}

fn check_key_gen(value: u64) -> Result<(), RfError> {
    if value == 0 || value > MAX_JSON_INT {
        return Err(invalid("key_gen must be 1 or more, below 2^53"));
    }
    Ok(())
}

fn now_ms() -> Result<u64, RfError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("invalid clock"))?
        .as_millis();
    u64::try_from(elapsed).map_err(|_| invalid("clock out of range"))
}

fn validate_centre_id(centre: &str) -> Result<(), RfError> {
    if centre.is_empty()
        || centre.len() > MAX_CENTRE_ID_BYTES
        || !centre.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(invalid("--centre must be 1-128 printable ASCII bytes"));
    }
    Ok(())
}

/// Operator name: 1-64 bytes, no controls and no bidi marks (report label rules, section 3.2).
fn validate_name(name: &str) -> Result<(), RfError> {
    let controls = name
        .chars()
        .any(|c| c.is_control() || matches!(u32::from(c), 0x202A..=0x202E | 0x2066..=0x2069));
    if name.is_empty() || name.len() > MAX_NAME_BYTES || controls {
        return Err(invalid("--name must be 1-64 bytes without control or bidi characters"));
    }
    Ok(())
}

/// Node domain (owner decision 2026-11-25, D4): lower-case ASCII DNS host name, IDN as A-label,
/// at most 253 bytes, at least two labels, no port, path, trailing dot or IP literal.
fn validate_domain(domain: &str) -> Result<(), RfError> {
    let refuse = || {
        invalid(
            "--domain must be a lower-case ASCII DNS host name with at least two labels (IDN as A-label; no port, path or IP literal)",
        )
    };
    if domain.is_empty() || domain.len() > MAX_DOMAIN_BYTES {
        return Err(refuse());
    }
    if !domain.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
    }) {
        return Err(refuse());
    }
    if domain.parse::<IpAddr>().is_ok() {
        return Err(refuse());
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(refuse());
    }
    for label in &labels {
        let shape_ok = !label.is_empty()
            && label.len() <= MAX_LABEL_BYTES
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !shape_ok {
            return Err(refuse());
        }
    }
    // A host name's top-level label is never all digits; this refuses dotted IPv4 forms such as 192.0.2.1.
    let top_all_digits = labels.last().is_some_and(|top| top.bytes().all(|b| b.is_ascii_digit()));
    if top_all_digits {
        return Err(refuse());
    }
    Ok(())
}

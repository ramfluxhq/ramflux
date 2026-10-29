// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local provisioning under the same node identity used by signed discovery.

mod output;

use crate::{RfError, cli::NodeCustody};
use ed25519_dalek::SigningKey;
use ramflux_crypto::custody::{
    VerifiedNodeRecord, sign_node_identity_record, verify_node_identity_record,
};
use ramflux_protocol::{
    custody::{
        BindingMode, Envelope, MAX_BRANCH_LEASE_SECONDS, NodeIdentityRecord, ProxyKey,
        ReceiptKeyStatus,
    },
    domain, encode_base64url,
};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const DAY: u64 = 86_400;
const OVERLAP: u64 = 604_800 + 600;

fn invalid(message: impl Into<String>) -> RfError {
    RfError::Message(message.into())
}

pub(crate) fn provision(options: &NodeCustody, renew: bool) -> Result<(), RfError> {
    if options.validity_days == 0 || options.validity_days > MAX_BRANCH_LEASE_SECONDS / DAY {
        return Err(invalid("custody validity must be 1..30 days"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("invalid clock"))?
        .as_secs();
    let seed = output::read_seed(&options.node_signing_seed)?;
    let node_key = SigningKey::from_bytes(&seed);
    let public = encode_base64url(node_key.verifying_key().to_bytes());
    if public != options.expected_public_key {
        return Err(invalid("node signing seed does not match the pinned discovery public key"));
    }
    let destination = output::Destination::open(&options.output_dir)?;
    let previous = destination.current_record()?;
    if previous.is_some() && !options.force_new_proxy {
        return Err(invalid(
            "custody output already exists; use --force-new-proxy for explicit renewal",
        ));
    }
    if renew && previous.is_none() {
        return Err(invalid(
            "custody-renew requires existing custody.env and its signed predecessor",
        ));
    }
    let previous = previous
        .as_ref()
        .map(|record| {
            verify_node_identity_record(record, &options.node_id, &public, now)
                .map_err(|error| invalid(error.to_string()))
        })
        .transpose()?;
    let proxy_seed =
        Zeroizing::new(ramflux_crypto::random_32().map_err(|error| invalid(error.to_string()))?);
    let record = make_record(options, &node_key, &proxy_seed, previous.as_ref(), now)?;
    let verified = verify_node_identity_record(&record, &options.node_id, &public, now)
        .map_err(|error| invalid(error.to_string()))?;
    if let Some(previous) = &previous {
        let bindings: std::collections::BTreeMap<_, _> =
            previous.key_bindings().map(|(id, binding)| (id.to_owned(), binding)).collect();
        previous
            .verify_successor(
                &verified,
                |id| bindings.get(id).cloned(),
                |public| {
                    bindings
                        .iter()
                        .find(|(_, value)| value.public_key == public)
                        .map(|(id, _)| id.clone())
                },
            )
            .map_err(|error| invalid(error.to_string()))?;
    }
    let env_path = destination.publish(&verified, &proxy_seed)?;
    println!("custody env: {}", env_path.display());
    println!("node id: {}", options.node_id);
    println!("node public key: {public}");
    println!("record epoch: {}", record.body.epoch);
    println!("proxy expires at Unix UTC seconds: {}", now + options.validity_days * DAY);
    if previous.is_some() {
        println!(
            "rotation material prepared; deploy through the supported coordinated rotation procedure"
        );
    }
    Ok(())
}

fn make_record(
    options: &NodeCustody,
    node_key: &SigningKey,
    proxy_seed: &[u8; 32],
    previous: Option<&VerifiedNodeRecord>,
    now: u64,
) -> Result<Envelope<NodeIdentityRecord>, RfError> {
    let sign_until =
        now.checked_add(options.validity_days * DAY).ok_or_else(|| invalid("expiry overflow"))?;
    let overlap_until =
        sign_until.checked_add(OVERLAP).ok_or_else(|| invalid("overlap overflow"))?;
    let mut body = previous.map_or_else(
        || NodeIdentityRecord {
            schema: domain::CUSTODY_NODE_RECORD.into(),
            version: 1,
            node_id: options.node_id.clone(),
            node_signing_public_key: options.expected_public_key.clone(),
            client_tls_certificate_sha256: None,
            epoch: 1,
            previous_record_hash: None,
            issued_at: now,
            receipt_keys: vec![],
            revoked_receipt_key_ids: vec![],
            proxy_keys: vec![],
            revoked_proxy_key_ids: vec![],
            channel_binding_modes: vec![BindingMode::HomeRelayReceipt],
        },
        |previous| previous.envelope().body.clone(),
    );
    if let Some(previous) = previous {
        body.epoch = body.epoch.checked_add(1).ok_or_else(|| invalid("record epoch overflow"))?;
        body.previous_record_hash = Some(previous.hash().to_owned());
        body.issued_at = now;
        body.proxy_keys.retain(|key| key.overlap_until >= now);
        for key in &mut body.proxy_keys {
            key.status = ReceiptKeyStatus::Retiring;
            key.overlap_until = key.overlap_until.max(now + OVERLAP);
        }
    }
    body.proxy_keys.push(ProxyKey {
        key_id: encode_base64url(
            ramflux_crypto::random_32().map_err(|error| invalid(error.to_string()))?,
        ),
        public_key: encode_base64url(SigningKey::from_bytes(proxy_seed).verifying_key().to_bytes()),
        not_before: now,
        sign_until,
        overlap_until,
        status: ReceiptKeyStatus::Active,
        proxy_id: "ramflux-gateway".into(),
        audiences: vec![options.node_id.clone()],
    });
    sign_node_identity_record(node_key, body).map_err(|error| invalid(error.to_string()))
}

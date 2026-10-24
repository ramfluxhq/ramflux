// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    DeviceAuthKeyResponse, GATEWAY_DEVICE_PROOF_HASH_DOMAIN, GATEWAY_OPEN_HASH_DOMAIN,
    GATEWAY_SESSION_PROTOCOL_VERSION, GatewayAuthFrame, GatewayOpenFrame, NodeCoreError,
    NodeReplayGuardState,
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[must_use]
pub fn gateway_open_hash(open: &GatewayOpenFrame) -> String {
    ramflux_protocol::canonical_json_bytes(open).map_or_else(
        |_| String::new(),
        |bytes| ramflux_crypto::blake3_256_base64url(GATEWAY_OPEN_HASH_DOMAIN, &bytes),
    )
}

impl DeviceAuthKeyResponse {
    /// Recover identity only from a verified, active root-signed device entry.
    /// The registry supplies its highest accepted record; callers must also verify possession
    /// of the committed branch signing key before using this identity for request admission.
    /// # Errors
    /// Rejects legacy unsigned records, revoked entries, or inconsistent principal, epoch and key.
    pub fn authenticated_device_identity(
        &self,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let reject =
            || NodeCoreError::ItestHttp("device requires current root-signed authority".into());
        let record = self.signed_device_set.as_ref().ok_or_else(reject)?;
        let root = ramflux_crypto::verifying_key_from_base64url(
            self.root_public_key.as_deref().ok_or_else(reject)?,
        )
        .map_err(|_| reject())?;
        let identity = ramflux_crypto::RootQualifiedDeviceRef::from_signed_device_set(
            &root,
            record,
            &self.device_id,
        )
        .map_err(|_| reject())?;
        let entry = record
            .devices
            .iter()
            .find(|entry| entry.device_id == self.device_id)
            .ok_or_else(reject)?;
        let key = ramflux_crypto::verifying_key_from_base64url(&self.branch_public_key)
            .map_err(|_| reject())?;
        let commitment = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::DEVICE_SIGNING_KEY_COMMITMENT,
            &key.to_bytes(),
        );
        if self.revoked
            || record.principal_id != self.principal_id
            || entry.device_epoch != self.device_epoch
            || entry.status != ramflux_protocol::DeviceSetStatus::Active
            || entry.signing_key_commitment != commitment
        {
            return Err(reject());
        }
        Ok(identity)
    }
}

/// # Errors
/// Returns an error when auth does not bind to the open frame or signatures fail.
pub fn validate_gateway_auth(
    open: &GatewayOpenFrame,
    auth: &GatewayAuthFrame,
    now: i64,
    registered: &DeviceAuthKeyResponse,
) -> Result<(), NodeCoreError> {
    if open.protocol_version != GATEWAY_SESSION_PROTOCOL_VERSION {
        return Err(NodeCoreError::ItestHttp("unsupported gateway session protocol".to_owned()));
    }
    if registered.revoked {
        return Err(NodeCoreError::ItestHttp(format!("device revoked: {}", registered.device_id)));
    }
    if registered.device_id != open.device_id {
        return Err(NodeCoreError::ItestHttp(
            "registered device does not match open device".to_owned(),
        ));
    }
    if registered.target_delivery_id != open.target_delivery_id {
        return Err(NodeCoreError::ItestHttp(
            "registered target does not match open target".to_owned(),
        ));
    }
    if auth.device_proof.device_id != open.device_id {
        return Err(NodeCoreError::ItestHttp("device proof does not match open device".to_owned()));
    }
    if auth.device_proof.principal_id != registered.principal_id {
        return Err(NodeCoreError::ItestHttp(
            "device proof principal does not match registered principal".to_owned(),
        ));
    }
    if auth.device_proof.device_epoch != registered.device_epoch {
        return Err(NodeCoreError::ItestHttp(
            "device proof epoch does not match registered epoch".to_owned(),
        ));
    }
    if auth.signed_request.source_device_id != open.device_id {
        return Err(NodeCoreError::ItestHttp(
            "signed request source device does not match open device".to_owned(),
        ));
    }
    if auth.device_proof.nonce != open.stream_nonce
        || auth.signed_request.nonce != open.stream_nonce
    {
        return Err(NodeCoreError::ItestHttp(
            "signed request does not bind stream nonce".to_owned(),
        ));
    }
    if auth.device_proof.expires_at <= now || auth.signed_request.expires_at <= now {
        return Err(NodeCoreError::ItestHttp("gateway auth expired".to_owned()));
    }
    let device_proof_bytes = ramflux_protocol::canonical_json_bytes(&auth.device_proof)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    let expected_device_proof_hash =
        ramflux_crypto::blake3_256_base64url(GATEWAY_DEVICE_PROOF_HASH_DOMAIN, &device_proof_bytes);
    if auth.signed_request.device_proof_hash != expected_device_proof_hash {
        return Err(NodeCoreError::ItestHttp("device proof hash mismatch".to_owned()));
    }
    if auth.signed_request.body_hash != gateway_open_hash(open) {
        return Err(NodeCoreError::ItestHttp("open frame body hash mismatch".to_owned()));
    }
    let signed_request_bytes = ramflux_protocol::signed_bytes(&auth.signed_request)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    ramflux_crypto::verify_canonical_signature(
        &signed_request_bytes,
        &auth.signed_request.signed.signature,
        &registered.branch_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    let device_proof_signed_bytes = ramflux_protocol::signed_bytes(&auth.device_proof)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    ramflux_crypto::verify_canonical_signature(
        &device_proof_signed_bytes,
        &auth.device_proof.signed.signature,
        &registered.branch_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

/// # Errors
/// Returns an error when auth validation fails or the `SignedRequest` replay tuple was already used.
pub fn validate_gateway_auth_with_replay(
    open: &GatewayOpenFrame,
    auth: &GatewayAuthFrame,
    now: i64,
    replay_guard: &mut NodeReplayGuardState,
    registered: &DeviceAuthKeyResponse,
) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
    validate_gateway_auth(open, auth, now, registered)?;
    let source = registered.authenticated_device_identity()?;
    if auth.device_proof.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
        != Some(source.root_commitment())
    {
        return Err(NodeCoreError::ItestHttp("gateway root identity mismatch".into()));
    }
    replay_guard.check_signed_request(&source, &auth.signed_request, now)?;
    Ok(source)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
use std::io::{BufRead, BufReader};

const SDK_HTTP_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct SdkMvp1PublishPrekeyRequest {
    pub(crate) device_id: String,
    pub(crate) bundle: ramflux_crypto::PrekeyBundle,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct SdkMvp1RegisterIdentityRequest {
    pub(crate) root_public_key: String,
    pub(crate) principal_commitment: String,
    pub(crate) branch_public_key: String,
    pub(crate) proof: BranchProofDocument,
    pub(crate) target_delivery_id: String,
    pub(crate) gateway_id: String,
    pub(crate) session_id: String,
    pub(crate) push_alias_hash: Option<String>,
    pub(crate) now: i64,
    pub(crate) registration_pow: Option<serde_json::Value>,
    pub(crate) source_ip_hash: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct SdkMvp1IdentityRegistrationResponse {
    pub(crate) principal_id: String,
    pub(crate) device_id: String,
    pub(crate) device_epoch: u64,
    pub(crate) target_delivery_id: String,
    pub(crate) session_bound: bool,
    pub(crate) registration_trust_tier: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct SdkMvp1PrekeyResponse {
    pub(crate) device_id: String,
    pub(crate) bundle: Option<ramflux_crypto::PrekeyBundle>,
    #[serde(default)]
    pub(crate) target_delivery_id: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub(crate) struct SdkMvp1RevokeDeviceRequest {
    pub(crate) device_id: String,
    pub(crate) principal_commitment: String,
    pub(crate) root_public_key: String,
    pub(crate) revoked_at: i64,
    pub(crate) signature: String,
}

#[derive(serde::Serialize)]
pub(crate) struct SdkMvp1RevokeDeviceSigningBody<'a> {
    pub(crate) device_id: &'a str,
    pub(crate) principal_commitment: &'a str,
    pub(crate) revoked_at: i64,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub(crate) struct SdkMvp1RevokeDeviceResponse {
    pub(crate) device_id: String,
    pub(crate) revoked: bool,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub(crate) struct SdkMvp1DeviceManifestDevice {
    pub(crate) principal_id: String,
    pub(crate) principal_commitment: String,
    pub(crate) device_id: String,
    pub(crate) device_epoch: u64,
    pub(crate) branch_public_key: String,
    pub(crate) target_delivery_id: String,
    pub(crate) branch_proof: BranchProofDocument,
    pub(crate) prekey_bundle: ramflux_crypto::PrekeyBundle,
    pub(crate) branch_authorized_event_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub(crate) struct SdkMvp1DeviceManifestResponse {
    pub(crate) principal_id: String,
    pub(crate) principal_commitment: String,
    pub(crate) root_public_key: String,
    pub(crate) devices: Vec<SdkMvp1DeviceManifestDevice>,
}

pub fn identity_root_public_key_commitment(root_public_key: &str) -> Result<String, SdkError> {
    let root_public_key_bytes = ramflux_protocol::decode_base64url(root_public_key)
        .map_err(|error| SdkError::LocalBus(format!("invalid root public key: {error}")))?;
    Ok(ramflux_crypto::blake3_256_base64url(
        "ramflux.identity.root_public_key.commitment.v1",
        &root_public_key_bytes,
    ))
}

#[must_use]
pub fn identity_root_public_key_commitment_for_seed(
    principal_id: &str,
    root_seed: [u8; 32],
) -> String {
    let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
    ramflux_crypto::blake3_256_base64url(
        "ramflux.identity.root_public_key.commitment.v1",
        &root.signing_key.verifying_key().to_bytes(),
    )
}

pub(crate) fn sdk_publish_prekey_bundle(
    gateway_url: &str,
    device_id: &str,
    bundle: &ramflux_crypto::PrekeyBundle,
) -> Result<SdkMvp1PrekeyResponse, SdkError> {
    sdk_http_post_json(
        gateway_url,
        "/mvp1/prekey/publish",
        &SdkMvp1PublishPrekeyRequest { device_id: device_id.to_owned(), bundle: bundle.clone() },
    )
}

pub(crate) fn sdk_fetch_prekey_bundle(
    gateway_url: &str,
    device_id: &str,
) -> Result<SdkMvp1PrekeyResponse, SdkError> {
    sdk_http_get_json(gateway_url, &format!("/mvp1/prekey/{device_id}"))
}

pub(crate) async fn sdk_gateway_post_json<T, R>(
    config: &GatewaySessionConfig,
    path: &str,
    value: &T,
) -> Result<R, SdkError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_value(value)?;
    sdk_gateway_request_json(
        config,
        ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: path.to_owned(),
            body,
        },
    )
    .await
}

pub(crate) async fn sdk_gateway_get_json<R>(
    config: &GatewaySessionConfig,
    path: &str,
) -> Result<R, SdkError>
where
    R: serde::de::DeserializeOwned,
{
    sdk_gateway_request_json(
        config,
        ramflux_transport::GatewayQuicRequest {
            method: "GET".to_owned(),
            path: path.to_owned(),
            body: serde_json::Value::Null,
        },
    )
    .await
}

async fn sdk_gateway_request_json<R>(
    config: &GatewaySessionConfig,
    request: ramflux_transport::GatewayQuicRequest,
) -> Result<R, SdkError>
where
    R: serde::de::DeserializeOwned,
{
    let response = match config.transport_kind {
        GatewaySessionTransportKind::Auto => {
            match sdk_quic_gateway_request(config, &request, config.quic_fallback_timeout).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        gateway_addr = %config.gateway_addr,
                        tcp_gateway_addr = %config.tcp_gateway_addr.unwrap_or(config.gateway_addr),
                        "gateway QUIC request unavailable; falling back to TCP-TLS"
                    );
                    sdk_tcp_tls_gateway_request(config, &request).await?
                }
            }
        }
        GatewaySessionTransportKind::Quic => {
            sdk_quic_gateway_request(config, &request, config.timeout).await?
        }
        GatewaySessionTransportKind::TcpTls => {
            sdk_tcp_tls_gateway_request(config, &request).await?
        }
    };
    if response.status != 200 {
        return Err(SdkError::GatewaySessionRejected(format!(
            "gateway request {} {} rejected with status {}: {}",
            request.method, request.path, response.status, response.body
        )));
    }
    Ok(serde_json::from_value(response.body)?)
}

async fn sdk_quic_gateway_request(
    config: &GatewaySessionConfig,
    request: &ramflux_transport::GatewayQuicRequest,
    timeout: Duration,
) -> Result<ramflux_transport::GatewayQuicResponse, SdkError> {
    let mut client = ramflux_transport::QuicGatewayClient::connect(
        config.bind_addr,
        config.gateway_addr,
        &config.server_name,
        &config.ca_cert,
        timeout,
    )
    .await?;
    client.set_session_timeout(config.timeout);
    Ok(client.request(request).await?)
}

async fn sdk_tcp_tls_gateway_request(
    config: &GatewaySessionConfig,
    request: &ramflux_transport::GatewayQuicRequest,
) -> Result<ramflux_transport::GatewayQuicResponse, SdkError> {
    let (_client, mut stream) = ramflux_transport::TcpTlsGatewayClient::connect(
        config.bind_addr,
        config.tcp_gateway_addr.unwrap_or(config.gateway_addr),
        &config.server_name,
        &config.ca_cert,
        config.timeout,
    )
    .await?;
    ramflux_transport::write_gateway_session_json(&mut stream, request).await?;
    Ok(ramflux_transport::read_gateway_session_json(&mut stream).await?)
}

pub(crate) fn sdk_http_post_json<T, R>(base_url: &str, path: &str, value: &T) -> Result<R, SdkError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_vec(value)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        sdk_http_host_port(base_url)?,
        body.len()
    );
    sdk_http_json_request(base_url, request.as_bytes(), Some(&body))
}

pub(crate) fn sdk_http_get_json<R>(base_url: &str, path: &str) -> Result<R, SdkError>
where
    R: serde::de::DeserializeOwned,
{
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        sdk_http_host_port(base_url)?
    );
    sdk_http_json_request(base_url, request.as_bytes(), None)
}

pub(crate) fn sdk_http_json_request<R>(
    base_url: &str,
    request_head: &[u8],
    body: Option<&[u8]>,
) -> Result<R, SdkError>
where
    R: serde::de::DeserializeOwned,
{
    let host_port = sdk_http_host_port(base_url)?;
    let mut stream = std::net::TcpStream::connect(&host_port)?;
    stream.set_read_timeout(Some(SDK_HTTP_TIMEOUT))?;
    stream.set_write_timeout(Some(SDK_HTTP_TIMEOUT))?;
    stream.write_all(request_head)?;
    if let Some(body) = body {
        stream.write_all(body)?;
    }
    stream.flush()?;
    let (status_line, body) = read_sdk_http_response(&mut stream)?;
    if !status_line.contains(" 200 ") {
        return Err(SdkError::LocalBus(format!(
            "SDK HTTP request failed: {status_line}: {}",
            String::from_utf8_lossy(&body)
        )));
    }
    Ok(serde_json::from_slice(&body)?)
}

fn read_sdk_http_response(stream: &mut std::net::TcpStream) -> Result<(String, Vec<u8>), SdkError> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    if status_line.is_empty() {
        return Err(SdkError::LocalBus("SDK HTTP response missing status line".to_owned()));
    }
    let status_line = status_line.trim_end().to_owned();
    let mut content_length = None;
    loop {
        let mut header = String::new();
        let bytes = reader.read_line(&mut header)?;
        if bytes == 0 {
            return Err(SdkError::LocalBus(
                "SDK HTTP response ended before header terminator".to_owned(),
            ));
        }
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_length = Some(value.trim().parse::<usize>().map_err(|source| {
                SdkError::LocalBus(format!("bad SDK HTTP response content length: {source}"))
            })?);
        }
    }
    let content_length = content_length
        .ok_or_else(|| SdkError::LocalBus("SDK HTTP response missing Content-Length".to_owned()))?;
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    Ok((status_line, body))
}

pub(crate) fn sdk_http_host_port(base_url: &str) -> Result<String, SdkError> {
    let rest = base_url
        .strip_prefix("http://")
        .ok_or_else(|| SdkError::LocalBus(format!("unsupported prekey URL: {base_url}")))?;
    Ok(rest.split('/').next().unwrap_or(rest).to_owned())
}

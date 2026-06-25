// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) fn local_bus_trace(message: &str, fields: impl AsRef<str>) {
    if std::env::var("RAMFLUX_BUS_TRACE").as_deref() == Ok("1") {
        eprintln!("BUS-TRACE: {message} {}", fields.as_ref());
        let mut stderr = std::io::stderr();
        let _ = std::io::Write::flush(&mut stderr);
    }
}

pub(crate) fn request_account_id(request: &LocalBusFrame) -> Result<&str, SdkError> {
    request
        .account_id
        .as_deref()
        .ok_or_else(|| SdkError::LocalBus(format!("{} requires account_id", request.method)))
}

pub(crate) fn local_bus_response(
    request: &LocalBusFrame,
    body: serde_json::Value,
) -> LocalBusFrame {
    LocalBusFrame {
        bus_protocol: "ramflux.local_bus.v1".to_owned(),
        frame_id: format!("frame_resp_{}", request.request_id),
        kind: LocalBusFrameKind::Response,
        request_id: request.request_id.clone(),
        account_id: request.account_id.clone(),
        sdk_api: request.sdk_api.clone(),
        method: request.method.clone(),
        body,
        trace_id: request.trace_id.clone(),
        ok: Some(true),
        error: None,
    }
}

pub(crate) fn local_bus_error(request: &LocalBusFrame, error: &SdkError) -> LocalBusFrame {
    LocalBusFrame {
        bus_protocol: "ramflux.local_bus.v1".to_owned(),
        frame_id: format!("frame_err_{}", request.request_id),
        kind: LocalBusFrameKind::Error,
        request_id: request.request_id.clone(),
        account_id: request.account_id.clone(),
        sdk_api: request.sdk_api.clone(),
        method: request.method.clone(),
        body: serde_json::Value::Null,
        trace_id: request.trace_id.clone(),
        ok: Some(false),
        error: Some(LocalBusErrorBody {
            code: local_bus_error_code(error).to_owned(),
            message: error.to_string(),
            retry_after_ms: None,
        }),
    }
}

pub(crate) fn local_bus_error_code(error: &SdkError) -> &'static str {
    match error {
        SdkError::CapabilityDenied(_) | SdkError::Sync(SyncError::CapabilityDenied) => {
            "CapabilityDenied"
        }
        SdkError::GrantInvalidated | SdkError::Sync(SyncError::GrantInvalidated) => {
            "GrantInvalidated"
        }
        SdkError::SignatureVerificationFailed(_) => "SignatureVerificationFailed",
        SdkError::RemoteAppApprovalRequired => "RemoteAppApprovalRequired",
        _ => "ValidationFailed",
    }
}

pub(crate) fn local_bus_event(
    request: &LocalBusFrame,
    account_id: &str,
    sdk_api: &str,
    method: &str,
    body: serde_json::Value,
) -> LocalBusFrame {
    LocalBusFrame {
        bus_protocol: "ramflux.local_bus.v1".to_owned(),
        frame_id: format!("frame_evt_{}", request.request_id),
        kind: LocalBusFrameKind::Event,
        request_id: request.request_id.clone(),
        account_id: Some(account_id.to_owned()),
        sdk_api: sdk_api.to_owned(),
        method: method.to_owned(),
        body,
        trace_id: request.trace_id.clone(),
        ok: None,
        error: None,
    }
}

pub(crate) async fn write_local_bus_frame<W>(
    writer: &mut W,
    frame: &LocalBusFrame,
) -> Result<(), SdkError>
where
    W: AsyncWrite + Unpin,
{
    let body = ramflux_protocol::canonical_json_bytes(frame)?;
    let len = u32::try_from(body.len()).map_err(|_error| {
        SdkError::LocalBus(format!("local bus frame too large: {}", body.len()))
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_local_bus_frame<R>(reader: &mut R) -> Result<LocalBusFrame, SdkError>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0_u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > 1024 * 1024 {
        return Err(SdkError::LocalBus(format!("local bus frame too large: {len}")));
    }
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

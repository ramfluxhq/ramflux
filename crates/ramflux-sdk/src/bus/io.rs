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

/// The single local-bus frame ceiling (T25-A1 / OBJ-IPC-01), enforced SYMMETRICALLY on both the
/// write and read paths. The writer rejects an oversized frame BEFORE emitting any bytes, so a
/// too-large request/response never produces a partial frame or a committed-write-then-read-failure
/// (the deterministic oversized-response ambiguous-success); the reader rejects any inbound frame
/// above it. 1 MiB.
pub(crate) const MAX_LOCAL_BUS_FRAME_BYTES: usize = 1024 * 1024;

pub(crate) async fn write_local_bus_frame<W>(
    writer: &mut W,
    frame: &LocalBusFrame,
) -> Result<(), SdkError>
where
    W: AsyncWrite + Unpin,
{
    let body = ramflux_protocol::canonical_json_bytes(frame)?;
    if body.len() > MAX_LOCAL_BUS_FRAME_BYTES {
        // Reject before writing any bytes: no partial frame is emitted and, for a request, no local
        // or relay mutation has happened yet (the frame never reaches dispatch).
        return Err(SdkError::LocalBus(format!(
            "local bus frame too large: {} > {MAX_LOCAL_BUS_FRAME_BYTES}",
            body.len()
        )));
    }
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
    if len > MAX_LOCAL_BUS_FRAME_BYTES {
        return Err(SdkError::LocalBus(format!("local bus frame too large: {len}")));
    }
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_frame(body: serde_json::Value) -> LocalBusFrame {
        LocalBusFrame {
            bus_protocol: "ramflux.local_bus.v1".to_owned(),
            frame_id: "frame_test".to_owned(),
            kind: LocalBusFrameKind::Request,
            request_id: "req_test".to_owned(),
            account_id: Some("acct".to_owned()),
            sdk_api: "test".to_owned(),
            method: "object.put".to_owned(),
            body,
            trace_id: None,
            ok: None,
            error: None,
        }
    }

    // T25-A1: an oversized frame is rejected on the write path BEFORE any byte is emitted.
    #[tokio::test]
    async fn write_rejects_oversized_frame_before_emitting() {
        let blob = "x".repeat(MAX_LOCAL_BUS_FRAME_BYTES + 1);
        let frame = test_frame(serde_json::json!({ "blob": blob }));
        let mut out: Vec<u8> = Vec::new();
        let result = write_local_bus_frame(&mut out, &frame).await;
        assert!(matches!(&result, Err(e) if e.to_string().contains("too large")), "{result:?}");
        assert!(out.is_empty(), "no partial frame may be emitted on reject");
    }

    // A frame comfortably under the cap round-trips through write then read.
    #[tokio::test]
    async fn write_then_read_roundtrips_frame_under_cap() -> Result<(), SdkError> {
        let frame = test_frame(serde_json::json!({ "committed": true }));
        let mut out: Vec<u8> = Vec::new();
        write_local_bus_frame(&mut out, &frame).await?;
        assert!(out.len() < MAX_LOCAL_BUS_FRAME_BYTES);
        let mut reader: &[u8] = &out;
        let read = read_local_bus_frame(&mut reader).await?;
        assert_eq!(read, frame);
        Ok(())
    }

    // The read path rejects a length prefix of cap+1 before reading the body (symmetric cap).
    #[tokio::test]
    async fn read_rejects_len_prefix_above_cap() {
        // cap+1 fits in u32; the fallback still exceeds the cap so the reject path is exercised either way.
        let len = u32::try_from(MAX_LOCAL_BUS_FRAME_BYTES + 1).unwrap_or(u32::MAX);
        let raw = len.to_be_bytes();
        let mut reader: &[u8] = &raw;
        let result = read_local_bus_frame(&mut reader).await;
        assert!(matches!(&result, Err(e) if e.to_string().contains("too large")), "{result:?}");
    }
}

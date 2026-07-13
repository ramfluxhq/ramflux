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

/// T25-A3 (CTRL-102 / OBJ-IPC-01): the maximum whole-object plaintext accepted by the bounded
/// UPLOAD spool. 16 MiB. `object.put.begin/chunk/finish` all fail closed above it — the object
/// never enters the local commit. Public so the `rf` streaming client shares one authority.
pub const MAX_LOCAL_BUS_OBJECT_BYTES: usize = 16 * 1024 * 1024;

/// T25-A3: the maximum RAW plaintext bytes carried by a single `object.put.chunk` frame. 512 KiB.
/// base64 inflates this ~4/3 to ~699 KiB; with the JSON local-bus envelope the whole frame stays
/// far below [`MAX_LOCAL_BUS_FRAME_BYTES`] (proven by `_CHUNK_FRAME_BOUND_PROOF`). The `rf` writer
/// clamps its per-chunk read to this; the daemon rejects any chunk whose decoded payload exceeds it.
pub const MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES: usize = 512 * 1024;

/// T25-A3: the auto-route threshold. A `rf object put` of a file at or below this size keeps the
/// small one-shot `object.put` request path; a LARGER file auto-routes to the bounded spool
/// (begin/chunk/finish) so the user never needs a flag to make a large PUT succeed. Chosen at 512
/// KiB, well under the ~768 KiB one-shot request ceiling, so a one-shot request frame always fits.
pub const MAX_LOCAL_BUS_ONE_SHOT_OBJECT_BYTES: usize = 512 * 1024;

/// Reserved headroom (bytes) for the local-bus JSON envelope (`bus_protocol`, ids, method, offset,
/// …) + base64 padding wrapped around a maximally sized chunk payload. Generous.
const LOCAL_BUS_CHUNK_ENVELOPE_HEADROOM: usize = 64 * 1024;

/// base64 (URL-safe, no pad) encodes `raw` bytes to `4*ceil(raw/3)` characters.
const fn base64_len(raw: usize) -> usize {
    4 * raw.div_ceil(3)
}

/// Compile-time proof that a maximally sized `object.put.chunk` frame cannot reach the 1 MiB cap:
/// `base64(MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES) + envelope headroom < MAX_LOCAL_BUS_FRAME_BYTES`.
const _: () = assert!(
    base64_len(MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES) + LOCAL_BUS_CHUNK_ENVELOPE_HEADROOM
        < MAX_LOCAL_BUS_FRAME_BYTES,
    "a maximally sized object.put.chunk frame must stay below the 1 MiB local-bus frame cap"
);

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

    // T25-A3: a maximally sized object.put.chunk frame (512 KiB raw -> base64 + envelope) MUST
    // serialize to a frame strictly below the 1 MiB cap, so the writer accepts it (no reject) and no
    // chunk ever needs the cap raised. This is the runtime companion to `_CHUNK_FRAME_BOUND_PROOF`.
    #[tokio::test]
    async fn max_object_put_chunk_frame_stays_below_cap() -> Result<(), SdkError> {
        let payload = vec![0xAB_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES];
        let data_base64 = ramflux_protocol::encode_base64url(&payload);
        // The largest plausible chunk envelope: long ids at the verified max offset.
        let body = serde_json::json!({
            "operation_id": "op-".to_owned() + &"z".repeat(64),
            "offset": MAX_LOCAL_BUS_OBJECT_BYTES - MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES,
            "data_base64": data_base64,
        });
        let mut frame = test_frame(body);
        frame.method = "object.put.chunk".to_owned();
        frame.request_id = "req_".to_owned() + &"9".repeat(48);
        frame.account_id = Some("acct_".to_owned() + &"a".repeat(64));
        let mut out: Vec<u8> = Vec::new();
        write_local_bus_frame(&mut out, &frame).await?;
        assert!(
            out.len() < MAX_LOCAL_BUS_FRAME_BYTES,
            "max chunk frame {} must stay below the 1 MiB cap {MAX_LOCAL_BUS_FRAME_BYTES}",
            out.len()
        );
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

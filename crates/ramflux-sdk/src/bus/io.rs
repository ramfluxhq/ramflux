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
        seq: None,
        at: None,
        deadline_ms: None,
        operation_id: None,
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
        body: match error {
            SdkError::LocalBusRefused { body, .. } => (**body).clone(),
            _ => serde_json::Value::Null,
        },
        trace_id: request.trace_id.clone(),
        seq: None,
        at: None,
        deadline_ms: None,
        operation_id: None,
        ok: Some(false),
        error: Some(local_bus_error_body(error)),
    }
}

pub(crate) fn local_bus_error_body(error: &SdkError) -> LocalBusErrorBody {
    if let SdkError::LocalBusRefused { code, message, body } = error {
        return LocalBusErrorBody {
            code: code.clone(),
            message: message.clone(),
            reason_code: body
                .get("reason_code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            details: body.get("details").cloned().map(Box::new),
            retry_after_ms: None,
            cause: None,
        };
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    let mut cause = None;
    while let Some(source) = current {
        if let Some(io) = source.downcast_ref::<std::io::Error>() {
            cause = Some(LocalBusIoCause {
                kind: format!("{:?}", io.kind()),
                raw_os_error: io.raw_os_error(),
            });
        }
        current = source.source();
    }
    LocalBusErrorBody {
        details: match error {
            SdkError::ContactConfirmationRequired(change) => {
                Some(Box::new(serde_json::json!(change)))
            }
            _ => None,
        },
        reason_code: match error {
            SdkError::Storage(StorageError::AccountWriterBusy(_)) => Some("account_busy".into()),
            SdkError::ContactInput(reason) => Some(reason.to_string()),
            SdkError::ContactConfirmationRequired(_) => {
                Some("root_replacement_confirmation_required".into())
            }
            SdkError::ContactHomeNodeUnsupported => Some("invalid_card".into()),
            _ if local_bus_error_code(error) == "transfer_requires_sync" => {
                Some("head_or_removal_floor_mismatch".into())
            }
            _ => None,
        },
        code: local_bus_error_code(error).to_owned(),
        message: if local_bus_error_code(error) == "account_busy" {
            "account in use by another process".into()
        } else {
            error.to_string()
        },
        retry_after_ms: if matches!(
            error,
            SdkError::ContactInput(crate::ContactReason::LookupRateLimited)
        ) {
            Some(60_000)
        } else if local_bus_error_code(error) == "account_busy" {
            Some(1_000)
        } else {
            None
        },
        cause,
    }
}

pub(crate) fn local_bus_error_code(error: &SdkError) -> &'static str {
    if matches!(error,SdkError::LocalBusRefused{code,..} if code == "transfer_requires_sync") {
        return "transfer_requires_sync";
    }
    if let Some(code) = crate::error_policy::security_code(error) {
        return code;
    }
    match error {
        SdkError::NetworkingPending => "NetworkingPending",
        SdkError::CustodyModeDowngrade => "CustodyModeDowngrade",
        SdkError::CustodyCreationDisabled => "CustodyCreationDisabled",
        SdkError::CustodySetupInvalid => "CustodySetupInvalid",
        SdkError::CustodyConfirmationFailed => "CustodyConfirmationFailed",
        SdkError::CustodyVaultUnavailable => "CustodyVaultUnavailable",
        SdkError::CustodyRandomUnavailable => "CustodyRandomUnavailable",
        SdkError::AccountNotOpen(_) => "AccountNotOpen",
        SdkError::TaskRefused { reason, .. } => reason.as_str(),
        SdkError::Storage(StorageError::Protocol(
            ramflux_protocol::ProtocolError::GroupTransferRequiresSync,
        ))
        | SdkError::Protocol(ramflux_protocol::ProtocolError::GroupTransferRequiresSync)
        | SdkError::Crypto(CryptoError::Protocol(
            ramflux_protocol::ProtocolError::GroupTransferRequiresSync,
        )) => "transfer_requires_sync",
        SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(_))
        | SdkError::Storage(StorageError::Protocol(
            ramflux_protocol::ProtocolError::GroupStateLimit(_),
        ))
        | SdkError::Crypto(CryptoError::Protocol(
            ramflux_protocol::ProtocolError::GroupStateLimit(_),
        )) => "GroupStateCapacity",
        SdkError::Storage(error) => storage_error_code(error),
        SdkError::TaskDeliveryTooLarge { .. } => "TaskDeliveryTooLarge",
        SdkError::SurfaceDeliveryTooLarge { .. } => "too_large",
        SdkError::SurfaceRefused { reason, .. } => reason.as_str(),
        SdkError::CapabilityDenied(_) | SdkError::Sync(SyncError::CapabilityDenied) => {
            "CapabilityDenied"
        }
        SdkError::GrantInvalidated | SdkError::Sync(SyncError::GrantInvalidated) => {
            "GrantInvalidated"
        }
        SdkError::Transport(error) => crate::error_policy::transport_code(error),
        SdkError::ContactRequestCapacity(_)
        | SdkError::ContactUnavailable(_)
        | SdkError::ContactInput(crate::ContactReason::LookupRateLimited) => "Unavailable",
        SdkError::CallControlReceiptCapacity { .. } => "CallControlReceiptCapacity",
        SdkError::SignatureVerificationFailed(_) => "SignatureVerificationFailed",
        SdkError::RemoteAppApprovalRequired => "RemoteAppApprovalRequired",
        SdkError::OwnDeviceAuthorizationRefreshFailed(_) => "OwnDeviceAuthorizationRefreshFailed",
        _ => "ValidationFailed",
    }
}

fn storage_error_code(error: &StorageError) -> &'static str {
    use StorageError as E;
    match error {
        E::AccountWriterBusy(_) => "account_busy",
        E::Io(_) | E::Sqlite(_) => "storage_unavailable",
        E::Integrity(_)
        | E::Protocol(_)
        | E::AmbiguousDeviceId(_)
        | E::Core(_)
        | E::Crypto(_)
        | E::AccountKeyMismatch
        | E::EncryptionUnavailable { .. }
        | E::MigrationChecksumMismatch { .. }
        | E::KeyWrappingFailed(_)
        | E::RekeyRollbackFailed(_)
        | E::AccountNotFound(_)
        | E::Serde(_)
        | E::HistoryBundleHashMismatch
        | E::AuthorizationRejected
        | E::GroupMemberLimitExceeded
        | E::InvalidGroupRole(_)
        | E::GroupPermissionDenied
        | E::GroupControlReplay(_)
        | E::GroupControlEpochMismatch { .. }
        | E::GroupControlSigningKeyMissing(_)
        | E::GroupInviteMissing(_)
        | E::GroupInviteInvalidState { .. }
        | E::GroupInviteExpired(_)
        | E::GroupInviteAcceptorMismatch(_)
        | E::SenderKeyNotDistributed
        | E::GroupEpochAccessDenied
        | E::MessageNotFound(_)
        | E::MessageIdConflict(_)
        | E::EventIdConflict(_)
        | E::IdentityLifecycleBlocked(_)
        | E::InvalidRecoveryState { .. } => "ValidationFailed",
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
        seq: None,
        at: None,
        deadline_ms: None,
        operation_id: None,
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
    let body = encode_local_bus_frame(frame)?;
    write_encoded_local_bus_frame(writer, &body).await
}

pub(crate) fn encode_local_bus_frame(frame: &LocalBusFrame) -> Result<Vec<u8>, SdkError> {
    let body = ramflux_protocol::canonical_json_bytes(frame)?;
    checked_frame_len(body.len())?;
    Ok(body)
}

pub(crate) async fn write_encoded_local_bus_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), SdkError> {
    let len = checked_frame_len(body.len())?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

pub(super) fn checked_frame_len(len: usize) -> Result<u32, SdkError> {
    if len > MAX_LOCAL_BUS_FRAME_BYTES {
        // Reject before writing any bytes: no partial frame is emitted and, for a request, no local
        // or relay mutation has happened yet (the frame never reaches dispatch).
        return Err(SdkError::LocalBus(format!(
            "local bus frame too large: {len} > {MAX_LOCAL_BUS_FRAME_BYTES}"
        )));
    }
    u32::try_from(len).map_err(|_| SdkError::LocalBus(format!("local bus frame too large: {len}")))
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
    let mut body = zeroize::Zeroizing::new(vec![0_u8; len]);
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
            seq: None,
            at: None,
            deadline_ms: None,
            operation_id: None,
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

#[cfg(test)]
mod transport_refusal_tests {
    use super::*;
    #[tokio::test]
    async fn r6_a_quic_deadline_is_an_unavailable_bus_response_with_its_diagnostic_intact()
    -> Result<(), SdkError> {
        let request = LocalBusFrame::request(
            "transport",
            Some("account".into()),
            "task",
            "task.propose",
            serde_json::json!({}),
        );
        let error = SdkError::Transport(ramflux_transport::TransportError::Quic(
            "deadline has elapsed; detail=Elapsed(())".into(),
        ));
        let response = local_bus_error(&request, &error);
        let mut wire = Vec::new();
        write_local_bus_frame(&mut wire, &response).await?;
        let mut read = wire.as_slice();
        let response = read_local_bus_frame(&mut read).await?;
        let error = response.error.ok_or_else(|| SdkError::LocalBus("missing refusal".into()))?;
        assert_eq!(error.code, "Unavailable");
        assert!(error.message.contains("deadline has elapsed"));
        Ok(())
    }
}

#[cfg(test)]
mod transport_retry_tests {
    use super::*;
    use ramflux_transport::TransportError as T;
    #[test]
    fn r7_authentication_and_security_failures_are_not_retryable_transport_outages()
    -> Result<(), SdkError> {
        let cases = [
            (T::NotAuthenticated, "Unauthenticated"),
            (T::Protocol(ramflux_protocol::ProtocolError::NotObject), "ValidationFailed"),
            (
                T::Codec(
                    serde_json::from_str::<serde_json::Value>("{")
                        .err()
                        .ok_or_else(|| SdkError::LocalBus("invalid JSON accepted".into()))?,
                ),
                "ValidationFailed",
            ),
            (T::Tls("certificate pin mismatch".into()), "TransportSecurity"),
            (T::Quic("deadline has elapsed".into()), "Unavailable"),
            (T::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)), "Unavailable"),
            (T::NotOpen, "Unavailable"),
            (T::BackpressureRejected { capacity: 1, in_flight: 1 }, "Unavailable"),
            (T::ShutdownDraining, "Unavailable"),
            (T::ShutdownTimeout { in_flight: 1 }, "Unavailable"),
            (T::RetryExhausted { attempts: 3 }, "Unavailable"),
            (T::Http("HTTP 503: busy".into()), "Unavailable"),
            (T::Http("HTTP/2 502 Bad Gateway".into()), "Unavailable"),
            (T::Http("HTTP 403: denied".into()), "ValidationFailed"),
            (T::Http("bad endpoint: response body mentions HTTP 503".into()), "ValidationFailed"),
            (T::InvalidDnsName("bad name".into()), "ValidationFailed"),
            (T::FrameTooLarge { len: 2_000_000 }, "ValidationFailed"),
            (T::BackendMismatch { expected: "quic", actual: "test" }, "ValidationFailed"),
            (T::NonProductionBackend { backend: "test", reason: "test only" }, "ValidationFailed"),
            (T::UnsupportedOperation { operation: "unsupported" }, "ValidationFailed"),
        ];
        for (error, code) in cases {
            let error = SdkError::Transport(error);
            assert_eq!(local_bus_error_code(&error), code, "{error}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod http_client_refusal_tests {
    use super::*;
    #[tokio::test]
    async fn r7_http_client_statuses_and_deadlines_use_the_transport_retry_policy()
    -> Result<(), SdkError> {
        for (status, expected) in [(403, "ValidationFailed"), (503, "Unavailable")] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let mut request = [0; 4096];
                tokio::io::AsyncReadExt::read(&mut stream, &mut request).await?;
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await
            });
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()
                .map_err(ramflux_transport::TransportError::from)?
                .get(format!("http://{addr}/"))
                .send()
                .await
                .map_err(ramflux_transport::TransportError::from)?;
            let error = response
                .error_for_status()
                .err()
                .ok_or_else(|| SdkError::LocalBus("error status accepted".into()))?;
            assert_eq!(local_bus_error_code(&SdkError::Transport(error.into())), expected);
            server.await.map_err(|e| SdkError::LocalBus(e.to_string()))??;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        // A listening endpoint with no accept/response keeps the request pending until its deadline.
        let error = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(50))
            .build()
            .map_err(ramflux_transport::TransportError::from)?
            .get(format!("http://{addr}/"))
            .send()
            .await
            .err()
            .ok_or_else(|| SdkError::LocalBus("deadline did not fire".into()))?;
        assert!(error.is_timeout());
        assert_eq!(local_bus_error_code(&SdkError::Transport(error.into())), "Unavailable");
        drop(listener);
        Ok(())
    }
}

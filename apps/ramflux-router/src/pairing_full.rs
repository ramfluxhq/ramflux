// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Raw full-pairing mesh: actual mTLS peer, pre-body permit claim and fresh native loans.
use crate::router_runtime::RouterHandle;
use ramflux_node_core::{
    MeshPeerIdentity,
    pairing_relay::{
        FULL_MESH_ADMIT_PATH, FULL_MESH_FRAME_BYTES, FullAdmittedReply, FullArm, FullAuthorization,
        FullForwardClaim, FullMeshAdmit, FullNativeRelay, FullSendPermit, PAIRING_CLAIM_PATH,
        PairingRelayError,
    },
};
use ramflux_protocol::{
    custody::pairing::{
        PairingWire,
        full_transfer::{
            PROFILE, U64,
            relay::{ClosedFull, FullClaim, SentFull, SentFullControl},
        },
        native::Failure,
    },
    decode_base64url,
};
use ramflux_transport::{
    MeshHttpRequest, MeshRequestDeadline, MeshTlsServerStream, TransportError,
};
use std::{
    io::Write,
    net::{IpAddr, TcpStream},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) struct ReadContext<'a> {
    pub(crate) router: &'a RouterHandle,
    pub(crate) peer: &'a MeshPeerIdentity,
    pub(crate) socket: TcpStream,
    pub(crate) accepted: Instant,
}
pub(crate) struct Ingress {
    kind: Kind,
    _deadline: MeshRequestDeadline,
}
enum Kind {
    Claim(IpAddr),
    Admit,
    Forward(Option<FullSendPermit>),
}
pub(crate) fn cap(_method: &str, path: &str) -> usize {
    match path {
        FULL_MESH_ADMIT_PATH => 1024,
        "/pairing/v1/full/send" => 524_288,
        "/pairing/v1/full/poll" | "/pairing/v1/full/close" => 8192,
        _ => ramflux_protocol::home_migration::MAX_FRAME_BYTES,
    }
}
fn header<'a>(raw: &'a str, name: &str) -> Result<Option<&'a str>, TransportError> {
    let mut found = None;
    for line in raw.split("\r\n").skip(1).take_while(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or_else(invalid)?;
        if key.eq_ignore_ascii_case(name) {
            if found.is_some() {
                return Err(invalid());
            }
            found = Some(value.trim_matches([' ', '\t']));
        }
    }
    Ok(found)
}
fn b32(value: &str) -> Result<Zeroizing<[u8; 32]>, TransportError> {
    if value.len() != 43 {
        return Err(invalid());
    }
    let bytes = Zeroizing::new(decode_base64url(value).map_err(|_| invalid())?);
    if Zeroizing::new(ramflux_protocol::encode_base64url(bytes.as_slice())).as_str() != value {
        return Err(invalid());
    }
    Ok(Zeroizing::new(bytes.as_slice().try_into().map_err(|_| invalid())?))
}
pub(crate) fn admit(
    ctx: &ReadContext<'_>,
    method: &str,
    path: &str,
    raw: &str,
    bytes: usize,
) -> Result<Option<Ingress>, TransportError> {
    let raw_claim = path == PAIRING_CLAIM_PATH
        && header(raw, "content-type")? == Some("application/octet-stream");
    let full = raw_claim
        || matches!(
            path,
            FULL_MESH_ADMIT_PATH
                | "/pairing/v1/full/send"
                | "/pairing/v1/full/poll"
                | "/pairing/v1/full/close"
        );
    if !full {
        return Ok(None);
    }
    if method != "POST"
        || ctx.peer.service_id != "ramflux-federation"
        || !ramflux_node_core::device_pairing_enabled().map_err(|_| invalid())?
        || header(raw, "content-type")? != Some("application/octet-stream")
        || raw.len() > 4096
        || raw.len().checked_add(bytes).is_none_or(|total| total > FULL_MESH_FRAME_BYTES)
    {
        return Err(invalid());
    }
    let deadline = ramflux_transport::mesh_socket_request_deadline(
        &ctx.socket,
        ctx.accepted + Duration::from_secs(5),
    )?;
    let kind = if raw_claim {
        if bytes > 8192 {
            return Err(invalid());
        }
        Kind::Claim(
            header(raw, "x-ramflux-pairing-source")?
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())?,
        )
    } else if path == FULL_MESH_ADMIT_PATH {
        Kind::Admit
    } else {
        Kind::Forward(Some(claim(ctx, method, path, raw, bytes).map_err(|_| invalid())?))
    };
    Ok(Some(Ingress { kind, _deadline: deadline }))
}
fn claim(
    ctx: &ReadContext<'_>,
    method: &str,
    path: &str,
    raw: &str,
    bytes: usize,
) -> Result<FullSendPermit, PairingRelayError> {
    let arm =
        match header(raw, "x-ramflux-pairing-arm").map_err(|_| PairingRelayError::WrongContext)? {
            Some("send") => FullArm::Send,
            Some("send_control") => FullArm::SendControl,
            Some("poll") => FullArm::Poll,
            Some("poll_control") => FullArm::PollControl,
            Some("close") => FullArm::Close,
            _ => return Err(PairingRelayError::WrongContext),
        };
    if path != arm.mesh_path() || bytes > arm.body_limit() {
        return Err(PairingRelayError::WrongContext);
    }
    FullAuthorization::parse(method, arm.public_path(), true, raw)?;
    let nonce = b32(header(raw, "x-ramflux-pairing-nonce")
        .map_err(|_| PairingRelayError::WrongContext)?
        .ok_or(PairingRelayError::WrongContext)?)
    .map_err(|_| PairingRelayError::WrongContext)?;
    let id = b32(header(raw, "x-ramflux-pairing-permit")
        .map_err(|_| PairingRelayError::WrongContext)?
        .ok_or(PairingRelayError::WrongContext)?)
    .map_err(|_| PairingRelayError::WrongContext)?;
    let authorization = header(raw, "authorization")
        .map_err(|_| PairingRelayError::WrongContext)?
        .ok_or(PairingRelayError::WrongContext)?;
    let store = ctx.router.pairing_relay().ok_or(PairingRelayError::WrongContext)?;
    let node = ctx.router.pairing_node().ok_or(PairingRelayError::WrongContext)?;
    FullNativeRelay::new(node, ctx.router.state(), store).take(&FullForwardClaim {
        id: &id,
        peer: ctx.peer,
        request_nonce: &nonce,
        authorization,
        path,
        arm,
        bytes,
    })
}
pub(crate) enum Reply {
    Bytes(Zeroizing<Vec<u8>>),
    Data(FullAdmittedReply),
}
pub(crate) fn handle(
    ctx: &ReadContext<'_>,
    ingress: &mut Ingress,
    request: &mut MeshHttpRequest,
) -> Reply {
    match run(ctx, &mut ingress.kind, Zeroizing::new(std::mem::take(&mut request.body))) {
        Ok(reply) => reply,
        Err(error) => Reply::Bytes(failure(&error)),
    }
}
fn run(
    ctx: &ReadContext<'_>,
    kind: &mut Kind,
    mut body: Zeroizing<Vec<u8>>,
) -> Result<Reply, PairingRelayError> {
    let store = ctx.router.pairing_relay().ok_or(PairingRelayError::WrongContext)?;
    let node = ctx.router.pairing_node().ok_or(PairingRelayError::WrongContext)?;
    let native = FullNativeRelay::new(node, ctx.router.state(), store);
    match kind {
        Kind::Claim(source) => {
            let claim =
                FullClaim::from_wire_bytes(&body).map_err(|_| PairingRelayError::WrongContext)?;
            native.claim(ctx.peer, *source, &claim).map(Reply::Bytes)
        }
        Kind::Admit => {
            let request = FullMeshAdmit::from_wire_bytes(&body)
                .map_err(|_| PairingRelayError::WrongContext)?;
            native
                .admit(ctx.peer, &request)?
                .encode_secret()
                .map(Reply::Bytes)
                .map_err(|_| PairingRelayError::WrongContext)
        }
        Kind::Forward(permit) => {
            let permit = permit.take().ok_or(PairingRelayError::WrongContext)?;
            native.forward(ctx.peer, permit, std::mem::take(&mut *body)).map(Reply::Data)
        }
    }
}

fn failure(error: &PairingRelayError) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        Failure {
            schema: "ramflux.pairing.Failure.v2".into(),
            version: 2,
            code: error.code().into(),
            retry_after_ms: match error {
                PairingRelayError::Busy { retry_after_ms } => Some(*retry_after_ms),
                _ => None,
            },
        }
        .to_wire_bytes()
        .unwrap_or_else(|_| b"{\"error\":\"request rejected\"}".to_vec()),
    )
}
pub(crate) fn write(stream: &mut MeshTlsServerStream, reply: &Reply) -> Result<(), TransportError> {
    let bytes;
    let (prefix, body, suffix): (&[u8], &[u8], &[u8]) = match reply {
        Reply::Bytes(value) => (b"", value, b""),
        Reply::Data(FullAdmittedReply::Packet(frame)) => (
            b"{\"kind\":\"polled_full\",\"packet\":",
            frame.as_ref().map_or(b"null".as_slice(), |frame| frame.packet_bytes()),
            b",\"profile\":\"primary_transfer_full_v1\"}",
        ),
        Reply::Data(FullAdmittedReply::Control(frame)) => (
            b"{\"control\":",
            frame.as_ref().map_or(b"null".as_slice(), |frame| frame.as_bytes()),
            b",\"kind\":\"polled_full_control\",\"profile\":\"primary_transfer_full_v1\"}",
        ),
        Reply::Data(value) => {
            bytes = match value {
                FullAdmittedReply::Sent(counter) => SentFull {
                    counter: U64(*counter),
                    kind: "sent_full".into(),
                    profile: PROFILE.into(),
                }
                .encode_secret(),
                FullAdmittedReply::ControlSent => {
                    SentFullControl { kind: "sent_full_control".into(), profile: PROFILE.into() }
                        .encode_secret()
                }
                FullAdmittedReply::Closed => {
                    ClosedFull { kind: "closed_full".into(), profile: PROFILE.into() }
                        .encode_secret()
                }
                _ => return Err(invalid()),
            }
            .map_err(|_| invalid())?;
            (b"", bytes.as_slice(), b"")
        }
    };
    let length = prefix.len() + body.len() + suffix.len();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )?;
    stream.write_all(prefix)?;
    stream.write_all(body)?;
    stream.write_all(suffix)?;
    stream.flush()?;
    Ok(())
}
fn invalid() -> TransportError {
    TransportError::Http("full pairing mesh refused".into())
}

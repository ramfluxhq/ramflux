// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded test mesh dispatch through the actual current-native relay and pre-body permits.
use super::*;
use ramflux_node_core::{
    MeshPeerIdentity,
    pairing_relay::{
        FULL_MESH_ADMIT_PATH, FullAdmittedReply, FullArm, FullForwardClaim, FullMeshAdmit,
        FullNativeRelay, FullSendPermit, PairingRelayError,
    },
};
use ramflux_protocol::{
    custody::pairing::full_transfer::{
        PROFILE, U64,
        relay::{ClosedFull, FullClaim, SentFull, SentFullControl},
    },
    decode_base64url,
};
use ramflux_transport::{MeshTlsServerStream, TransportError};
use zeroize::Zeroizing;

enum Admission {
    Claim(IpAddr),
    Admit,
    Forward(FullSendPermit),
}
fn invalid() -> TransportError {
    TransportError::Http("test: full mesh request refused".into())
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
fn required<'a>(raw: &'a str, name: &str) -> Result<&'a str, TransportError> {
    header(raw, name)?.ok_or_else(invalid)
}
fn b32(value: &str) -> Result<Zeroizing<[u8; 32]>, TransportError> {
    if value.len() != 43 {
        return Err(invalid());
    }
    let bytes = Zeroizing::new(decode_base64url(value).map_err(|_| invalid())?);
    if ramflux_protocol::encode_base64url(bytes.as_slice()) != value {
        return Err(invalid());
    }
    Ok(Zeroizing::new(bytes.as_slice().try_into().map_err(|_| invalid())?))
}
fn admit(
    native: &FullNativeRelay<'_>,
    peer: &MeshPeerIdentity,
    path: &str,
    raw: &str,
    bytes: usize,
) -> Result<Option<Admission>, TransportError> {
    if header(raw, "content-type")? != Some("application/octet-stream") {
        return Ok(None);
    }
    if peer.service_id != "ramflux-federation"
        || raw.len() > 4096
        || raw
            .len()
            .checked_add(bytes)
            .is_none_or(|total| total > ramflux_node_core::pairing_relay::FULL_MESH_FRAME_BYTES)
    {
        return Err(invalid());
    }
    if path == PAIRING_CLAIM_PATH {
        if bytes > 8192 {
            return Err(invalid());
        }
        return Ok(Some(Admission::Claim(
            required(raw, "x-ramflux-pairing-source")?.parse().map_err(|_| invalid())?,
        )));
    }
    if path == FULL_MESH_ADMIT_PATH {
        return Ok(Some(Admission::Admit));
    }
    let arm = match required(raw, "x-ramflux-pairing-arm")? {
        "send" => FullArm::Send,
        "send_control" => FullArm::SendControl,
        "poll" => FullArm::Poll,
        "poll_control" => FullArm::PollControl,
        "close" => FullArm::Close,
        _ => return Err(invalid()),
    };
    if path != arm.mesh_path() || bytes > arm.body_limit() {
        return Err(invalid());
    }
    let id = b32(required(raw, "x-ramflux-pairing-permit")?)?;
    let nonce = b32(required(raw, "x-ramflux-pairing-nonce")?)?;
    let permit = native
        .take(&FullForwardClaim {
            id: &id,
            peer,
            request_nonce: &nonce,
            authorization: required(raw, "authorization")?,
            path,
            arm,
            bytes,
        })
        .map_err(|_| invalid())?;
    Ok(Some(Admission::Forward(permit)))
}
pub(super) fn serve(
    stream: &mut MeshTlsServerStream,
    peer: &MeshPeerIdentity,
    native: &FullNativeRelay<'_>,
    store: &Arc<Mutex<PairingRelayStore>>,
    calls: &std::sync::atomic::AtomicUsize,
) -> TestResult {
    let _deadline =
        ramflux_transport::mesh_request_deadline(stream, Instant::now() + Duration::from_secs(5))?;
    let Some(request) = ramflux_transport::read_bounded_mesh_http_request_with_admission(
        stream,
        &|_, path| match path {
            FULL_MESH_ADMIT_PATH => 1024,
            "/pairing/v1/full/send" => 524_288,
            _ => 65_536,
        },
        |method, path, raw, bytes| {
            if method != "POST" {
                return Err(invalid());
            }
            admit(native, peer, path, raw, bytes)
        },
    )?
    else {
        return Ok(());
    };
    let (mut request, admission) = request.into_parts();
    let body = Zeroizing::new(std::mem::take(&mut request.body));
    let result = match admission {
        Some(Admission::Claim(source)) => FullClaim::from_wire_bytes(&body)
            .map_err(|_| PairingRelayError::WrongContext)
            .and_then(|claim| native.claim(peer, source, &claim)),
        Some(Admission::Admit) => {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            FullMeshAdmit::from_wire_bytes(&body)
                .map_err(|_| PairingRelayError::WrongContext)
                .and_then(|request| native.admit(peer, &request))
                .and_then(|permit| {
                    permit.encode_secret().map_err(|_| PairingRelayError::WrongContext)
                })
        }
        Some(Admission::Forward(permit)) => {
            let mut body = body;
            return match native.forward(peer, permit, std::mem::take(&mut *body)) {
                Ok(reply) => write_data(stream, &reply),
                Err(error) => write_failure(stream, &error),
            };
        }
        None => {
            let forward: PairingMeshForward = serde_json::from_slice(&body)?;
            let reply = handle_pairing_mesh(store, &request.path, &forward);
            return write_bytes(stream, &serde_json::to_vec(&reply)?);
        }
    };
    match result {
        Ok(bytes) => write_bytes(stream, &bytes),
        Err(error) => write_failure(stream, &error),
    }
}
fn write_failure(stream: &mut MeshTlsServerStream, error: &PairingRelayError) -> TestResult {
    let bytes = Zeroizing::new(
        Failure {
            schema: "ramflux.pairing.Failure.v2".into(),
            version: 2,
            code: error.code().into(),
            retry_after_ms: match error {
                PairingRelayError::Busy { retry_after_ms } => Some(*retry_after_ms),
                _ => None,
            },
        }
        .to_wire_bytes()?,
    );
    write_bytes(stream, &bytes)
}
fn write_bytes(stream: &mut MeshTlsServerStream, bytes: &[u8]) -> TestResult {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}
fn write_data(stream: &mut MeshTlsServerStream, reply: &FullAdmittedReply) -> TestResult {
    let bytes;
    let (prefix, body, suffix): (&[u8], &[u8], &[u8]) = match reply {
        FullAdmittedReply::Packet(frame) => (
            b"{\"kind\":\"polled_full\",\"packet\":",
            frame.as_ref().map_or(b"null".as_slice(), |frame| frame.packet_bytes()),
            b",\"profile\":\"primary_transfer_full_v1\"}",
        ),
        FullAdmittedReply::Control(frame) => (
            b"{\"control\":",
            frame.as_ref().map_or(b"null".as_slice(), |frame| frame.as_bytes()),
            b",\"kind\":\"polled_full_control\",\"profile\":\"primary_transfer_full_v1\"}",
        ),
        value => {
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
                _ => return Err(invalid().into()),
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

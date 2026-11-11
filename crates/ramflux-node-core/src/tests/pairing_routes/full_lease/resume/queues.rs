// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::pairing_relay::{FullDataAccepted, PairingRelayError};
use ramflux_protocol::custody::pairing::full_transfer::{
    PROFILE, SecretBase64, U64,
    relay::{EncryptedPacket, SendFull},
};
fn send(token: &FullResumeToken, counter: u64, size: usize) -> SendFull {
    SendFull {
        kind: "send_full".into(),
        profile: PROFILE.into(),
        token: SecretBase64::from_bytes(token.token.as_ref()),
        packet: EncryptedPacket {
            ciphertext: encode_base64url(vec![7; size]),
            counter: U64(counter),
            epoch: token.epoch.clone(),
            lease_id: token.lease_id.clone(),
            role: token.role.clone(),
        },
    }
}
fn accept(
    relay: &Mutex<PairingRelayStore>,
    token: &FullResumeToken,
    request: &SendFull,
    admission: &FullNativeAdmission<'_>,
) -> TestResult<FullDataAccepted> {
    let header = format!(
        "POST /client/pairing/v1/send HTTP/1.1\r\nAuthorization: PairingFull {}.{}.{}.{}\r\n\r\n",
        token.lease_id,
        token.epoch,
        token.role,
        encode_base64url(token.token.as_ref())
    );
    let mut body = request.to_wire_bytes()?;
    body.shrink_to_fit();
    let permit =
        reserve_http(relay, "/client/pairing/v1/send", true, &header, body.len(), admission)?;
    Ok(locked(relay)?.accept_full_send(permit, body, admission)?)
}
pub(super) fn prove(
    relay: &Mutex<PairingRelayStore>,
    initiator: &FullResumeToken,
    responder: &FullResumeToken,
    admission: &FullNativeAdmission<'_>,
    clock: &Arc<TestPairingClock>,
) -> TestResult {
    clock.advance_secs(1);
    let ready = send(responder, 0, 16);
    assert_eq!(accept(relay, responder, &ready, admission)?, FullDataAccepted::Accepted(0));
    // First B packet consumes the retained HPKE control. Only the Ready body remains.
    let stats = locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget;
    assert_eq!(stats.buffers, 1);
    let held_ready = locked(relay)?
        .poll_full_data(&route(initiator), None, admission)?
        .ok_or("missing Ready")?;
    assert_eq!(held_ready.counter(), 0);
    assert_eq!(held_ready.packet_bytes(), ready.packet.to_wire_bytes()?);
    assert!(
        !std::str::from_utf8(held_ready.packet_bytes())?
            .contains(&encode_base64url(responder.token.as_ref()))
    );
    assert!(locked(relay)?.poll_full_data(&route(initiator), Some(0), admission)?.is_none());
    assert_eq!(
        locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget.reserved_bytes,
        stats.reserved_bytes
    );
    // Exact retry re-ACKs; no second queued allocation/counter increment.
    assert_eq!(accept(relay, responder, &ready, admission)?, FullDataAccepted::Duplicate(0));
    assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget.buffers, 1);
    let mut changed = ready.clone();
    changed.packet.ciphertext = encode_base64url([8; 16]);
    assert!(accept(relay, responder, &changed, admission).is_err());
    assert!(matches!(
        locked(relay)?.poll_full_data(&route(initiator), Some(8), admission),
        Err(PairingRelayError::Replay)
    ));
    let next = send(responder, 1, 16);
    assert_eq!(accept(relay, responder, &next, admission)?, FullDataAccepted::Accepted(1));
    clock.advance_secs(1);
    let held_next = locked(relay)?
        .poll_full_data(&route(initiator), None, admission)?
        .ok_or("missing responder continuation")?;
    assert_eq!(held_next.counter(), 1);
    let source = send(initiator, 0, 131_072);
    assert_eq!(accept(relay, initiator, &source, admission)?, FullDataAccepted::Accepted(0));
    let held_source = locked(relay)?
        .poll_full_data(&route(responder), None, admission)?
        .ok_or("missing initiator zero")?;
    assert_eq!(held_source.counter(), 0);
    assert_eq!(held_source.packet_bytes(), source.packet.to_wire_bytes()?);
    // A repeat poll also spends byte credit. It must wait for deterministic refill.
    assert!(matches!(
        locked(relay)?.poll_full_data(&route(responder), None, admission),
        Err(PairingRelayError::Busy { .. })
    ));
    clock.advance_secs(1);
    let again = locked(relay)?
        .poll_full_data(&route(responder), None, admission)?
        .ok_or("missing exact borrowed retry")?;
    assert_eq!(again.packet_bytes().as_ptr(), held_source.packet_bytes().as_ptr());
    drop(again);
    clock.advance_secs(10);
    assert!(matches!(
        locked(relay)?.reserve_full_body(&route(initiator), 64, admission),
        Err(PairingRelayError::WrongContext)
    ));
    let retired = locked(relay)?.full_resume_stats()?.ok_or("stats")?;
    assert_eq!(retired.connections, 0);
    assert_eq!(retired.body_budget.buffers, 3);
    drop(held_ready);
    drop(held_next);
    drop(held_source);
    assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget.buffers, 0);
    Ok(())
}

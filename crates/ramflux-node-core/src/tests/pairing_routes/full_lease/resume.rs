// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
mod mesh;
mod queues;
use crate::pairing_relay::{
    FullNativeAdmission, FullResumeChallenge, FullResumeOffer, FullResumeProgress, FullResumeToken,
    FullRoute,
};
use ramflux_protocol::custody::Envelope;
use ramflux_protocol::custody::pairing::full_transfer::lease::{DataLease, ResumeProof};

fn signed(
    challenge: &FullResumeChallenge,
    who: &str,
    seed: u8,
) -> TestResult<Envelope<ResumeProof>> {
    let mut body = challenge.template.clone();
    body.role = who.into();
    Ok(Envelope {
        signature: ramflux_crypto::sign_canonical_bytes_with_seed(
            &body.signing_bytes()?,
            [seed; 32],
        ),
        body,
    })
}
fn token(progress: FullResumeProgress) -> TestResult<FullResumeToken> {
    match progress {
        FullResumeProgress::Ready(token) => Ok(*token),
        FullResumeProgress::Pending => {
            Err("both original proofs did not establish data-only state".into())
        }
    }
}
fn route(token: &FullResumeToken) -> FullRoute<'_> {
    FullRoute {
        lease_id: &token.lease_id,
        epoch: &token.epoch,
        role: &token.role,
        token: &token.token,
    }
}
fn offer(lease: &Envelope<DataLease>, epoch: u8) -> FullResumeOffer {
    FullResumeOffer {
        lease: lease.clone(),
        hpke_keys: BranchKeys {
            source: encode_base64url(ramflux_crypto::X25519KeyPair::from_seed([51; 32]).public),
            destination: encode_base64url(
                ramflux_crypto::X25519KeyPair::from_seed([52; 32]).public,
            ),
        },
        epoch: encode_base64url([epoch; 32]),
    }
}

#[derive(Clone, Copy)]
pub(super) enum ControlCase {
    Replay,
    WrongRoleToken,
    Header,
    Queue,
    Mesh,
}

pub(super) fn prove_resume(
    relay: &Mutex<PairingRelayStore>,
    lease: &Envelope<DataLease>,
    driver: &custody_sessions::Driver,
    router: &RouterCore,
    clock: &Arc<TestPairingClock>,
    control_case: Option<ControlCase>,
) -> TestResult {
    let record = router
        .custody_record(&driver.reference.account_anchor, NOW)?
        .ok_or("native record missing")?;
    let current = ramflux_crypto::custody::verify_record(&record.record, NOW, None, None)?;
    let admission = FullNativeAdmission::for_current(&driver.node, &current, &lease.body.grant);
    let offer = offer(lease, 41);
    let challenge = locked(relay)?.begin_full_resume(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        &offer,
        &admission,
    )?;
    assert_eq!(challenge.expires_in_ms, 10_000);
    let source = signed(&challenge, "initiator", 12)?;
    let destination = signed(&challenge, "responder", 37)?;
    assert!(matches!(
        locked(relay)?.submit_full_resume(&source, &admission)?,
        FullResumeProgress::Pending
    ));
    assert_eq!(locked(relay)?.stats().full, 0);
    let mut altered = destination.clone();
    altered.body.nonce = encode_base64url([90; 32]);
    altered.signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(&altered.body.signing_bytes()?, [37; 32]);
    assert!(matches!(
        locked(relay)?.submit_full_resume(&altered, &admission),
        Err(crate::pairing_relay::PairingRelayError::WrongContext)
    ));
    let responder = token(locked(relay)?.submit_full_resume(&destination, &admission)?)?;
    let initiator = token(locked(relay)?.submit_full_resume(&source, &admission)?)?;
    assert_eq!(locked(relay)?.stats().full, 1);
    assert_eq!(locked(relay)?.stats().slots, 2);
    let distinct = initiator.token.as_slice() != responder.token.as_slice();
    assert!(distinct);
    let reflected = FullRoute { token: &responder.token, ..route(&initiator) };
    assert!(locked(relay)?.reserve_full_body(&reflected, 1024, &admission).is_err());
    let wrong_epoch = encode_base64url([80; 32]);
    let wrong = FullRoute { epoch: &wrong_epoch, ..route(&initiator) };
    assert!(locked(relay)?.reserve_full_body(&wrong, 1024, &admission).is_err());
    let permit = locked(relay)?.reserve_full_body(&route(&initiator), 524_288, &admission)?;
    let stats = locked(relay)?.full_resume_stats()?.ok_or("resume stats")?;
    assert_eq!(stats.body_budget.reserved_bytes, 524_288);
    assert!(stats.body_budget.metadata_bound_bytes <= 65_536);
    drop(permit);
    assert_eq!(
        locked(relay)?.full_resume_stats()?.ok_or("resume stats")?.body_budget.reserved_bytes,
        0
    );
    if let Some(case) = control_case {
        clock.advance_secs(1);
        if matches!(case, ControlCase::Header) {
            prove_headers(relay, &initiator, &responder, &admission)?;
        } else if matches!(case, ControlCase::Mesh) {
            mesh::prove(relay, &initiator, &responder, &admission, clock)?;
        } else if matches!(case, ControlCase::Queue) {
            prove_control(relay, &initiator, &responder, &admission, ControlCase::Replay)?;
            queues::prove(relay, &initiator, &responder, &admission, clock)?;
        } else {
            prove_control(relay, &initiator, &responder, &admission, case)?;
        }
    }
    prove_restarted(lease, &admission, clock, &source, &destination, &initiator)?;
    clock.advance_secs(10);
    assert!(matches!(
        locked(relay)?.reserve_full_body(&route(&initiator), 64, &admission),
        Err(crate::pairing_relay::PairingRelayError::WrongContext)
    ));
    assert_eq!(locked(relay)?.stats().full, 0);
    Ok(())
}
fn prove_restarted(
    lease: &Envelope<DataLease>,
    admission: &FullNativeAdmission<'_>,
    clock: &Arc<TestPairingClock>,
    old_source: &Envelope<ResumeProof>,
    old_destination: &Envelope<ResumeProof>,
    old_token: &FullResumeToken,
) -> TestResult {
    let mut restarted = PairingRelayStore::new(PairingRelayConfig {
        clock: Arc::clone(clock) as Arc<dyn PairingClock>,
        node_seed: [8; 32],
        public_origin: ORIGIN.into(),
    })?;
    assert_eq!(restarted.stats().slots, 0);
    let challenge = restarted.begin_full_resume(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        &offer(lease, 42),
        admission,
    )?;
    assert_ne!(challenge.template.boot_id, old_source.body.boot_id);
    assert!(restarted.submit_full_resume(old_source, admission).is_err());
    assert!(restarted.submit_full_resume(old_destination, admission).is_err());
    assert!(matches!(
        restarted.submit_full_resume(&signed(&challenge, "initiator", 12)?, admission)?,
        FullResumeProgress::Pending
    ));
    let recipient =
        token(restarted.submit_full_resume(&signed(&challenge, "responder", 37)?, admission)?)?;
    assert_eq!(restarted.stats().slots, 1);
    assert_eq!(restarted.stats().full, 1);
    assert!(restarted.reserve_full_body(&route(old_token), 64, admission).is_err());
    let permit = restarted.reserve_full_body(&route(&recipient), 64, admission)?;
    drop(permit);
    let stats = restarted.full_resume_stats()?.ok_or("resume stats")?;
    assert_eq!(stats.pending_challenges, 0);
    assert_eq!(stats.connections, 1);
    Ok(())
}

fn prove_control(
    relay: &Mutex<PairingRelayStore>,
    initiator: &FullResumeToken,
    responder: &FullResumeToken,
    admission: &FullNativeAdmission<'_>,
    case: ControlCase,
) -> TestResult {
    use crate::pairing_relay::PairingRelayError;
    use ramflux_protocol::custody::pairing::full_transfer::{
        PROFILE, SecretBase64,
        relay::{HpkeConfirmFull, PollFullControl, SendFullControl},
    };
    let mut request = SendFullControl {
        control: HpkeConfirmFull {
            confirmation: encode_base64url([3; 64]),
            enc: encode_base64url([4; 32]),
            epoch: initiator.epoch.clone(),
            lease_id: initiator.lease_id.clone(),
            kind: "hpke_confirm".into(),
            role: "initiator".into(),
        },
        kind: "send_full_control".into(),
        profile: PROFILE.into(),
        token: SecretBase64::from_bytes(initiator.token.as_ref()),
    };
    if matches!(case, ControlCase::WrongRoleToken) {
        request.token = SecretBase64::from_bytes(responder.token.as_ref());
        assert!(matches!(
            locked(relay)?.send_full_control(&request, admission),
            Err(PairingRelayError::WrongContext)
        ));
        let stats = locked(relay)?.full_resume_stats()?.ok_or("resume stats")?;
        assert_eq!(stats.body_budget.buffers, 0);
        request.token = SecretBase64::from_bytes(initiator.token.as_ref());
    }
    locked(relay)?.send_full_control(&request, admission)?;
    let before = locked(relay)?.full_resume_stats()?.ok_or("resume stats")?.body_budget;
    assert_eq!(before.buffers, 1);
    assert!(matches!(
        locked(relay)?.send_full_control(&request, admission),
        Err(PairingRelayError::Replay)
    ));
    assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("resume stats")?.body_budget, before);
    let poll = PollFullControl {
        epoch: responder.epoch.clone(),
        kind: "poll_full_control".into(),
        lease_id: responder.lease_id.clone(),
        profile: PROFILE.into(),
        role: "responder".into(),
        token: SecretBase64::from_bytes(responder.token.as_ref()),
    };
    let first = locked(relay)?.poll_full_control(&poll, admission)?.ok_or("missing control")?;
    let second = locked(relay)?.poll_full_control(&poll, admission)?.ok_or("missing retry")?;
    assert_eq!(first.as_bytes(), request.control.to_wire_bytes()?);
    assert_eq!(first.as_bytes().as_ptr(), second.as_bytes().as_ptr());
    assert!(matches!(
        locked(relay)?.poll_full_control(&poll, admission),
        Err(PairingRelayError::Busy { .. })
    ));
    Ok(())
}

fn prove_headers(
    relay: &Mutex<PairingRelayStore>,
    initiator: &FullResumeToken,
    responder: &FullResumeToken,
    admission: &FullNativeAdmission<'_>,
) -> TestResult {
    use crate::pairing_relay::PairingRelayError;
    use ramflux_protocol::custody::pairing::full_transfer::{
        PROFILE, SecretBase64, U64,
        relay::{EncryptedPacket, SendFull},
    };
    let valid = format!(
        "POST /client/pairing/v1/send HTTP/1.1\r\nAuthorization: PairingFull {}.{}.initiator.{}\r\nContent-Length: 60000\r\n\r\n",
        initiator.lease_id,
        initiator.epoch,
        encode_base64url(initiator.token.as_ref())
    );
    let before = locked(relay)?.full_resume_stats()?.ok_or("resume stats")?.body_budget;
    let cases = [
        "POST /client/pairing/v1/send HTTP/1.1\r\nContent-Length: 60000\r\n\r\n".to_owned(),
        valid.replace("Content-Length:", "authorization: Bearer duplicate\r\nContent-Length:"),
        valid.replace("PairingFull ", "Bearer "),
        valid.replace(".initiator.", ".responder."),
        valid.replace(&initiator.epoch, &encode_base64url([90; 32])),
        valid.replace(&initiator.lease_id, &encode_base64url([90; 32])),
        valid.replace(
            &encode_base64url(initiator.token.as_ref()),
            &encode_base64url(responder.token.as_ref()),
        ),
    ];
    for header in &cases {
        assert!(matches!(
            reserve_http(relay, "/client/pairing/v1/send", true, header, 60_000, admission),
            Err(PairingRelayError::WrongContext)
        ));
        assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("resume stats")?.body_budget, before);
    }
    // No body is transmitted: a read-before-auth bug returns 408 instead of this 400.
    for header in cases.iter().take(2) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let mut client = std::net::TcpStream::connect(listener.local_addr()?)?;
        let (mut server, _) = listener.accept()?;
        client.write_all(header.as_bytes())?;
        let limits = crate::HttpRequestLimits {
            max_body_bytes: 524_288,
            ..crate::pairing_relay::pairing_http_limits()
        };
        let result = crate::read_http_request_with_full_admission(
            &mut server,
            crate::HttpRequestLimits::default(),
            limits,
            |_, path| crate::pairing_relay::is_pairing_path(path),
            std::time::Instant::now(),
            |_, path, raw, length| {
                reserve_http(relay, path, true, raw, length, admission).map(Some).map_err(|_| {
                    crate::NodeCoreError::HttpRequestRejected { status: "400 Bad Request" }
                })
            },
        );
        assert!(matches!(
            result,
            Err(crate::NodeCoreError::HttpRequestRejected { status: "400 Bad Request" })
        ));
        assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("resume stats")?.body_budget, before);
    }
    assert!(matches!(
        reserve_http(relay, "/client/pairing/v1/send", false, &valid, 60_000, admission),
        Err(PairingRelayError::WrongContext)
    ));
    assert!(matches!(
        reserve_http(relay, "/healthz", true, &valid, 60_000, admission),
        Err(PairingRelayError::WrongContext)
    ));
    let send = SendFull {
        kind: "send_full".into(),
        profile: PROFILE.into(),
        token: SecretBase64::from_bytes(initiator.token.as_ref()),
        packet: EncryptedPacket {
            ciphertext: encode_base64url([8; 16]),
            counter: U64(0),
            epoch: initiator.epoch.clone(),
            lease_id: initiator.lease_id.clone(),
            role: "initiator".into(),
        },
    };
    let bytes = send.encode_secret()?;
    let permit =
        reserve_http(relay, "/client/pairing/v1/send", true, &valid, bytes.len(), admission)?;
    permit.verify_body(&bytes)?;
    for part in 0..4 {
        let mut changed = send.clone();
        match part {
            0 => changed.packet.lease_id = encode_base64url([90; 32]),
            1 => changed.packet.epoch = encode_base64url([90; 32]),
            2 => changed.packet.role = "responder".into(),
            _ => changed.token = SecretBase64::from_bytes(responder.token.as_ref()),
        }
        assert!(matches!(
            permit.verify_body(&changed.encode_secret()?),
            Err(PairingRelayError::WrongContext)
        ));
    }
    drop(permit);
    assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("resume stats")?.body_budget, before);
    Ok(())
}

fn reserve_http(
    relay: &Mutex<PairingRelayStore>,
    path: &str,
    tls: bool,
    header: &str,
    bytes: usize,
    admission: &FullNativeAdmission<'_>,
) -> Result<crate::pairing_relay::FullSendPermit, crate::pairing_relay::PairingRelayError> {
    use crate::pairing_relay::{FullAuthorization, PairingRelayError};
    let auth = FullAuthorization::parse("POST", path, tls, header)?;
    relay
        .lock()
        .map_err(|_| PairingRelayError::WrongContext)?
        .reserve_full_http_body(&auth, bytes, admission)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::pairing_relay::{FullArm, FullForwardClaim, FullMeshAdmit, SecretAuthorization};
use ramflux_protocol::custody::pairing::full_transfer::SecretBase64;
use zeroize::Zeroizing;
fn authorization(token: &FullResumeToken) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "PairingFull {}.{}.{}.{}",
        token.lease_id,
        token.epoch,
        token.role,
        encode_base64url(token.token.as_ref())
    ))
}
fn peer(node: &str) -> crate::MeshPeerIdentity {
    crate::MeshPeerIdentity {
        node_id: node.into(),
        service_id: "ramflux-federation".into(),
        instance_id: None,
        spiffe_uri: format!("spiffe://{node}/ramflux-federation"),
    }
}
pub(super) fn prove(
    relay: &Mutex<PairingRelayStore>,
    initiator: &FullResumeToken,
    responder: &FullResumeToken,
    admission: &FullNativeAdmission<'_>,
    clock: &Arc<TestPairingClock>,
) -> TestResult {
    let auth = authorization(initiator);
    let federation = peer("real-peer");
    let other_peer = peer("different-peer");
    let original = queues::send(initiator, 0, 16).to_wire_bytes()?;
    let other_role = queues::send(responder, 0, 16).to_wire_bytes()?;
    assert_eq!(original.len(), other_role.len());
    let bytes = original.len();
    prove_arm_header(&auth)?;
    let request = FullMeshAdmit {
        arm: FullArm::Send,
        authorization: SecretAuthorization::new(auth.to_string()),
        content_length: u64::try_from(bytes)?,
        request_nonce: SecretBase64::from_bytes(&[66; 32]),
    };
    // Exercise the exact secret wire codec as well as the reservation owner.
    let request = FullMeshAdmit::from_wire_bytes(&request.encode_secret()?)?;
    let ticket = locked(relay)?.admit_full_forward(&request, &federation, admission)?;
    let id = ticket.permit.decode(32)?;
    let id: &[u8; 32] = id.as_slice().try_into()?;
    let claim = FullForwardClaim {
        id,
        peer: &federation,
        request_nonce: &[66; 32],
        authorization: &auth,
        path: FullArm::Send.mesh_path(),
        arm: FullArm::Send,
        bytes,
    };
    let before = locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget;
    assert_eq!(before.reserved_bytes, bytes);
    for wrong in [
        FullForwardClaim { peer: &other_peer, ..claim },
        FullForwardClaim { request_nonce: &[67; 32], ..claim },
        FullForwardClaim { bytes: bytes - 1, ..claim },
        FullForwardClaim { arm: FullArm::SendControl, ..claim },
        FullForwardClaim { path: FullArm::Poll.mesh_path(), ..claim },
    ] {
        assert!(locked(relay)?.take_full_forward(&wrong, admission).is_err());
        assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget, before);
    }
    let b_auth = authorization(responder);
    assert!(
        locked(relay)?
            .take_full_forward(&FullForwardClaim { authorization: &b_auth, ..claim }, admission)
            .is_err()
    );
    let mut wrong_lease = initiator.lease_id.clone();
    wrong_lease.replace_range(..1, if wrong_lease.starts_with('A') { "B" } else { "A" });
    let swapped = Zeroizing::new(auth.replacen(&initiator.lease_id, &wrong_lease, 1));
    assert!(
        locked(relay)?
            .take_full_forward(&FullForwardClaim { authorization: &swapped, ..claim }, admission)
            .is_err()
    );
    assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget, before);
    // Both forwards are released by the same barrier. The node mutex is the real
    // production atomic owner; exactly one thread can move its non-cloneable permit.
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| -> TestResult {
        let first = scope.spawn(|| {
            barrier.wait();
            relay
                .lock()
                .map_err(|_| "lock")?
                .take_full_forward(&claim, admission)
                .map_err(|_| "refused")
        });
        let second = scope.spawn(|| {
            barrier.wait();
            relay
                .lock()
                .map_err(|_| "lock")?
                .take_full_forward(&claim, admission)
                .map_err(|_| "refused")
        });
        let a = first.join().map_err(|_| "first forward panicked")?;
        let b = second.join().map_err(|_| "second forward panicked")?;
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert_eq!(
            locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget.reserved_bytes,
            bytes
        );
        let permit = a.or(b).map_err(|_| "no successful claim")?;
        assert!(permit.verify_body(&other_role).is_err(), "equal-length role swap");
        let mut other_lease = queues::send(initiator, 0, 16);
        other_lease.packet.lease_id = encode_base64url([98; 32]);
        let other_lease = other_lease.to_wire_bytes()?;
        assert_eq!(other_lease.len(), original.len());
        assert!(permit.verify_body(&other_lease).is_err(), "equal-length lease swap");
        permit.verify_body(&original)?;
        // Dropping the only successful claim models disconnect mid-body.
        drop(permit);
        Ok(())
    })?;
    assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget.reserved_bytes, 0);
    assert!(locked(relay)?.take_full_forward(&claim, admission).is_err());
    let mut next = request.clone();
    next.request_nonce = SecretBase64::from_bytes(&[68; 32]);
    locked(relay)?.admit_full_forward(&next, &federation, admission)?;
    clock.advance_secs(5);
    assert_eq!(locked(relay)?.full_resume_stats()?.ok_or("stats")?.body_budget.reserved_bytes, 0);
    prove_close(relay, initiator, admission, next, &claim)?;
    Ok(())
}

fn prove_arm_header(auth: &str) -> TestResult {
    let header = Zeroizing::new(format!(
        "POST /client/pairing/v1/send HTTP/1.1\r\nAuthorization: {auth}\r\nX-Ramflux-Pairing-Arm: send\r\n\r\n"
    ));
    assert_eq!(
        FullArm::from_header("POST", FullArm::Send.public_path(), true, &header)?,
        FullArm::Send
    );
    for altered in [
        header.replace("X-Ramflux-Pairing-Arm: send\r\n", ""),
        header.replace(
            "X-Ramflux-Pairing-Arm: send",
            "X-Ramflux-Pairing-Arm: send\r\nX-Ramflux-Pairing-Arm: send",
        ),
        header.replace("X-Ramflux-Pairing-Arm: send", "X-Ramflux-Pairing-Arm: poll"),
    ] {
        let altered = Zeroizing::new(altered);
        assert!(FullArm::from_header("POST", FullArm::Send.public_path(), true, &altered).is_err());
    }
    Ok(())
}
fn prove_close(
    relay: &Mutex<PairingRelayStore>,
    initiator: &FullResumeToken,
    admission: &FullNativeAdmission<'_>,
    mut next: FullMeshAdmit,
    claim: &FullForwardClaim<'_>,
) -> TestResult {
    let federation = claim.peer;
    let auth = claim.authorization;
    // Closing an epoch between admission and forwarding retires its unused tickets,
    // without treating CloseFull as cancellation of the durable seven-day lease.
    next.request_nonce = SecretBase64::from_bytes(&[70; 32]);
    let unused = locked(relay)?.admit_full_forward(&next, federation, admission)?;
    let unused_id = unused.permit.decode(32)?;
    let unused_id: &[u8; 32] = unused_id.as_slice().try_into()?;
    let close = ramflux_protocol::custody::pairing::full_transfer::relay::CloseFull {
        epoch: initiator.epoch.clone(),
        kind: "close_full".into(),
        lease_id: initiator.lease_id.clone(),
        profile: ramflux_protocol::custody::pairing::full_transfer::PROFILE.into(),
        role: initiator.role.clone(),
        token: SecretBase64::from_bytes(initiator.token.as_ref()),
    };
    let mut close_body = close.to_wire_bytes()?;
    close_body.shrink_to_fit();
    let closing = FullMeshAdmit {
        arm: FullArm::Close,
        authorization: SecretAuthorization::new(auth.to_owned()),
        content_length: u64::try_from(close_body.len())?,
        request_nonce: SecretBase64::from_bytes(&[71; 32]),
    };
    let close_ticket = locked(relay)?.admit_full_forward(&closing, federation, admission)?;
    let close_id = close_ticket.permit.decode(32)?;
    let close_id: &[u8; 32] = close_id.as_slice().try_into()?;
    let close_claim = FullForwardClaim {
        id: close_id,
        request_nonce: &[71; 32],
        arm: FullArm::Close,
        path: FullArm::Close.mesh_path(),
        bytes: close_body.len(),
        ..*claim
    };
    let permit = locked(relay)?.take_full_forward(&close_claim, admission)?;
    assert!(matches!(
        locked(relay)?.accept_full_forward(permit, close_body, admission)?,
        crate::pairing_relay::FullAdmittedReply::Closed
    ));
    let stale = FullForwardClaim { id: unused_id, request_nonce: &[70; 32], ..*claim };
    assert!(locked(relay)?.take_full_forward(&stale, admission).is_err());
    let stats = locked(relay)?.full_resume_stats()?.ok_or("stats")?;
    assert_eq!(stats.connections, 0);
    assert_eq!(stats.body_budget.reserved_bytes, 0);
    Ok(())
}

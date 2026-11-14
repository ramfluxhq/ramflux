// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-process typed transport through the actual native/permit owners; no TLS/Fedwire claim.
use super::Relay;
use ramflux_node_core::{
    MeshPeerIdentity,
    pairing_relay::{
        FullAdmittedReply, FullArm, FullForwardClaim, FullMeshAdmit, FullNativeRelay,
        PairingRelayError, SecretAuthorization,
    },
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        PROFILE, SecretBase64, U64,
        relay::{
            CloseFull, ClosedFull, EncryptedPacket, FullClaim, FullDiscovery, FullProofReply,
            HelloFull, HpkeConfirmFull, PollFull, PollFullControl, PollFullDiscovery, PolledFull,
            PolledFullControl, ProveFull, SendFull, SendFullControl, SentFull, SentFullControl,
        },
    },
};
use ramflux_sdk::{
    SdkError,
    custody::pairing::{FullPairingTransport, FullPortFuture, FullRelayRequest},
};
use zeroize::Zeroizing;
fn error(value: PairingRelayError) -> SdkError {
    SdkError::PairingCode(value.code())
}
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
fn wire(value: &ramflux_protocol::custody::pairing::WireError) -> SdkError {
    let _ = value;
    SdkError::PairingCode("InvalidInput")
}
fn peer() -> MeshPeerIdentity {
    MeshPeerIdentity {
        node_id: "component-federation".into(),
        service_id: "ramflux-federation".into(),
        instance_id: None,
        spiffe_uri: "spiffe://component/ramflux-federation".into(),
    }
}
impl Relay {
    fn full_claim(&self, claim: &FullClaim) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        FullNativeRelay::new(&self.0.identity, &self.0.router, self.0.relay.clone())
            .claim(&peer(), "127.0.0.1".parse().map_err(|_| wrong())?, claim)
            .map_err(error)
    }
    fn full_request(
        &self,
        request: &impl FullRelayRequest,
        arm: FullArm,
    ) -> Result<FullAdmittedReply, SdkError> {
        let body = request.encode_full()?;
        let (lease, epoch, role, token) = request.scope();
        let token = token.decode(32).map_err(|error| wire(&error))?;
        let token = Zeroizing::new(ramflux_protocol::encode_base64url(token.as_slice()));
        let authorization = SecretAuthorization::new(format!(
            "PairingFull {lease}.{epoch}.{role}.{}",
            token.as_str()
        ));
        let nonce = ramflux_crypto::random_32()?;
        let admit = FullMeshAdmit {
            arm,
            authorization,
            content_length: u64::try_from(body.len()).map_err(|_| wrong())?,
            request_nonce: SecretBase64::from_bytes(&nonce),
        };
        let peer = peer();
        let native = FullNativeRelay::new(&self.0.identity, &self.0.router, self.0.relay.clone());
        let permit = native.admit(&peer, &admit).map_err(error)?;
        let id = permit.permit.decode(32).map_err(|error| wire(&error))?;
        let id = id.as_slice().try_into().map_err(|_| wrong())?;
        let claimed = native
            .take(&FullForwardClaim {
                id,
                peer: &peer,
                request_nonce: &nonce,
                authorization: admit.authorization.as_str(),
                path: arm.mesh_path(),
                arm,
                bytes: body.len(),
            })
            .map_err(error)?;
        // The actual node owner requires an exact body allocation held by its claimed permit.
        let body = body.to_vec().into_boxed_slice().into_vec();
        native.forward(&peer, claimed, body).map_err(error)
    }
}
macro_rules! claim {
    ($method:ident,$request:ty,$reply:ty,$arm:ident,$decode:expr) => {
        fn $method<'a>(&'a self, _: &'a str, request: &'a $request) -> FullPortFuture<'a, $reply> {
            Box::pin(async move {
                let bytes = self.full_claim(&FullClaim::$arm(Box::new(request.clone())))?;
                ($decode)(&bytes).map_err(|error| wire(&error))
            })
        }
    };
}
impl FullPairingTransport for Relay {
    claim!(hello_full, HelloFull, FullDiscovery, Hello, FullDiscovery::from_wire_bytes);
    claim!(
        discover_full,
        PollFullDiscovery,
        FullDiscovery,
        Discovery,
        FullDiscovery::from_wire_bytes
    );
    claim!(prove_full, ProveFull, FullProofReply, Proof, FullProofReply::from_wire_bytes);
    fn send_full<'a>(&'a self, _: &'a str, request: &'a SendFull) -> FullPortFuture<'a, SentFull> {
        Box::pin(async move {
            match self.full_request(request, FullArm::Send)? {
                FullAdmittedReply::Sent(counter) => Ok(SentFull {
                    kind: "sent_full".into(),
                    profile: PROFILE.into(),
                    counter: U64(counter),
                }),
                _ => Err(wrong()),
            }
        })
    }
    fn poll_full<'a>(
        &'a self,
        _: &'a str,
        request: &'a PollFull,
    ) -> FullPortFuture<'a, PolledFull> {
        Box::pin(async move {
            match self.full_request(request, FullArm::Poll)? {
                FullAdmittedReply::Packet(frame) => Ok(PolledFull {
                    kind: "polled_full".into(),
                    profile: PROFILE.into(),
                    packet: frame
                        .map(|frame| EncryptedPacket::from_wire_bytes(frame.packet_bytes()))
                        .transpose()
                        .map_err(|error| wire(&error))?,
                }),
                _ => Err(wrong()),
            }
        })
    }
    fn send_full_control<'a>(
        &'a self,
        _: &'a str,
        request: &'a SendFullControl,
    ) -> FullPortFuture<'a, SentFullControl> {
        Box::pin(async move {
            match self.full_request(request, FullArm::SendControl)? {
                FullAdmittedReply::ControlSent => Ok(SentFullControl {
                    kind: "sent_full_control".into(),
                    profile: PROFILE.into(),
                }),
                _ => Err(wrong()),
            }
        })
    }
    fn poll_full_control<'a>(
        &'a self,
        _: &'a str,
        request: &'a PollFullControl,
    ) -> FullPortFuture<'a, PolledFullControl> {
        Box::pin(async move {
            match self.full_request(request, FullArm::PollControl)? {
                FullAdmittedReply::Control(frame) => Ok(PolledFullControl {
                    kind: "polled_full_control".into(),
                    profile: PROFILE.into(),
                    control: frame
                        .map(|frame| HpkeConfirmFull::from_wire_bytes(frame.as_bytes()))
                        .transpose()
                        .map_err(|error| wire(&error))?,
                }),
                _ => Err(wrong()),
            }
        })
    }
    fn close_full<'a>(
        &'a self,
        _: &'a str,
        request: &'a CloseFull,
    ) -> FullPortFuture<'a, ClosedFull> {
        Box::pin(async move {
            match self.full_request(request, FullArm::Close)? {
                FullAdmittedReply::Closed => {
                    Ok(ClosedFull { kind: "closed_full".into(), profile: PROFILE.into() })
                }
                _ => Err(wrong()),
            }
        })
    }
}

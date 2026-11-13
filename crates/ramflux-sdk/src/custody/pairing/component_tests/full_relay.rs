// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-process typed transport through the actual native/permit owners; no TLS/Fedwire claim.
use super::FullNativeFixture;
use crate::{
    SdkError,
    custody::pairing::{FullPairingTransport, FullPortFuture, FullRelayRequest},
};
use ramflux_node_core::{
    MeshPeerIdentity,
    pairing_relay::{
        FullAdmittedReply, FullArm, FullForwardClaim, FullMeshAdmit, FullNativeRelay, PairingClock,
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
use zeroize::Zeroizing;
fn error(value: PairingRelayError) -> SdkError {
    SdkError::PairingCode(value.code())
}
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
fn wire(value: &ramflux_protocol::custody::pairing::WireError) -> SdkError {
    crate::custody::pairing::transport::wire(value)
}
fn peer() -> MeshPeerIdentity {
    MeshPeerIdentity {
        node_id: "component-federation".into(),
        service_id: "ramflux-federation".into(),
        instance_id: None,
        spiffe_uri: "spiffe://component/ramflux-federation".into(),
    }
}
impl FullNativeFixture {
    fn full_claim(&self, claim: &FullClaim) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        if let FullClaim::Hello(hello) = claim {
            let mut seen = self.full_hellos.lock().map_err(|_| wrong())?;
            if seen.len() < 4
                && !seen.iter().any(|value| value.role == hello.role && value.epoch == hello.epoch)
            {
                seen.push(hello.as_ref().clone());
            }
        }
        FullNativeRelay::new(&self.identity, &self.node.core, self.store.clone())
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
        let native = FullNativeRelay::new(&self.identity, &self.node.core, self.store.clone());
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
impl FullPairingTransport for FullNativeFixture {
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

use crate::custody::pairing::PairingTransport;
use ramflux_protocol::custody::pairing::relay::{
    Claim, Claimed, Close, Closed, Poll, Polled, Send as LegacySend, Sent,
};
use std::{future::Future, pin::Pin, sync::Arc};
type LegacyFuture<T> = Pin<Box<dyn Future<Output = Result<T, SdkError>> + Send>>;
macro_rules! legacy {
    ($method:ident,$request:ty,$reply:ty) => {
        fn $method(&self, origin: String, request: $request) -> LegacyFuture<$reply> {
            let legacy = crate::custody::pairing::tests::MemoryRelay { store: self.store.clone() };
            legacy.$method(origin, request)
        }
    };
}
impl PairingTransport for FullNativeFixture {
    fn full_transport(&self) -> Option<Arc<dyn FullPairingTransport>> {
        Some(Arc::new(self.clone()))
    }
    legacy!(claim, Claim, Claimed);
    legacy!(send, LegacySend, Sent);
    legacy!(poll, Poll, Polled);
    legacy!(close, Close, Closed);
}

struct ClockBridge {
    manual: Arc<ramflux_node_core::pairing_relay::TestPairingClock>,
    started: tokio::time::Instant,
}
impl PairingClock for ClockBridge {
    fn wall_unix_secs(&self) -> Result<u64, PairingRelayError> {
        self.manual.wall_unix_secs()
    }
    fn monotonic_ms(&self) -> u64 {
        self.manual
            .monotonic_ms()
            .saturating_add(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}
pub(super) fn clock(
    manual: Arc<ramflux_node_core::pairing_relay::TestPairingClock>,
) -> Arc<dyn ramflux_node_core::pairing_relay::PairingClock> {
    Arc::new(ClockBridge { manual, started: tokio::time::Instant::now() })
}

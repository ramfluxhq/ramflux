// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! OVP-02 one-use mesh admission. Reservations remain in the existing full body budget.
use super::{FullNativeAdmission, FullResumeServer, FullSendPermit};
use crate::pairing_relay::{FullAuthorization, FullMetadataPermit, PairingRelayError};
use ramflux_protocol::custody::pairing::{
    PairingWire, WireError,
    full_transfer::{PACKET_BYTES, SecretBase64},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const FULL_MESH_ADMIT_PATH: &str = "/pairing/v1/admit_full";
pub const FULL_MESH_FRAME_BYTES: usize = PACKET_BYTES + 4096;
const _: () = assert!(FULL_MESH_FRAME_BYTES <= ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FullArm {
    Send,
    Poll,
    Close,
    SendControl,
    PollControl,
}
impl FullArm {
    /// Non-authorizing arm discriminator, parsed under the original 16-KiB header cap.
    /// A2 still authenticates the complete lease/epoch/role/token before any body expansion.
    /// # Errors
    /// Refuses missing/duplicate/unknown arms, wrong routes, non-TLS and invalid A2 headers.
    pub fn from_header(
        method: &str,
        path: &str,
        trusted_tls: bool,
        header: &str,
    ) -> Result<Self, PairingRelayError> {
        let _auth = FullAuthorization::parse(method, path, trusted_tls, header)?;
        let mut arm = None;
        for line in header.split("\r\n").skip(1).take_while(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or(PairingRelayError::WrongContext)?;
            if name.eq_ignore_ascii_case("x-ramflux-pairing-arm") {
                if arm.is_some() {
                    return Err(PairingRelayError::WrongContext);
                }
                arm = Some(match value.trim_matches([' ', '\t']) {
                    "send" => Self::Send,
                    "send_control" => Self::SendControl,
                    "poll" => Self::Poll,
                    "poll_control" => Self::PollControl,
                    "close" => Self::Close,
                    _ => return Err(PairingRelayError::WrongContext),
                });
            }
        }
        let arm = arm.ok_or(PairingRelayError::WrongContext)?;
        if arm.public_path() != path {
            return Err(PairingRelayError::WrongContext);
        }
        Ok(arm)
    }
    #[must_use]
    pub fn body_limit(self) -> usize {
        if self == Self::Send { PACKET_BYTES } else { 8192 }
    }
    #[must_use]
    pub fn public_path(self) -> &'static str {
        match self {
            Self::Send | Self::SendControl => "/client/pairing/v1/send",
            Self::Poll | Self::PollControl => "/client/pairing/v1/poll",
            Self::Close => "/client/pairing/v1/close",
        }
    }
    #[must_use]
    pub fn mesh_path(self) -> &'static str {
        match self {
            Self::Send | Self::SendControl => "/pairing/v1/full/send",
            Self::Poll | Self::PollControl => "/pairing/v1/full/poll",
            Self::Close => "/pairing/v1/full/close",
        }
    }
}
/// Never Debug: this is the exact A2 header, not an account/native session credential.
#[derive(Clone)]
pub struct SecretAuthorization(Zeroizing<String>);
impl SecretAuthorization {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl Serialize for SecretAuthorization {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for SecretAuthorization {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullMeshAdmit {
    pub arm: FullArm,
    pub authorization: SecretAuthorization,
    pub content_length: u64,
    pub request_nonce: SecretBase64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullMeshPermit {
    pub permit: SecretBase64,
}
macro_rules! secret_wire {
    ($ty:ty,$limit:expr,$value:ident,$validate:block) => {
        impl $ty {
            /// # Errors
            /// Refuses invalid fields or an oversized complete mesh control.
            pub fn encode_secret(&self) -> Result<Zeroizing<Vec<u8>>, WireError> {
                self.validate()?;
                let mut bytes = Zeroizing::new(Vec::with_capacity(Self::LIMIT));
                serde_json::to_writer(&mut *bytes, self).map_err(|_| WireError::Json)?;
                if bytes.len() > Self::LIMIT {
                    return Err(WireError::Size);
                }
                Ok(bytes)
            }
        }
        impl PairingWire for $ty {
            const LIMIT: usize = $limit;
            fn validate(&self) -> Result<(), WireError> {
                let $value = self;
                $validate
            }
            fn to_wire_bytes(&self) -> Result<Vec<u8>, WireError> {
                Ok(std::mem::take(&mut *self.encode_secret()?))
            }
            fn from_wire_bytes(input: &[u8]) -> Result<Self, WireError> {
                decode(input)
            }
        }
    };
}
fn decode<T: PairingWire + serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, WireError> {
    if input.len() > T::LIMIT {
        return Err(WireError::Size);
    }
    let value: T = ramflux_protocol::parse_i_json_secret(input).map_err(|_| WireError::Shape)?;
    if Zeroizing::new(value.to_wire_bytes()?).as_slice() != input {
        return Err(WireError::NonCanonical);
    }
    Ok(value)
}
secret_wire!(FullMeshAdmit, 1024, value, {
    if value.content_length == 0
        || value.content_length > value.arm.body_limit() as u64
        || value.authorization.as_str().len() > 512
        || !value.authorization.as_str().is_ascii()
        || value.authorization.as_str().bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(WireError::Field("full_admission"));
    }
    if value.request_nonce.decode(32)?.len() != 32 {
        return Err(WireError::Field("request_nonce"));
    }
    Ok(())
});
secret_wire!(FullMeshPermit, 128, value, {
    if value.permit.decode(32)?.len() != 32 {
        return Err(WireError::Field("permit"));
    }
    Ok(())
});
/// Claim operands supplied by the authenticated mesh listener, before reading the body.
/// The authorization value is secret and must never enter a generic header log.
pub struct FullForwardClaim<'a> {
    pub id: &'a [u8; 32],
    pub peer: &'a crate::MeshPeerIdentity,
    pub request_nonce: &'a [u8; 32],
    pub authorization: &'a str,
    pub path: &'a str,
    pub arm: FullArm,
    pub bytes: usize,
}
fn federation_peer(peer: &crate::MeshPeerIdentity) -> Result<[u8; 32], PairingRelayError> {
    if peer.service_id != "ramflux-federation" {
        return Err(PairingRelayError::WrongContext);
    }
    // Commit all authenticated identity fields, not a caller-provided forwarding header.
    let mut hasher = blake3::Hasher::new();
    for field in [
        peer.node_id.as_str(),
        peer.service_id.as_str(),
        peer.instance_id.as_deref().unwrap_or(""),
        peer.spiffe_uri.as_str(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}
pub(super) struct ForwardTicket {
    id: Zeroizing<[u8; 32]>,
    deadline: u64,
    boot: [u8; 32],
    peer: [u8; 32],
    nonce: Zeroizing<[u8; 32]>,
    arm: FullArm,
    bytes: usize,
    permit: FullSendPermit,
    _metadata: FullMetadataPermit,
}
impl ForwardTicket {
    pub(super) fn matches_epoch(&self, lease: &str, epoch: &str) -> bool {
        self.permit.lease_id == lease && self.permit.epoch == epoch
    }
}
impl FullResumeServer {
    pub(in crate::pairing_relay) fn prune_forward(&mut self, now: u64) {
        for ticket in &mut self.forward {
            if ticket.as_ref().is_some_and(|ticket| now >= ticket.deadline) {
                ticket.take();
            }
        }
    }
    pub(in crate::pairing_relay) fn admit_forward(
        &mut self,
        request: &FullMeshAdmit,
        peer: &crate::MeshPeerIdentity,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullMeshPermit, PairingRelayError> {
        request.validate().map_err(|error| super::wire(&error))?;
        let peer = federation_peer(peer)?;
        let nonce = request.request_nonce.decode(32).map_err(|error| super::wire(&error))?;
        let nonce: Zeroizing<[u8; 32]> = Zeroizing::new(
            nonce.as_slice().try_into().map_err(|_| PairingRelayError::WrongContext)?,
        );
        self.prune()?;
        if self.forward.iter().flatten().any(|entry| {
            entry.peer == peer && super::constant_time_eq(entry.nonce.as_ref(), nonce.as_ref())
        }) {
            return Err(PairingRelayError::Replay);
        }
        let now = self.clock.monotonic_ms();
        let position = self
            .forward
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| PairingRelayError::busy(now))?;
        // Construct only a bounded temporary header for the same A2 parser; erase it on exit.
        let header = Zeroizing::new(format!(
            "POST {} HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
            request.arm.public_path(),
            request.authorization.as_str()
        ));
        let auth = FullAuthorization::parse("POST", request.arm.public_path(), true, &header)?;
        let bytes =
            usize::try_from(request.content_length).map_err(|_| PairingRelayError::WrongContext)?;
        let permit = self.reserve_body(&auth.route(), bytes, admission)?;
        let extra = std::mem::size_of::<ForwardTicket>() - std::mem::size_of::<FullSendPermit>()
            + std::mem::size_of::<usize>();
        let metadata = self.budget.reserve_metadata(extra, now)?;
        let id = Zeroizing::new(
            ramflux_crypto::random_32().map_err(|_| PairingRelayError::invalid("entropy"))?,
        );
        if self
            .forward
            .iter()
            .flatten()
            .any(|entry| super::constant_time_eq(entry.id.as_ref(), id.as_ref()))
        {
            return Err(PairingRelayError::invalid("entropy"));
        }
        let reply = FullMeshPermit { permit: SecretBase64::from_bytes(id.as_ref()) };
        self.forward[position] = Some(Box::new(ForwardTicket {
            id,
            deadline: now.saturating_add(5000),
            boot: super::b32(&self.boot_id)?,
            peer,
            nonce,
            arm: request.arm,
            bytes,
            permit,
            _metadata: metadata,
        }));
        Ok(reply)
    }
    pub(in crate::pairing_relay) fn take_forward(
        &mut self,
        claim: &FullForwardClaim<'_>,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullSendPermit, PairingRelayError> {
        self.prune()?;
        let peer = federation_peer(claim.peer)?;
        if claim.path != claim.arm.mesh_path() || claim.authorization.len() > 512 {
            return Err(PairingRelayError::WrongContext);
        }
        let header = Zeroizing::new(format!(
            "POST {} HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
            claim.arm.public_path(),
            claim.authorization
        ));
        let auth = FullAuthorization::parse("POST", claim.arm.public_path(), true, &header)?;
        let route = auth.route();
        let position = self
            .forward
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| super::constant_time_eq(entry.id.as_ref(), claim.id))
            })
            .ok_or(PairingRelayError::WrongContext)?;
        let entry = self.forward[position].as_ref().ok_or(PairingRelayError::WrongContext)?;
        // Validate every operand BEFORE moving the reservation. Mismatches cannot cancel
        // the legitimate consumer, and &mut self makes the successful claim atomic.
        let token_matches = super::constant_time_eq(entry.permit.token.as_ref(), route.token);
        let nonce_matches = super::constant_time_eq(entry.nonce.as_ref(), claim.request_nonce);
        if entry.boot != super::b32(&self.boot_id)?
            || entry.peer != peer
            || !nonce_matches
            || entry.arm != claim.arm
            || entry.bytes != claim.bytes
            || entry.permit.lease_id != route.lease_id
            || entry.permit.epoch != route.epoch
            || entry.permit.role != route.role
            || !token_matches
        {
            return Err(PairingRelayError::WrongContext);
        }
        // Recheck at claim and again after complete body decoding in accept_send.
        self.authenticate(&route, admission)?;
        let entry = self.forward[position].take().ok_or(PairingRelayError::WrongContext)?;
        let mut permit = entry.permit;
        permit.arm = Some(entry.arm);
        Ok(permit)
    }
}

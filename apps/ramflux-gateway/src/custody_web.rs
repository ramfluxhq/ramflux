// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Custody handshake of the web listener: `web_origin_bound` only, session opening only.
//!
//! The binding context is authored by this listener from its own configuration and
//! connection state. The value a device must have signed is recomputed here; nothing
//! in it is taken from client bytes.

use super::{GatewayGrant, Proxy};
use crate::GatewayQuicContext;
use crate::web_ingress::close::CloseCode;
use crate::web_ingress::socket::Outgoing;
use ramflux_protocol::custody::{
    BindingMode, CustodyClientFrame, CustodyProofAction, CustodyRefusal, CustodyServerFrame,
    WebOriginBindingV1, decode,
};
use std::time::Duration;
use tokio::sync::mpsc;

/// Hard ceiling of the whole authentication, whatever the configured custody timeout is.
const WEB_AUTH_CEILING: Duration = Duration::from_secs(30);
/// A device needs three custody frames; anything beyond this is not a handshake.
const WEB_CUSTODY_FRAME_BUDGET: usize = 8;

/// Why the handshake ended without a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The socket reader already ended the connection.
    Closed,
    BadFrame,
    AuthRefused,
    /// A possession proof was presented and refused; counted against the source.
    ProofRefused,
    Timeout,
    RateLimited,
    NodeUnavailable,
}

impl Refusal {
    pub(crate) fn close_code(self) -> Option<CloseCode> {
        match self {
            Self::Closed => None,
            Self::BadFrame => Some(CloseCode::BadFrame),
            Self::AuthRefused | Self::ProofRefused => Some(CloseCode::AuthRefused),
            Self::Timeout => Some(CloseCode::Timeout),
            Self::RateLimited => Some(CloseCode::RateLimited),
            Self::NodeUnavailable => Some(CloseCode::NodeUnavailable),
        }
    }
}

/// A verified web grant and the first gateway frame that followed the handoff.
pub(crate) struct Handoff {
    pub(crate) grant: GatewayGrant,
    pub(crate) first: ramflux_node_core::GatewayClientFrame,
}

async fn receive(
    frames: &mut mpsc::Receiver<Vec<u8>>,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, Refusal> {
    match tokio::time::timeout_at(deadline, frames.recv()).await {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(Refusal::Closed),
        Err(_elapsed) => Err(Refusal::Timeout),
    }
}

async fn send(
    out: &mpsc::Sender<Outgoing>,
    frame: &CustodyServerFrame,
    deadline: tokio::time::Instant,
) -> Result<(), Refusal> {
    let bytes = serde_json::to_vec(frame).map_err(|_| Refusal::NodeUnavailable)?;
    match tokio::time::timeout_at(deadline, out.send(Outgoing::Binary(bytes))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_closed)) => Err(Refusal::Closed),
        Err(_elapsed) => Err(Refusal::Timeout),
    }
}

/// Proof actions of the web listener: open a session, or the device's own prekeys.
fn action_allowed(action: &CustodyProofAction) -> bool {
    matches!(
        action,
        CustodyProofAction::OpenSession
            | CustodyProofAction::Register { .. }
            | CustodyProofAction::RegisterUpdate { .. }
            | CustodyProofAction::PrekeyStatus { .. }
    )
}

/// The only custody frames a web device may send before the handoff. Publication, home
/// migration, pairing and every custody `request` frame are refused.
fn permitted(frame: &CustodyClientFrame) -> bool {
    match frame {
        CustodyClientFrame::Challenge { action, .. }
        | CustodyClientFrame::Prove { action, .. } => action_allowed(action),
        _ => false,
    }
}

/// Run `custody_open` → `node_identity` + `web_binding` → `challenge` → `prove` →
/// `gateway_handoff` and return the grant with the first gateway frame.
///
/// # Errors
/// Returns the refusal that decides the close code. The reason never tells the client
/// which authentication check failed.
pub(crate) async fn handshake(
    frames: &mut mpsc::Receiver<Vec<u8>>,
    out: &mpsc::Sender<Outgoing>,
    context: &GatewayQuicContext,
    binding: WebOriginBindingV1,
    capacity: &ramflux_node_core::CustodyIngressPermit,
) -> Result<Handoff, Refusal> {
    let now = tokio::time::Instant::now();
    let deadline =
        (now + WEB_AUTH_CEILING).min(tokio::time::Instant::from_std(capacity.auth_deadline()));
    let first_deadline = (now + crate::session::GATEWAY_FIRST_FRAME_TIMEOUT).min(deadline);

    let first = receive(frames, first_deadline).await?;
    let open: CustodyClientFrame = decode(&first, 4096).map_err(|_| Refusal::BadFrame)?;
    let CustodyClientFrame::CustodyOpen { binding_mode } = open else {
        return Err(Refusal::BadFrame);
    };
    if binding_mode != BindingMode::WebOriginBound {
        return Err(Refusal::AuthRefused);
    }
    // The gateway nonce belongs to this connection: a first-time device proves twice
    // (its prekey registration, then the session). No proof is accepted after it expires.
    let context_expires_at = binding.expires_at;
    // Recomputed from this listener's own state; compared with the proof below.
    let observed = ramflux_crypto::custody::web_origin_binding_hash(&binding)
        .map_err(|_| Refusal::NodeUnavailable)?;
    let (mut proxy, identity) =
        tokio::time::timeout_at(deadline, Proxy::open(context, &first, Some(binding.clone())))
            .await
            .map_err(|_| Refusal::Timeout)?
            .map_err(|_| Refusal::NodeUnavailable)?;
    send(out, &identity, deadline).await?;
    send(out, &CustodyServerFrame::WebBinding { context: binding }, deadline).await?;

    for _ in 0..WEB_CUSTODY_FRAME_BUDGET {
        let bytes = receive(frames, deadline).await?;
        let frame: CustodyClientFrame =
            decode(&bytes, crate::web_ingress::WEB_PRE_SESSION_FRAME_MAX_BYTES)
                .map_err(|_| Refusal::BadFrame)?;
        if let CustodyClientFrame::GatewayHandoff { session_id } = &frame {
            let grant = proxy.handoff(session_id).map_err(|_| Refusal::AuthRefused)?;
            let first = receive(frames, deadline).await?;
            let first = ramflux_protocol::parse_i_json(&first).map_err(|_| Refusal::BadFrame)?;
            drop(proxy);
            return Ok(Handoff { grant, first });
        }
        if !permitted(&frame) {
            return Err(Refusal::AuthRefused);
        }
        let proving = if let CustodyClientFrame::Prove { proof, .. } = &frame {
            if proof.body.binding_mode != BindingMode::WebOriginBound
                || ramflux_node_core::now_unix_seconds() > context_expires_at
            {
                return Err(Refusal::ProofRefused);
            }
            true
        } else {
            false
        };
        let response = tokio::time::timeout_at(
            deadline,
            proxy.frame(context, frame, Some(observed.as_str()), capacity),
        )
        .await
        .map_err(|_| Refusal::Timeout)?
        .map_err(|_| Refusal::NodeUnavailable)?;
        match response {
            CustodyServerFrame::Refused {
                code:
                    CustodyRefusal::Busy
                    | CustodyRefusal::Capacity
                    | CustodyRefusal::CapacityRetryAfter { .. },
                ..
            } => return Err(Refusal::RateLimited),
            CustodyServerFrame::Refused { .. } => {
                return Err(if proving { Refusal::ProofRefused } else { Refusal::AuthRefused });
            }
            CustodyServerFrame::Challenge { .. }
            | CustodyServerFrame::SessionEstablished { .. }
            | CustodyServerFrame::Registered { .. } => {
                send(out, &response, deadline).await?;
            }
            _ => return Err(Refusal::AuthRefused),
        }
    }
    Err(Refusal::AuthRefused)
}

#[cfg(test)]
mod tests {
    use super::{Refusal, permitted};
    use crate::web_ingress::close::CloseCode;
    use ramflux_protocol::custody::{CustodyClientFrame, CustodyProofAction, DeviceRef};

    fn device() -> DeviceRef {
        DeviceRef {
            account_anchor: "anchor".to_owned(),
            device_id: "device".to_owned(),
            device_epoch: 1,
        }
    }

    #[test]
    fn proof_actions_outside_open_session_and_own_prekey_ops_are_refused_on_web_listener() {
        assert!(permitted(&CustodyClientFrame::Challenge {
            device_ref: device(),
            action: CustodyProofAction::OpenSession,
        }));
        assert!(permitted(&CustodyClientFrame::Challenge {
            device_ref: device(),
            action: CustodyProofAction::Register { prekey_bundle: serde_json::Value::Null },
        }));
        assert!(!permitted(&CustodyClientFrame::NodeIdentity { record_hash: None }));
        assert!(!permitted(&CustodyClientFrame::GatewayHandoff { session_id: "s".to_owned() }));
    }

    #[test]
    fn every_authentication_refusal_maps_to_the_same_close_code() {
        assert_eq!(Refusal::AuthRefused.close_code(), Some(CloseCode::AuthRefused));
        assert_eq!(Refusal::ProofRefused.close_code(), Some(CloseCode::AuthRefused));
        assert_eq!(Refusal::Closed.close_code(), None);
        assert_eq!(Refusal::Timeout.close_code(), Some(CloseCode::Timeout));
    }
}

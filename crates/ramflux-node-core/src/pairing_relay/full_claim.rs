// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed A3 dispatch under the real current-native owner; no signing authority is returned.
use super::{FullNativeAdmission, FullResumeProgress, PairingRelayError, PairingRelayStore};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        PROFILE,
        relay::{FullClaim, ResumePendingFull},
    },
};
use std::net::IpAddr;
use zeroize::Zeroizing;

/// Apply one original-byte decoded A3 request. The caller supplies current native state from
/// the node's own durable owner, then returns these exact bytes over the confidential mesh.
/// # Errors
/// Refuses stale native/lease state, unknown challenges, changed operands or bounded resources.
pub fn apply_full_claim(
    store: &mut PairingRelayStore,
    source: IpAddr,
    claim: &FullClaim,
    admission: &FullNativeAdmission<'_>,
) -> Result<Zeroizing<Vec<u8>>, PairingRelayError> {
    match claim {
        FullClaim::Hello(hello) => store
            .hello_full(source, hello, admission)?
            .to_wire_bytes()
            .map(Zeroizing::new)
            .map_err(|error| super::limits::wire(&error)),
        FullClaim::Discovery(poll) => store
            .poll_full_discovery(source, poll, admission)?
            .to_wire_bytes()
            .map(Zeroizing::new)
            .map_err(|error| super::limits::wire(&error)),
        FullClaim::Proof(proof) => match store.submit_full_resume(&proof.proof, admission)? {
            FullResumeProgress::Pending => ResumePendingFull {
                epoch: proof.proof.body.epoch.clone(),
                kind: "resume_pending_full".into(),
                lease_id: proof.proof.body.lease_id.clone(),
                profile: PROFILE.into(),
            }
            .encode_secret()
            .map_err(|error| super::limits::wire(&error)),
            FullResumeProgress::Ready(token) => token.encode_secret(),
        },
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual current-native owner shared by raw mesh adapters; never a caller-selected head/arm.
use super::{
    FullAdmittedReply, FullAuthorization, FullForwardClaim, FullMeshAdmit, FullMeshPermit,
    FullNativeAdmission, FullSendPermit, PairingRelayError, PairingRelayStore, apply_full_claim,
};
use crate::{MeshPeerIdentity, RouterCore};
use ramflux_crypto::custody::VerifiedNodeRecord;
use ramflux_protocol::custody::pairing::full_transfer::{lease::DataGrant, relay::FullClaim};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, PairingRelayError>;
/// The adapter supplies the actual mTLS peer. No network or bulk I/O occurs under native loans.
pub struct FullNativeRelay<'a> {
    node: &'a VerifiedNodeRecord,
    router: &'a RouterCore,
    store: Arc<Mutex<PairingRelayStore>>,
}
impl<'a> FullNativeRelay<'a> {
    #[must_use]
    pub fn new(
        node: &'a VerifiedNodeRecord,
        router: &'a RouterCore,
        store: Arc<Mutex<PairingRelayStore>>,
    ) -> Self {
        Self { node, router, store }
    }
    fn peer(peer: &MeshPeerIdentity) -> Result<()> {
        if peer.service_id == "ramflux-federation" {
            Ok(())
        } else {
            Err(PairingRelayError::WrongContext)
        }
    }
    fn store(&self) -> Result<std::sync::MutexGuard<'_, PairingRelayStore>> {
        self.store.lock().map_err(|_| PairingRelayError::WrongContext)
    }
    fn current<T>(
        &self,
        grant: &DataGrant,
        work: impl FnOnce(&mut PairingRelayStore, &FullNativeAdmission<'_>) -> Result<T>,
    ) -> Result<T> {
        let now = self.store()?.full_relay_now()?;
        self.router.with_current_pairing_authority(
            &grant.source_ref.account_anchor,
            now,
            |current| {
                let admission = FullNativeAdmission::for_current(self.node, current, grant);
                let mut store = self.store()?;
                work(&mut store, &admission)
            },
        )
    }
    /// # Errors
    /// Authenticates original signed leases/proofs before any current-account lookup.
    pub fn claim(
        &self,
        peer: &MeshPeerIdentity,
        source: IpAddr,
        claim: &FullClaim,
    ) -> Result<Zeroizing<Vec<u8>>> {
        Self::peer(peer)?;
        let grant = self.claim_grant(claim)?;
        self.current(&grant, |store, admission| apply_full_claim(store, source, claim, admission))
    }
    fn claim_grant(&self, claim: &FullClaim) -> Result<DataGrant> {
        let lease = match claim {
            FullClaim::Hello(value) => &value.lease,
            FullClaim::Discovery(value) => &value.lease,
            FullClaim::Proof(value) => return self.store()?.full_proof_grant(value),
        };
        let now = self.store()?.full_relay_now()?;
        ramflux_crypto::custody::pairing::verify_full_data_lease(
            lease,
            &lease.body.grant,
            self.node,
            now,
        )
        .map_err(|error| super::full_resume::crypto(&error))?;
        Ok(lease.body.grant.clone())
    }
    /// # Errors
    /// Refuses another service, malformed A2 scope, wrong token, stale native state or capacity.
    pub fn admit(
        &self,
        peer: &MeshPeerIdentity,
        request: &FullMeshAdmit,
    ) -> Result<FullMeshPermit> {
        Self::peer(peer)?;
        let original = Zeroizing::new(format!(
            "POST {} HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
            request.arm.public_path(),
            request.authorization.as_str()
        ));
        let auth = FullAuthorization::parse("POST", request.arm.public_path(), true, &original)?;
        let grant = self.store()?.full_authenticated_grant(&auth)?;
        self.current(&grant, |store, admission| store.admit_full_forward(request, peer, admission))
    }
    /// # Errors
    /// Reauthenticates the exact peer/permit/header before body allocation; mismatches do not
    /// consume somebody else's reservation. Uses the node's latest native head.
    pub fn take(&self, claim: &FullForwardClaim<'_>) -> Result<FullSendPermit> {
        Self::peer(claim.peer)?;
        let original = Zeroizing::new(format!(
            "POST {} HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
            claim.arm.public_path(),
            claim.authorization,
        ));
        let auth = FullAuthorization::parse("POST", claim.arm.public_path(), true, &original)?;
        let grant = self.store()?.full_authenticated_grant(&auth)?;
        self.current(&grant, |store, admission| store.take_full_forward(claim, admission))
    }
    /// # Errors
    /// Rechecks native state after exact complete-body scope validation and before enqueue.
    pub fn forward(
        &self,
        peer: &MeshPeerIdentity,
        permit: FullSendPermit,
        body: Vec<u8>,
    ) -> Result<FullAdmittedReply> {
        // Ensure early service/native failures erase the body while the permit remains owned.
        let mut body = Zeroizing::new(body);
        Self::peer(peer)?;
        let grant = self.store()?.full_permit_grant(&permit)?;
        self.current(&grant, |store, admission| {
            store.accept_full_forward(permit, std::mem::take(&mut *body), admission)
        })
    }
}

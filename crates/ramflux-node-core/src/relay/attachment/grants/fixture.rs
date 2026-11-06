// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Test-support authority fixture; never enabled by production service features.
#![allow(clippy::unwrap_used)]
use super::{
    AttachmentAuthority, AttachmentLedgerError, AttachmentOwner, RetirementOutcome,
    ScopedGrantRegistry, hex,
    test_support::{auth, auth_for_device, fixtures, owner_seed, signed},
};
use crate::{ObjectRelayCapability, RelayRedbStore};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::large_attachment::{
    AttachmentRetirement, QualifiedOwner, VerifiedAttachmentRetirement, VerifiedContentManifest,
    VerifiedScopedGrant,
};
pub struct RetirementFixture {
    pub store: RelayRedbStore,
    pub registry: ScopedGrantRegistry,
    pub native: VerifiedContentManifest,
    pub grant: VerifiedScopedGrant,
    pub now: u64,
    signer: SigningKey,
}
impl RetirementFixture {
    /// # Panics
    /// Panics on fixture I/O or invalid fixed signing material.
    #[must_use]
    pub fn new(path: &std::path::Path) -> Self {
        Self::new_at(path, 1_700_000_001)
    }
    /// # Panics
    /// Panics on invalid fixture setup. The supplied clock keeps replay startup deterministic.
    #[must_use]
    pub fn new_at(path: &std::path::Path, now: u64) -> Self {
        let (native, mut grant) = fixtures();
        if now != 1_700_000_001 {
            let mut current = grant.grant().clone();
            current.issued_at = now - 1;
            current.expires_at = now + 600;
            grant = signed(&current);
        }
        let store = RelayRedbStore::open_at(path, now).unwrap();
        let ledger = store.attachment_ledger(super::super::AttachmentPolicy::default()).unwrap();
        let upload = [21; 32];
        let owner =
            AttachmentOwner::from_authenticated_session(&native.manifest().owner.account_anchor)
                .unwrap();
        ledger
            .reserve(
                &owner,
                super::super::AttachmentReservationRequest {
                    upload_id: upload,
                    object_id: native.manifest().object_id,
                    layout: native.manifest().layout,
                },
                now - 1,
            )
            .unwrap();
        ledger.bind(&owner, &upload, &native, now - 1).unwrap();
        ledger.commit(&owner, &upload, now - 1).unwrap();
        let signer = SigningKey::from_bytes(&[77; 32]);
        let registry = ledger
            .scoped_grants(AttachmentAuthority {
                source: "node-a".into(),
                generation: 4,
                signing_public_key: signer.verifying_key().to_bytes(),
            })
            .unwrap();
        registry
            .register(&upload, &native, &grant, &auth(&native, &grant, now).context(), &signer)
            .unwrap();
        Self { store, registry, native, grant, now, signer }
    }
    /// # Panics
    /// Panics if valid fixture signing fails.
    #[must_use]
    pub fn request(&self) -> AttachmentRetirement {
        let g = self.grant.grant();
        AttachmentRetirement {
            reference_id: g.reference_id,
            grant_id: g.grant_id,
            grant_hash: g.hash().unwrap(),
            grant_epoch: g.epoch,
            source_authority: "node-a".into(),
            authority_generation: 4,
            operation_id: [99; 32],
            issued_at: self.now,
        }
    }
    /// # Panics
    /// Panics if fixed owner material is malformed.
    #[must_use]
    pub fn owner(&self) -> QualifiedOwner {
        self.grant.grant().owner.clone()
    }
    /// # Errors
    /// Returns the actual registry refusal.
    pub fn retire(
        &self,
        r: &AttachmentRetirement,
    ) -> Result<RetirementOutcome, AttachmentLedgerError> {
        self.retire_as(r, &self.owner(), owner_seed())
    }
    /// # Errors
    /// Returns current-owner authentication or registry refusals.
    /// # Panics
    /// Panics on malformed fixture signature material.
    pub fn retire_as(
        &self,
        r: &AttachmentRetirement,
        owner: &QualifiedOwner,
        seed: [u8; 32],
    ) -> Result<RetirementOutcome, AttachmentLedgerError> {
        let key = SigningKey::from_bytes(&seed);
        let sig = key.sign(&r.signing_bytes().unwrap()).to_bytes();
        let signed: VerifiedAttachmentRetirement = AttachmentRetirement::verify(
            &r.canonical_bytes().unwrap(),
            &sig,
            &key.verifying_key().to_bytes(),
        )
        .unwrap();
        let proof = auth_for_device(
            &self.native,
            self.now,
            ObjectRelayCapability::Tombstone,
            hex(blake3::hash(&r.signing_bytes().unwrap()).as_bytes()),
            owner,
            seed,
        );
        self.registry.retire(&signed, &proof.context())
    }
    /// # Panics
    /// Panics if registering the independent fixture grant fails.
    #[must_use]
    pub fn independent(&self, n: u8) -> VerifiedScopedGrant {
        let mut g = self.grant.grant().clone();
        g.grant_id = [n; 32];
        let g = signed(&g);
        self.registry
            .register(
                &[21; 32],
                &self.native,
                &g,
                &auth(&self.native, &g, self.now).context(),
                &self.signer,
            )
            .unwrap();
        g
    }
}

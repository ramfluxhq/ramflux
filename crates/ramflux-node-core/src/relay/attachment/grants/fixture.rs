// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Test-support authority fixture; never enabled by production service features.
#![allow(clippy::unwrap_used)]
use super::{
    AttachmentAuthority, AttachmentLedgerError, AttachmentOwner, RetirementOutcome,
    ScopedGrantRegistry, hex,
    test_support::{auth_for_device_at, fixtures_case, owner_seed, signed},
};
use crate::{ObjectRelayCapability, RelayRedbStore};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::large_attachment::{
    AttachmentRetirement, QualifiedOwner, ScopedAttachmentGrant, VerifiedAttachmentRetirement,
    VerifiedContentManifest, VerifiedScopedGrant,
};
pub struct RetirementFixture {
    pub store: RelayRedbStore,
    pub registry: ScopedGrantRegistry,
    pub native: VerifiedContentManifest,
    pub grant: VerifiedScopedGrant,
    pub now: u64,
    pub source: String,
    pub generation: u64,
    signer: SigningKey,
}
/// Which frozen case and source authority a fixture registers under.
#[derive(Debug, Clone)]
pub struct FixtureSpec {
    pub case: usize,
    pub source: String,
    pub generation: u64,
    pub signer_seed: [u8; 32],
}
impl Default for FixtureSpec {
    fn default() -> Self {
        Self { case: 0, source: "node-a".into(), generation: 4, signer_seed: [77; 32] }
    }
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
        Self::new_with(path, now, &FixtureSpec::default())
    }
    /// # Panics
    /// Panics on invalid fixture setup.
    #[must_use]
    pub fn new_with(path: &std::path::Path, now: u64, spec: &FixtureSpec) -> Self {
        let (native, mut grant) = fixtures_case(spec.case);
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
        ledger.commit(&owner, &upload, 1, now - 1).unwrap();
        let signer = SigningKey::from_bytes(&spec.signer_seed);
        let registry = ledger
            .scoped_grants(AttachmentAuthority {
                source: spec.source.clone(),
                generation: spec.generation,
                signing_public_key: signer.verifying_key().to_bytes(),
            })
            .unwrap();
        registry
            .register(
                &upload,
                &native,
                &grant,
                &aud(&native, &grant, now, &spec.source).context(),
                &signer,
            )
            .unwrap();
        Self {
            store,
            registry,
            native,
            grant,
            now,
            source: spec.source.clone(),
            generation: spec.generation,
            signer,
        }
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
            source_authority: self.source.clone(),
            authority_generation: self.generation,
            operation_id: [99; 32],
            issued_at: self.now,
        }
    }
    /// True while some thread holds the lease mutex (a retirement mid-flight).
    #[must_use]
    pub fn lease_mutex_held(&self) -> bool {
        self.registry.leases_held()
    }
    /// Holds the ledger's single write lock until the returned guard is dropped.
    /// # Panics
    /// Panics on storage failure.
    #[must_use]
    pub fn hold_ledger_writer(&self) -> redb::WriteTransaction {
        self.registry.ledger.db.begin_write().unwrap()
    }
    /// Rewrites the committed payload row's two generation fields independently.
    /// # Panics
    /// Panics on storage failure or a missing payload row.
    pub fn set_generations(&self, pending: u64, committed: Option<u64>) {
        let owner = AttachmentOwner::from_authenticated_session(
            &self.native.manifest().owner.account_anchor,
        )
        .unwrap();
        let tx = self.registry.ledger.db.begin_write().unwrap();
        {
            let mut rows = tx.open_table(super::RECORDS).unwrap();
            let k = super::key(&owner, &[21; 32]);
            let mut row: serde_json::Value = {
                let value = super::ReadableTable::get(&rows, k.as_slice()).unwrap().unwrap();
                serde_json::from_slice(value.value()).unwrap()
            };
            row["pending_generation"] = pending.into();
            row["committed_generation"] = committed.map_or(serde_json::Value::Null, Into::into);
            rows.insert(k.as_slice(), serde_json::to_vec(&row).unwrap().as_slice()).unwrap();
        }
        tx.commit().unwrap();
    }
    /// Legacy shape (pending 0, nothing committed) or the bound shape (1, Some(1)).
    pub fn set_legacy_zero(&self, legacy: bool) {
        if legacy {
            self.set_generations(0, None);
        } else {
            self.set_generations(1, Some(1));
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
        let proof = auth_for_device_at(
            &self.native,
            self.now,
            ObjectRelayCapability::Tombstone,
            hex(blake3::hash(&r.signing_bytes().unwrap()).as_bytes()),
            owner,
            seed,
            &self.source,
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
                &aud(&self.native, &g, self.now, &self.source).context(),
                &self.signer,
            )
            .unwrap();
        g
    }
    /// Registers a variant of the fixture grant (for example fewer rights).
    /// # Panics
    /// Panics if registering the edited fixture grant fails.
    #[must_use]
    pub fn register_edited(
        &self,
        edit: impl FnOnce(&mut ScopedAttachmentGrant),
    ) -> VerifiedScopedGrant {
        let mut g = self.grant.grant().clone();
        edit(&mut g);
        let g = signed(&g);
        self.registry
            .register(
                &[21; 32],
                &self.native,
                &g,
                &aud(&self.native, &g, self.now, &self.source).context(),
                &self.signer,
            )
            .unwrap();
        g
    }
    /// The source authority signing key the fixture registered under.
    #[must_use]
    pub fn source_signer(&self) -> SigningKey {
        self.signer.clone()
    }
}

fn aud(
    native: &VerifiedContentManifest,
    grant: &VerifiedScopedGrant,
    now: u64,
    source: &str,
) -> super::test_support::Auth {
    auth_for_device_at(
        native,
        now,
        ObjectRelayCapability::Put,
        hex(&grant.grant().hash().unwrap()),
        &native.manifest().owner,
        owner_seed(),
        source,
    )
}

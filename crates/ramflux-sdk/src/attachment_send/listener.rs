// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test listener. Owner admission, registration, and ranged read use the relay ledger.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use ramflux_node_core::backend::AttachmentBackend;
use ramflux_node_core::{
    AttachmentAuthority, AttachmentLedgerError, AttachmentPolicy, AttachmentReplayProof,
    OwnerAdmission, OwnerAdmissionError, RelayRedbStore,
};
use ramflux_protocol::large_attachment::{
    AttachmentRegistrationReceipt, AttachmentRetirement, ContentManifest, OwnerAttachmentOperation,
    QualifiedOwner, ScopedAttachmentGrant,
};

use super::codes::{
    CODE_AUTHORITY_UNAVAILABLE, CODE_EXPIRED, CODE_NOT_GRANTEE, CODE_QUOTA_EXCEEDED,
    CODE_UPLOAD_REJECTED, Refusal,
};
use super::plane::{OwnerCall, Plane, ReadCall, RegisterCall, RetireCall};

pub(super) const NOW: u64 = 2_000_000_000;

pub(super) struct Listener {
    registry: ramflux_node_core::ScopedGrantRegistry,
    backend: ramflux_node_core::backend::LocalAttachmentBackend,
    requester: QualifiedOwner,
    authority: SigningKey,
    now: u64,
    reserves: AtomicU64,
    reads: AtomicU64,
    retires: AtomicU64,
    unreachable: std::sync::atomic::AtomicBool,
    reader: Mutex<QualifiedOwner>,
    manifests: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl Listener {
    pub(super) fn open(dir: &Path, requester: QualifiedOwner) -> Result<Self, String> {
        let store =
            RelayRedbStore::open(dir.join("relay.redb")).map_err(|error| error.to_string())?;
        let authority = SigningKey::from_bytes(&[77; 32]);
        let registry = store
            .attachment_ledger(AttachmentPolicy::default())
            .map_err(|error| error.to_string())?
            .scoped_grants(AttachmentAuthority {
                source: "node-a".into(),
                generation: 4,
                signing_public_key: authority.verifying_key().to_bytes(),
            })
            .map_err(|error| error.to_string())?;
        let backend = store
            .local_attachment_backend([1; 32], dir.join("objects"))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            registry,
            backend,
            reader: Mutex::new(requester.clone()),
            requester,
            authority,
            now: NOW,
            reserves: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            retires: AtomicU64::new(0),
            unreachable: std::sync::atomic::AtomicBool::new(false),
            manifests: Mutex::new(HashMap::new()),
        })
    }

    pub(super) fn set_reader(&self, reader: QualifiedOwner) {
        *self.reader.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = reader;
    }

    pub(super) fn reserves(&self) -> u64 {
        self.reserves.load(Ordering::Relaxed)
    }

    pub(super) fn retires(&self) -> u64 {
        self.retires.load(Ordering::Relaxed)
    }

    /// Simulates a relay that cannot be reached; later calls succeed again after `false`.
    pub(super) fn set_unreachable(&self, down: bool) {
        self.unreachable.store(down, Ordering::Relaxed);
    }

    pub(super) fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    fn now(&self) -> u64 {
        self.now
    }
}

impl Plane for Listener {
    fn owner(&self, call: &OwnerCall<'_>) -> Result<Vec<u8>, Refusal> {
        if OwnerAttachmentOperation::decode(call.operation).is_ok_and(|op| op.op == 9) {
            self.reserves.fetch_add(1, Ordering::Relaxed);
        }
        let admitted = self.registry.admit_owner_operation_after_authentication(
            &OwnerAdmission {
                operation: call.operation,
                body: call.body,
                proof: call.proof,
                proof_signature: call.signature,
                requester: &self.requester,
                now: self.now(),
            },
            &self.backend,
        );
        match admitted {
            Ok(bytes) => Ok(bytes),
            Err(OwnerAdmissionError::Ledger(AttachmentLedgerError::AccountQuotaExceeded {
                ..
            })) => Err(Refusal::new(CODE_QUOTA_EXCEEDED)),
            Err(OwnerAdmissionError::Ledger(AttachmentLedgerError::Expired)) => {
                Err(Refusal::new(CODE_EXPIRED))
            }
            Err(_) => Err(Refusal::new(CODE_UPLOAD_REJECTED)),
        }
    }

    fn register(&self, call: &RegisterCall<'_>) -> Result<Vec<u8>, Refusal> {
        let native = ContentManifest::decode_signed(call.manifest)
            .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        let grant = ScopedAttachmentGrant::decode_signed(call.grant)
            .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        let registered = self
            .registry
            .register_attested(
                &self.requester,
                call.upload_id,
                &native,
                &grant,
                &self.authority,
                self.now(),
            )
            .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        let raw = ramflux_protocol::decode_base64url(&registered.capability)
            .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        self.manifests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(native.manifest().object_id, call.manifest.to_vec());
        Ok(raw)
    }

    fn read(&self, call: &ReadCall<'_>) -> Result<Vec<u8>, Refusal> {
        let key = self.authority.verifying_key().to_bytes();
        let (grant, _) = AttachmentRegistrationReceipt::decode_capability(
            call.capability,
            "node-a",
            4,
            &key,
            self.now(),
        )
        .map_err(|_| Refusal::new(CODE_NOT_GRANTEE))?;
        let reader = self.reader.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        let proof = AttachmentReplayProof {
            nonce,
            issued_at: self.now(),
            expires_at: self.now().saturating_add(30),
        };
        if self
            .registry
            .admit_reader_after_authentication(&reader, &grant, 1, &proof, self.now())
            .is_err()
        {
            return Err(Refusal::new(CODE_NOT_GRANTEE));
        }
        let stored = self
            .manifests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(call.object_id)
            .cloned()
            .ok_or(Refusal::new(CODE_UPLOAD_REJECTED))?;
        let native = ContentManifest::decode_signed(&stored)
            .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        let index = u32::try_from(call.index).map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        let spec = ramflux_node_core::backend::BackendSegment::from_manifest(&native, 1, index)
            .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        let mut output = Vec::new();
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.backend
            .read_range(&spec, call.offset, call.length, &mut output)
            .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        Ok(output)
    }

    fn retire(&self, call: &RetireCall<'_>) -> Result<Vec<u8>, Refusal> {
        if self.unreachable.load(Ordering::Relaxed) {
            return Err(Refusal::new(CODE_AUTHORITY_UNAVAILABLE));
        }
        let signed = AttachmentRetirement::verify(
            call.retirement,
            call.signature,
            &self.requester.signing_public_key,
        )
        .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        let outcome = self
            .registry
            .retire_attested(&self.requester, &signed, self.now())
            .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        self.retires.fetch_add(1, Ordering::Relaxed);
        let retired = matches!(outcome, ramflux_node_core::RetirementOutcome::Retired);
        let erased = retired
            && self
                .registry
                .erase_unreferenced(&signed.request().grant_id, &self.backend)
                .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
        serde_json::to_vec(&serde_json::json!({
            "state": if retired { "retired" } else { "pending" },
            "object_erased": erased,
        }))
        .map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))
    }
}

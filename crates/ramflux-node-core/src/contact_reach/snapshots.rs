// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private, process-only encrypted snapshot leases; restart can never restore a lease.
use super::{ReachOwner, Result, refuse, storage};
use crate::{MigrationNode, RouterRedbStore};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::Signer;
use ramflux_protocol::{
    contact_reach::{
        MAX_STATE_BYTES, OperationResult, Reason, STATE_DOMAIN, STATE_PAGES_DOMAIN, StateManifest,
        StatePage, decode, state_hash,
    },
    custody::{self, Envelope as Signed},
};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Clone, Copy)]
pub(super) struct SnapshotRead<'a> {
    pub owner: ReachOwner<'a>,
    pub session: &'a str,
    pub known: u64,
    pub id: Option<&'a str>,
    pub page: u64,
    pub now: u64,
    pub proof: Option<&'a str>,
}
#[derive(Clone, Copy)]
struct LeaseContext<'a> {
    owner: ReachOwner<'a>,
    session: &'a str,
    home_hash: &'a str,
    authority_hash: &'a str,
    now: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    pages: Vec<StatePage>,
}
const MAX_IMAGE_BYTES: usize = MAX_STATE_BYTES;
struct Lease {
    manifest: Signed<StateManifest>,
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    session: String,
    provenance: ramflux_crypto::contact_reach::EncryptedProvenanceStage,
}
pub(super) struct Snapshots {
    key: zeroize::Zeroizing<[u8; 32]>,
    leases: Mutex<BTreeMap<String, Vec<Lease>>>,
}
impl Snapshots {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            key: zeroize::Zeroizing::new(ramflux_crypto::random_32()?),
            leases: Mutex::new(BTreeMap::new()),
        })
    }
    pub(super) fn read(
        &self,
        store: &RouterRedbStore,
        node: &MigrationNode,
        request: SnapshotRead<'_>,
    ) -> Result<OperationResult> {
        let SnapshotRead { owner, session, known, id, page, now, proof } = request;
        let mut leases = self.leases.lock().map_err(storage)?;
        let (tx, now) = store.begin_reach_write(now)?;
        let authority = super::store::authority(&tx, owner.recipient_root, now)?;
        super::store::authorize_read(&authority, owner.actor, now)
            .map_err(|_| refuse(Reason::ForeignReadRefused))?;
        let home = super::store::home(&tx, owner.recipient_root)?;
        if home.record.home() != (node.node_id(), node.public_key()) {
            return Err(refuse(if proof.is_some() {
                Reason::ForeignReadRefused
            } else {
                Reason::HomeRollback
            }));
        }
        let state = super::store::load_mirror(&tx, owner.recipient_root)?;
        if state.revision < known {
            return Err(refuse(Reason::HomeRollback));
        }
        let provenance = if id.is_none() {
            Some(super::store::provenance::index(&tx, owner.recipient_root, &state)?)
        } else {
            None
        };
        // The clock fence commits before a lease becomes visible; no state record is rewritten.
        tx.commit()?;
        leases.retain(|_, v| {
            v.retain(|l| l.manifest.body.expires_at > now);
            !v.is_empty()
        });
        if id.is_none() {
            if page != 0 {
                return Err(refuse(Reason::ForeignInvalidFrame));
            }
            if !leases.contains_key(owner.recipient_root) && leases.len() >= 1024 {
                return Err(refuse(Reason::ForeignCapacity));
            }
            let account = leases.entry(owner.recipient_root.into()).or_default();
            if account.len() >= 2 {
                return Err(refuse(Reason::ForeignCapacity));
            }
            let used = account.iter().try_fold(0_usize, |total, lease| {
                total
                    .checked_add(lease.staged_bytes()?)
                    .ok_or_else(|| refuse(Reason::ForeignCapacity))
            })?;
            let available = ramflux_protocol::contact_reach::MAX_REACH_STAGING_BYTES
                .checked_sub(used)
                .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
            let lease = self.new_lease(
                (store, available),
                node,
                &state,
                provenance.ok_or_else(|| refuse(Reason::CustodyRefused))?,
                LeaseContext {
                    owner,
                    session,
                    home_hash: &ramflux_protocol::home_migration::record_hash(&home.record)?,
                    authority_hash: &custody::object_hash(authority.envelope())?,
                    now,
                },
            )?;
            let bytes = account.iter().try_fold(lease.staged_bytes()?, |total, lease| {
                total
                    .checked_add(lease.staged_bytes()?)
                    .ok_or_else(|| refuse(Reason::ForeignCapacity))
            })?;
            if bytes > ramflux_protocol::contact_reach::MAX_REACH_STAGING_BYTES {
                return Err(refuse(Reason::ForeignCapacity));
            }
            account.push(lease);
        }
        let account = leases
            .get(owner.recipient_root)
            .ok_or_else(|| refuse(Reason::ForeignSnapshotExpired))?;
        let lease = if let Some(id) = id {
            account.iter().find(|l| l.manifest.body.snapshot_id == id)
        } else {
            account.last()
        }
        .ok_or_else(|| refuse(Reason::ForeignSnapshotExpired))?;
        if lease.session != session || &lease.manifest.body.requesting_device != owner.actor {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        lease.response(page, proof, self.key.as_ref())
    }

    fn new_lease(
        &self,
        resource: (&RouterRedbStore, usize),
        node: &MigrationNode,
        state: &super::AccountReach,
        index: super::store::provenance::ProvenanceIndex,
        context: LeaseContext<'_>,
    ) -> Result<Lease> {
        let LeaseContext { owner, session, now, .. } = context;
        let snapshot_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let records = state.records()?;
        let pages = pages::pack(&records, &snapshot_id, index.signers())?;
        // Reserve bounded working buffers before staging any proof ciphertext. This keeps
        // existing leases readable while a second snapshot is being built.
        let reserved = super::store::encoded(&pages)?
            .len()
            .checked_add(3 * MAX_STATE_BYTES + 4096 + session.len() + 28)
            .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        let capacity =
            resource.1.checked_sub(reserved).ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        let provenance = super::store::provenance::stage(resource.0, index, &records, capacity)?;
        let body = StateManifest {
            version: 1,
            account_anchor: owner.recipient_root.into(),
            requesting_device: owner.actor.clone(),
            home_head_hash: context.home_hash.into(),
            authority_head_hash: context.authority_hash.into(),
            revision: state.revision,
            policy_revision: state.policy_revision(),
            admission_revision: state.admission_revision,
            snapshot_id,
            page_count: u64::try_from(pages.len()).map_err(storage)?,
            record_count: u64::try_from(records.len()).map_err(storage)?,
            pages_hash: custody::framed_hash(STATE_PAGES_DOMAIN, &pages)?,
            state_hash: state_hash(
                owner.recipient_root,
                state.revision,
                state.policy_revision(),
                state.admission_revision,
                &records,
            )?,
            provenance_hash: provenance.identity().hash.clone(),
            provenance_count: provenance.identity().count,
            provenance_bytes: provenance.identity().bytes,
            issued_at: now,
            expires_at: now.checked_add(60).ok_or_else(|| refuse(Reason::ForeignUnavailable))?,
        };
        body.validate()?;
        let signature = ramflux_protocol::encode_base64url(
            node.key.sign(&custody::signing_bytes(STATE_DOMAIN, &body)?).to_bytes(),
        );
        let manifest = Signed { body, signature };
        if super::store::encoded(&manifest)?.len() > 4096 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        if super::store::encoded(&pages)?.len() > MAX_STATE_BYTES {
            return Err(refuse(Reason::ForeignCapacity));
        }
        provenance.verify_manifest(&manifest.body)?;
        drop(ramflux_protocol::contact_reach::verify_pages(&manifest.body, &pages)?);
        let plaintext = zeroize::Zeroizing::new(super::store::encoded(&Image { pages })?);
        if plaintext.len() > MAX_IMAGE_BYTES {
            return Err(refuse(Reason::ForeignCapacity));
        }
        let mut nonce = [0_u8; 12];
        for (out, input) in nonce.iter_mut().zip(ramflux_crypto::random_32()?.iter()) {
            *out = *input;
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(storage)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: &plaintext, aad: manifest.body.snapshot_id.as_bytes() },
            )
            .map_err(|_| refuse(Reason::ForeignUnavailable))?;
        Ok(Lease { manifest, ciphertext, nonce, session: session.into(), provenance })
    }
}

impl Lease {
    fn response(&self, page: u64, proof: Option<&str>, key: &[u8]) -> Result<OperationResult> {
        if let Some(hash) = proof {
            if !self.provenance.proof_hashes().any(|member| member == hash) {
                return Err(refuse(Reason::ForeignSnapshotInvalid));
            }
            let selected = self
                .provenance
                .read_proof(hash)
                .map_err(|_| refuse(Reason::ForeignSnapshotInvalid))?;
            let result = OperationResult::ReachProvenance {
                manifest: self.manifest.clone(),
                proof_hash: selected.proof_hash,
                authority: Box::new(selected.authority),
                custodian_history: selected.custodian_history,
            };
            if super::store::encoded(&result)?.len() + 1024
                > ramflux_protocol::contact_reach::MAX_REPLY_BYTES
            {
                return Err(refuse(Reason::ForeignCapacity));
            }
            return Ok(result);
        }
        let image = self.image(key)?;
        let page = image
            .pages
            .get(usize::try_from(page).map_err(storage)?)
            .ok_or_else(|| refuse(Reason::ForeignInvalidFrame))?
            .clone();
        Ok(OperationResult::ReachState { manifest: self.manifest.clone(), page })
    }

    fn staged_bytes(&self) -> Result<usize> {
        let metadata = super::store::encoded(&self.manifest)?
            .len()
            .checked_add(self.session.len() + 12)
            .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        self.provenance
            .staged_bytes()
            .checked_add(self.ciphertext.len())
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or_else(|| refuse(Reason::ForeignCapacity))
    }
    fn image(&self, key: &[u8]) -> Result<Image> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(storage)?;
        let bytes = zeroize::Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: self.manifest.body.snapshot_id.as_bytes(),
                    },
                )
                .map_err(|_| refuse(Reason::ForeignUnavailable))?,
        );
        Ok(decode(&bytes, MAX_IMAGE_BYTES)?)
    }
}

mod pages;

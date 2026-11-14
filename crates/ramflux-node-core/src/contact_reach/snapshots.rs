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
    provenance: ramflux_protocol::contact_reach::Provenance,
}
const MAX_IMAGE_BYTES: usize =
    MAX_STATE_BYTES + ramflux_protocol::contact_reach::MAX_PROVENANCE_BYTES;
struct Lease {
    manifest: Signed<StateManifest>,
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    session: String,
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
        let tx = store.begin_write()?;
        let now = super::store::clock(&tx, now)?;
        let authority = super::store::authority(&tx, owner.recipient_root, now)?;
        super::store::authorize_read(&authority, owner.actor, now)?;
        let home = super::store::home(&tx, owner.recipient_root)?;
        if home.record.home() != (node.node_id(), node.public_key()) {
            return Err(refuse(Reason::HomeRollback));
        }
        let state = super::store::load(&tx, owner.recipient_root)?;
        if state.revision < known {
            return Err(refuse(Reason::HomeRollback));
        }
        let provenance = if id.is_none() {
            Some(super::store::provenance::catalogue(&tx, owner.recipient_root, &state)?)
        } else {
            None
        };
        // The clock fence commits before a lease becomes visible; no state record is rewritten.
        tx.commit()?;
        let mut leases = self.leases.lock().map_err(storage)?;
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
            account.push(self.new_lease(
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
            )?);
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
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(storage)?;
        let bytes = zeroize::Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&lease.nonce),
                    Payload {
                        msg: &lease.ciphertext,
                        aad: lease.manifest.body.snapshot_id.as_bytes(),
                    },
                )
                .map_err(|_| refuse(Reason::ForeignUnavailable))?,
        );
        let image: Image = decode(&bytes, MAX_IMAGE_BYTES)?;
        if let Some(hash) = proof {
            let selected = image
                .provenance
                .authorities
                .into_iter()
                .find(|entry| entry.proof_hash == hash)
                .ok_or_else(|| refuse(Reason::ForeignSnapshotInvalid))?;
            let result = OperationResult::ReachProvenance {
                manifest: lease.manifest.clone(),
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
        let page = image
            .pages
            .get(usize::try_from(page).map_err(storage)?)
            .ok_or_else(|| refuse(Reason::ForeignInvalidFrame))?
            .clone();
        Ok(OperationResult::ReachState { manifest: lease.manifest.clone(), page })
    }
    fn new_lease(
        &self,
        node: &MigrationNode,
        state: &super::AccountReach,
        provenance: ramflux_protocol::contact_reach::Provenance,
        context: LeaseContext<'_>,
    ) -> Result<Lease> {
        let LeaseContext { owner, session, now, .. } = context;
        let snapshot_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let records = state.records()?;
        let mut pages = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for (index, chunk) in records.chunks(32).enumerate() {
            let value = StatePage {
                version: 1,
                snapshot_id: snapshot_id.clone(),
                page: u64::try_from(index).map_err(storage)?,
                records: chunk.to_vec(),
                signers: {
                    let mut selected = Vec::new();
                    for record in chunk {
                        for reference in ramflux_protocol::contact_reach::record_signers(record)? {
                            if seen.insert((reference.object_kind, reference.object_hash.clone())) {
                                selected.push(
                                    provenance
                                        .signers
                                        .iter()
                                        .find(|entry| {
                                            entry.object_kind == reference.object_kind
                                                && entry.object_hash == reference.object_hash
                                        })
                                        .ok_or_else(|| refuse(Reason::CustodyRefused))?
                                        .clone(),
                                );
                            }
                        }
                    }
                    selected.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
                    selected
                },
            };
            if super::store::encoded(&value)?.len() > 1024 * 1024 {
                return Err(refuse(Reason::ForeignCapacity));
            }
            pages.push(value);
        }
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
            provenance_hash: custody::framed_hash(
                ramflux_protocol::contact_reach::STATE_CONTENT_DOMAIN,
                &provenance,
            )?,
            provenance_count: u64::try_from(provenance.authorities.len()).map_err(storage)?,
            provenance_bytes: u64::try_from(super::store::encoded(&provenance)?.len())
                .map_err(storage)?,
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
        provenance.verify(&manifest.body, &pages)?;
        let plaintext =
            zeroize::Zeroizing::new(super::store::encoded(&Image { pages, provenance })?);
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
        Ok(Lease { manifest, ciphertext, nonce, session: session.into() })
    }
}

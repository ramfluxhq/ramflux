// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local records and signed intents pin exact originals; encrypted read stages own separate copies.
use super::{SavedReachState, provenance::store_error, refused};
use crate::SdkError;
use ramflux_protocol::contact_reach::{
    self as wire, Operation, Reason, SignerReference, StateRecord,
};
use ramflux_storage::AccountDb;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Pins(BTreeMap<(wire::ObjectKind, String), SignerReference>);
impl Pins {
    pub(super) fn retained_admission(
        &mut self,
        db: &AccountDb,
        hash: &str,
    ) -> Result<(), SdkError> {
        let mut reference = db
            .reach_provenance_reference(wire::ObjectKind::Admission, hash)
            .map_err(store_error)?
            .ok_or_else(|| refused(Reason::CustodyRefused))?;
        reference.proof_hash.clear();
        self.insert(reference)
    }

    pub(super) fn record(&mut self, record: &StateRecord) -> Result<(), SdkError> {
        for reference in wire::record_signers(record)? {
            self.insert(reference)?;
        }
        Ok(())
    }
    fn insert(&mut self, reference: SignerReference) -> Result<(), SdkError> {
        let key = (reference.object_kind, reference.object_hash.clone());
        if let Some(old) = self.0.get(&key)
            && old != &reference
        {
            return Err(refused(Reason::CustodyRefused));
        }
        self.0.insert(key, reference);
        if self.0.len() > wire::MAX_SIGNER_REFERENCES {
            return Err(refused(Reason::ForeignCapacity));
        }
        Ok(())
    }
    pub(super) fn roster(&mut self, roster: &wire::GroupRoster) -> Result<(), SdkError> {
        let body = &roster.header.body;
        self.insert(SignerReference {
            object_kind: wire::ObjectKind::GroupRoster,
            object_hash: ramflux_protocol::custody::framed_hash(
                wire::OPERATION_HASH_DOMAIN,
                &roster.header,
            )?,
            authority_head_hash: body.authority_head_hash.clone(),
            master_certificate_hash: body.master_certificate_hash.clone(),
            proof_hash: String::new(),
        })
    }
    pub(super) fn operation(&mut self, operation: &Operation) -> Result<(), SdkError> {
        match operation {
            Operation::Policy { update } => self.record(&StateRecord::Policy {
                revision: update.body.revision,
                update: update.clone(),
            }),
            Operation::Admission { update, .. }
            | Operation::Start { update, .. }
            | Operation::Reply { update, .. } => self.record(&StateRecord::AdmissionMeta {
                revision: update.body.expected_revision,
                last_update: Some(update.clone()),
            }),
            Operation::GroupRoster { roster, .. } => self.roster(roster),
            _ => Err(refused(Reason::ForeignInvalidFrame)),
        }
    }
}

pub(super) fn visit<T: serde::de::DeserializeOwned>(
    db: &AccountDb,
    prefix: &str,
    mut visit: impl FnMut(T) -> Result<(), SdkError>,
) -> Result<(), SdkError> {
    let mut after = String::new();
    let mut count = 0;
    loop {
        let keys = db.actor_state_key_page_after(prefix, &after, 128)?;
        if keys.is_empty() {
            return Ok(());
        }
        for key in keys {
            count += 1;
            // One queue may hold a checkpoint and both the active and coalesced operation.
            if count > 1024 {
                return Err(refused(Reason::ForeignCapacity));
            }
            visit(
                db.load_bounded_actor_state(&key, 3 * wire::MAX_FRAME_BYTES + 4096)
                    .map_err(store_error)?
                    .ok_or_else(|| refused(Reason::CustodyRefused))?,
            )?;
            after = key;
        }
    }
}

pub(super) fn collect(db: &AccountDb, saved: &SavedReachState) -> Result<(), SdkError> {
    // An unverified import can contain additional denials. It is never a deletion authority.
    if db.actor_state_exists(super::restore::KEY)? {
        return Ok(());
    }
    let mut pins = Pins::default();
    for record in saved.records.iter().chain(saved.restrictions.values()) {
        pins.record(record)?;
    }
    super::group_join::pin_originals(db, &mut pins)?;
    super::group_kick::pin_originals(db, &mut pins)?;
    super::group_roster::pin_originals(db, &mut pins)?;
    let mut live = Vec::with_capacity(pins.0.len());
    for selector in pins.0.into_values() {
        let reference = db
            .reach_provenance_reference(selector.object_kind, &selector.object_hash)
            .map_err(store_error)?
            .ok_or_else(|| refused(Reason::CustodyRefused))?;
        if selector.authority_head_hash != reference.authority_head_hash
            || selector.master_certificate_hash != reference.master_certificate_hash
        {
            return Err(refused(Reason::CustodyRefused));
        }
        live.push(reference);
    }
    db.collect_reach_provenance(&saved.root, &live).map_err(store_error)
}

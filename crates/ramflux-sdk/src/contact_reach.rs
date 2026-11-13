// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified recipient state. A home signature cannot manufacture friendship or positive grants.
use crate::SdkError;
use ramflux_crypto::{contact_reach as crypto, custody::VerifiedRecord};
use ramflux_protocol::{
    contact_reach::*,
    custody::{self, Envelope as Signed},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn refused(reason: Reason) -> SdkError {
    SdkError::ReachRefused(reason)
}
/// A completely verified home mirror, suitable for one atomic local projection.
pub struct VerifiedReachState {
    pub(crate) manifest: StateManifest,
    pub(crate) records: Vec<StateRecord>,
}
/// Independently pinned state-read context; none of these facts comes from the manifest itself.
pub struct ReachReadContext<'a> {
    pub authority: &'a VerifiedRecord,
    pub device: &'a custody::DeviceRef,
    pub home_head_hash: &'a str,
    pub home_node_key: &'a str,
    pub minimum_revision: u64,
    pub now: u64,
}
impl VerifiedReachState {
    /// Verify all pages, audience, lease and every embedded original account signature.
    /// # Errors
    /// Refuses partial state, rollback, home-forged grants, mismatched placements and unsafe records.
    pub fn verify(
        manifest: &Signed<StateManifest>,
        pages: &[StatePage],
        context: ReachReadContext<'_>,
    ) -> Result<Self, SdkError> {
        let b = &manifest.body;
        let root = &context.authority.envelope().body.account_anchor;
        b.validate()?;
        check_submission_time(b.issued_at, b.expires_at, context.now)?;
        if &b.account_anchor != root
            || &b.requesting_device != context.device
            || b.home_head_hash != context.home_head_hash
            || b.revision < context.minimum_revision
            || b.authority_head_hash != custody::object_hash(context.authority.envelope())?
        {
            return Err(refused(Reason::HomeRollback));
        }
        context.authority.authorize(context.device, "sync", context.now)?;
        ramflux_crypto::verify_canonical_signature(
            &custody::signing_bytes(STATE_DOMAIN, b)?,
            &manifest.signature,
            context.home_node_key,
        )?;
        let records = verify_pages(b, pages)?;
        let mut bases = BTreeMap::new();
        let mut friendship = BTreeSet::new();
        for record in &records {
            match record {
                StateRecord::Policy { update, .. } => {
                    crypto::verify_retained_policy(update, context.authority, context.now)?;
                    bases.insert(custody::framed_hash(OPERATION_HASH_DOMAIN, update)?, record);
                }
                StateRecord::AdmissionMeta { revision, last_update } => {
                    if (*revision == 0) != last_update.is_none() {
                        return Err(refused(Reason::ForeignSnapshotInvalid));
                    }
                    if let Some(update) = last_update {
                        crypto::verify_retained_admission(update, context.authority, context.now)?;
                        if update.body.expected_revision.checked_add(1) != Some(*revision) {
                            return Err(refused(Reason::ForeignSnapshotInvalid));
                        }
                    }
                }
                StateRecord::Grant { subject, permissions, grant_until, update } => {
                    crypto::verify_retained_admission(update, context.authority, context.now)?;
                    if &update.body.subject != subject
                        || update.body.decision != Decision::Allow
                        || update.body.permissions != Some(*permissions)
                        || update.body.grant_until != Some(*grant_until)
                        || update.body.expected_revision >= b.admission_revision
                    {
                        return Err(refused(Reason::ForeignSnapshotInvalid));
                    }
                    if let Subject::Friendship { root } = subject {
                        friendship.insert(root.as_str());
                    }
                    bases.insert(custody::framed_hash(OPERATION_HASH_DOMAIN, update)?, record);
                }
                StateRecord::Block { subject, update } => {
                    crypto::verify_retained_admission(update, context.authority, context.now)?;
                    if &update.body.subject != subject || update.body.decision != Decision::Block {
                        return Err(refused(Reason::ForeignSnapshotInvalid));
                    }
                }
                StateRecord::Decline { root, until, update } => {
                    crypto::verify_retained_admission(update, context.authority, context.now)?;
                    if update.body.subject != (Subject::Friendship { root: root.clone() })
                        || update.body.decision != Decision::Decline
                        || *until < update.body.issued_at
                        || *until > ramflux_protocol::MAX_SAFE_JSON_INTEGER
                    {
                        return Err(refused(Reason::ForeignSnapshotInvalid));
                    }
                }
                StateRecord::Retirement { subject, revision, update } => {
                    crypto::verify_retained_admission(update, context.authority, context.now)?;
                    if &update.body.subject != subject
                        || update.body.decision == Decision::Allow
                        || update.body.expected_revision.checked_add(1) != Some(*revision)
                        || *revision > b.admission_revision
                    {
                        return Err(refused(Reason::ForeignSnapshotInvalid));
                    }
                }
                _ => {}
            }
        }
        for record in &records {
            if let StateRecord::Placement {
                conversation_id,
                revision,
                placement,
                relationship,
                basis,
                ..
            } = record
            {
                if *revision > b.revision
                    || basis.is_empty()
                    || basis.len() > 2
                    || basis.iter().any(|hash| !bases.contains_key(hash))
                {
                    return Err(refused(Reason::ForeignSnapshotInvalid));
                }
                let accepted = basis.iter().any(|hash| matches!(bases.get(hash),Some(StateRecord::Grant { subject:Subject::Friendship { root },.. }) if friendship.contains(root.as_str())));
                let conversation = basis.iter().any(|hash| matches!(bases.get(hash),Some(StateRecord::Grant { subject:Subject::Conversation { conversation_id:id,.. },.. }) if id == conversation_id));
                let open = basis.iter().any(|hash| matches!(bases.get(hash),Some(StateRecord::Policy { update,.. }) if update.body.mode == ReachMode::Open));
                if *relationship == Relationship::Accepted && !accepted
                    || *placement == Placement::Direct && !accepted && !open
                    || *placement == Placement::Strangers
                        && !accepted
                        && !conversation
                        && !basis
                            .iter()
                            .any(|h| matches!(bases.get(h), Some(StateRecord::Policy { .. })))
                {
                    return Err(refused(Reason::ForeignSnapshotInvalid));
                }
            }
        }
        Ok(Self { manifest: b.clone(), records })
    }
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.manifest.revision
    }
    #[must_use]
    pub fn state_hash(&self) -> &str {
        &self.manifest.state_hash
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedReachState {
    root: String,
    revision: u64,
    state_hash: String,
    records: Vec<StateRecord>,
    restrictions: BTreeMap<String, StateRecord>,
    conflict: bool,
}
impl crate::RamfluxClient {
    /// Install verified state and independent restrictive floors in one account writer commit.
    /// This read does not bootstrap message/SelfSync erase floors or authorize new-device publication.
    /// # Errors
    /// Refuses account mismatch and rollback; an equal-revision content conflict is durably fenced.
    pub fn install_reach_state(&self, verified: VerifiedReachState) -> Result<(), SdkError> {
        let own = self.owned_device_identity()?;
        if own.root_commitment() != verified.manifest.account_anchor {
            return Err(refused(Reason::AnchorMismatch));
        }
        let db = self.account_db()?;
        db.surface_transaction(|| {
            let previous: Option<SavedReachState> =
                db.client_record("reach", "state")?.map(serde_json::from_value).transpose()?;
            if let Some(saved) = &previous {
                if saved.conflict || verified.manifest.revision < saved.revision {
                    return Err(refused(Reason::HomeRollback));
                }
                if verified.manifest.revision == saved.revision {
                    if verified.manifest.state_hash == saved.state_hash {
                        return Ok(());
                    }
                    let mut fenced = saved.clone();
                    fenced.conflict = true;
                    db.persist_client_record("reach", "state", &serde_json::to_value(fenced)?)?;
                    // Return after commit below; a callback error would roll the restrictive fence back.
                    return Ok(());
                }
            }
            let mut restrictions = previous.map_or_else(BTreeMap::new, |p| p.restrictions);
            for record in &verified.records {
                match record {
                    StateRecord::Block { .. }
                    | StateRecord::Decline { .. }
                    | StateRecord::Floor { .. }
                    | StateRecord::Conflict { .. } => {
                        restrictions
                            .insert(serde_json::to_string(&record.order_key()?)?, record.clone());
                    }
                    StateRecord::Retirement { subject, update, .. }
                        if update.body.decision == Decision::Unblock =>
                    {
                        restrictions.remove(&serde_json::to_string(&("block", subject.key()?))?);
                    }
                    _ => {}
                }
            }
            let saved = SavedReachState {
                root: verified.manifest.account_anchor,
                revision: verified.manifest.revision,
                state_hash: verified.manifest.state_hash,
                records: verified.records,
                restrictions,
                conflict: false,
            };
            db.persist_client_record("reach", "state", &serde_json::to_value(saved)?)?;
            Ok::<_, SdkError>(())
        })?;
        let saved: SavedReachState = serde_json::from_value(
            db.client_record("reach", "state")?
                .ok_or_else(|| refused(Reason::ForeignSnapshotInvalid))?,
        )?;
        if saved.conflict {
            return Err(refused(Reason::HomeFork));
        }
        Ok(())
    }
}

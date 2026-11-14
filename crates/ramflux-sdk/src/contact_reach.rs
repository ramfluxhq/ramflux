// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified recipient state. A home signature cannot manufacture friendship or positive grants.
mod collection;
mod current_authority;
mod delivery;
mod denials;
mod group_binding;
mod group_join;
mod group_kick;
mod group_profile;
mod group_restrictions;
mod group_roster;
#[cfg(test)]
mod group_test_support;
mod inner;
mod producer;
mod projection;
mod provenance;
mod receive_policy;
mod restore;
mod restrictions;
mod signal_settings;
use restrictions::merge_restrictions;
mod verification;
use crate::SdkError;
pub use producer::ReachSendIntent;
pub use projection::{ConversationPermission, ConversationReach};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::{
    contact_reach::{
        Reason, STATE_DOMAIN, StateManifest, StatePage, StateRecord, check_submission_time,
        verify_pages,
    },
    custody::{self, Envelope as Signed},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn refused(reason: Reason) -> SdkError {
    SdkError::ReachRefused(reason)
}
pub(crate) fn remote_result(
    result: ramflux_protocol::contact_reach::OperationResult,
) -> Result<ramflux_protocol::contact_reach::OperationResult, SdkError> {
    if let ramflux_protocol::contact_reach::OperationResult::Error {
        reason,
        retry_after_ms,
        current_revision,
    } = result
    {
        return Err(SdkError::ReachRemote { reason, retry_after_ms, current_revision });
    }
    Ok(result)
}
/// A completely verified home mirror, suitable for one atomic local projection.
pub struct VerifiedReachState {
    pub(crate) manifest: StateManifest,
    pub(crate) records: Vec<StateRecord>,
    home_node_key: String,
    provenance: ramflux_crypto::contact_reach::EncryptedProvenanceStage,
    positives_ready: bool,
    custodian_head_hash: Option<String>,
    home: Option<ramflux_crypto::home_migration::VerifiedHome>,
}
/// Independently pinned state-read context; none of these facts comes from the manifest itself.
#[derive(Clone, Copy)]
pub struct ReachReadContext<'a> {
    pub authority: &'a VerifiedRecord,
    pub device: &'a custody::DeviceRef,
    pub home_head_hash: &'a str,
    pub home: Option<&'a ramflux_crypto::home_migration::VerifiedHome>,
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
        provenance: ramflux_crypto::contact_reach::EncryptedProvenanceStage,
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
        if context.device.account_anchor == *root {
            context.authority.authorize(context.device, "sync", context.now)?;
        } else {
            context.authority.authorize_primary_management(
                context.device,
                "contact_consent",
                context.now,
            )?;
        }
        ramflux_crypto::verify_canonical_signature(
            &custody::signing_bytes(STATE_DOMAIN, b)?,
            &manifest.signature,
            context.home_node_key,
        )?;
        if context.home.is_some_and(|home| home.hash() != context.home_head_hash) {
            return Err(refused(Reason::HomeRollback));
        }
        let records = verify_pages(b, pages)?;
        provenance.verify_manifest(b)?;
        if provenance.signers() != ramflux_protocol::contact_reach::page_signers(pages)? {
            return Err(refused(Reason::ForeignSnapshotInvalid));
        }
        let bases = verification::verify_records(&records, b, &provenance, context.home)?;
        verification::verify_placements(&records, b, &bases)?;
        let positives_ready =
            verification::current_positives(&records, context.authority, context.now);
        Ok(Self {
            positives_ready,
            custodian_head_hash: current_authority::custodian_head(context.authority)?,
            home: context.home.cloned(),
            manifest: b.clone(),
            records,
            home_node_key: context.home_node_key.to_owned(),
            provenance,
        })
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
    admission_revision: u64,
    home_head_hash: String,
    home_node_key: String,
    authority_head_hash: String,
    #[serde(deserialize_with = "required_option")]
    custodian_head_hash: Option<String>,
    state_hash: String,
    provenance_hash: String,
    records: Vec<StateRecord>,
    restrictions: BTreeMap<String, StateRecord>,
    conflict: bool,
    positive_pending: bool,
}
impl crate::RamfluxClient {
    pub(super) fn require_reach_authority_head(
        &self,
        root: &str,
        expected: &str,
        expected_custodian: Option<&str>,
        now: u64,
    ) -> Result<(), SdkError> {
        let current = self
            .current_custody_authority(root, now)?
            .ok_or_else(|| refused(Reason::CustodyRefused))?;
        current_authority::require_binding(&current, expected, expected_custodian)
    }
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
        db.write_transaction(|| {
            let now = crate::custody::network_now()?;
            check_submission_time(verified.manifest.issued_at, verified.manifest.expires_at, now)?;
            self.require_reach_authority_head(
                &verified.manifest.account_anchor,
                &verified.manifest.authority_head_hash,
                verified.custodian_head_hash.as_deref(),
                now,
            )?;
            let previous: Option<SavedReachState> =
                db.client_record("reach", "state")?.map(serde_json::from_value).transpose()?;
            provenance::retain_snapshot(
                db,
                &verified.manifest.account_anchor,
                &verified.provenance,
            )?;
            let restored =
                restore::verify(db, &verified.manifest.account_anchor, verified.home.as_ref())?;
            if let Some(saved) = &previous {
                if saved.root != verified.manifest.account_anchor
                    || saved.conflict
                    || verified.manifest.revision < saved.revision
                {
                    return Err(refused(Reason::HomeRollback));
                }
                if verified.manifest.revision == saved.revision {
                    if verified.manifest.state_hash == saved.state_hash
                        && saved.provenance_hash == verified.manifest.provenance_hash
                    {
                        if restored.is_none() {
                            let mut refreshed = saved.clone();
                            refreshed.refresh_current(&verified);
                            collection::collect(db, &refreshed)?;
                            db.persist_client_record(
                                "reach",
                                "state",
                                &serde_json::to_value(refreshed)?,
                            )?;
                            return Ok(());
                        }
                    } else {
                        let mut fenced = saved.clone();
                        fenced.conflict = true;
                        db.persist_client_record("reach", "state", &serde_json::to_value(fenced)?)?;
                        // Return after commit below; a callback error would roll the restrictive fence back.
                        return Ok(());
                    }
                }
            }
            let retained = previous.as_ref().map_or_else(BTreeMap::new, |p| p.restrictions.clone());
            let retained = match restored.as_deref() {
                Some(records) => restrictions::merge_restored(retained, records)?,
                None => retained,
            };
            let restrictions = match merge_restrictions(retained, &verified.records) {
                Ok(restrictions) => restrictions,
                Err(SdkError::ReachRefused(Reason::HomeFork)) => {
                    let mut fenced = previous.ok_or_else(|| refused(Reason::HomeFork))?;
                    fenced.conflict = true;
                    db.persist_client_record("reach", "state", &serde_json::to_value(fenced)?)?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let saved = SavedReachState {
                root: verified.manifest.account_anchor,
                revision: verified.manifest.revision,
                admission_revision: verified.manifest.admission_revision,
                home_head_hash: verified.manifest.home_head_hash,
                home_node_key: verified.home_node_key,
                authority_head_hash: verified.manifest.authority_head_hash,
                custodian_head_hash: verified.custodian_head_hash,
                state_hash: verified.manifest.state_hash,
                provenance_hash: verified.manifest.provenance_hash,
                records: verified.records,
                restrictions,
                conflict: false,
                positive_pending: !verified.positives_ready,
            };
            if restored.is_some() {
                db.remove_actor_state(restore::KEY)?;
            }
            collection::collect(db, &saved)?;
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
        self.stage_reach_group_repairs()?;
        Ok(())
    }
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::deserialize(deserializer)
}
impl SavedReachState {
    fn refresh_current(&mut self, verified: &VerifiedReachState) {
        self.positive_pending = !verified.positives_ready;
        self.custodian_head_hash.clone_from(&verified.custodian_head_hash);
        self.home_head_hash.clone_from(&verified.manifest.home_head_hash);
        self.home_node_key.clone_from(&verified.home_node_key);
        self.authority_head_hash.clone_from(&verified.manifest.authority_head_hash);
    }
    fn require_positive_ready(&self) -> Result<(), SdkError> {
        if self.positive_pending {
            return Err(SdkError::InboundPending(
                "reach positive permissions require current management reconciliation".into(),
            ));
        }
        Ok(())
    }
}

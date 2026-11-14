// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable paged home mirrors with stable content identity across fresh transport leases.
use super::{
    Admission, MAX_STATE_BYTES, Permissions, ReachPolicy, STATE_CONTENT_DOMAIN, STATE_PAGES_DOMAIN,
    Subject, actor, digest, invalid, lifetime, safe,
};
use crate::{
    ProtocolError,
    custody::{DeviceRef, Envelope as Signed, framed_hash},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    Strangers,
    Direct,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    Unaccepted,
    Accepted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictScope {
    Policy,
    Admission,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateRecord {
    Policy {
        revision: u64,
        update: Signed<ReachPolicy>,
    },
    AdmissionMeta {
        revision: u64,
        last_update: Option<Signed<Admission>>,
    },
    Grant {
        subject: Subject,
        permissions: Permissions,
        grant_until: u64,
        update: Signed<Admission>,
    },
    Block {
        subject: Subject,
        update: Signed<Admission>,
    },
    Decline {
        root: String,
        until: u64,
        update: Signed<Admission>,
    },
    Retirement {
        subject: Subject,
        revision: u64,
        update: Signed<Admission>,
        group_floor: Option<Box<super::GroupFloor>>,
    },
    Placement {
        conversation_id: String,
        revision: u64,
        placement: Placement,
        relationship: Relationship,
        tombstone: bool,
        basis: Vec<String>,
    },
    Floor {
        subject: Subject,
        revision: u64,
        denied: bool,
        erase_generation: u64,
        erased: bool,
    },
    Conflict {
        scope: ConflictScope,
        revision: u64,
        first_hash: String,
        other_hash: String,
    },
}
impl StateRecord {
    fn validate_shape(&self, manifest: &StateManifest) -> Result<(), ProtocolError> {
        if matches!(
            self,
            Self::Block { subject: Subject::Group { .. }, .. }
                | Self::Floor { subject: Subject::Group { .. }, .. }
        ) {
            return Err(invalid("group denials require the canonical retirement record"));
        }
        if let Self::Retirement { subject, update, group_floor, .. } = self {
            if matches!(subject, Subject::Group { .. }) != group_floor.is_some() {
                return Err(invalid("group retirement floor null rule"));
            }
            if let Some(floor) = group_floor {
                floor.validate(update)?;
                if crate::canonical_json_bytes(self)?.len() > super::GROUP_DENIAL_RESERVATION {
                    return Err(invalid("group retirement reservation overflow"));
                }
            }
        }
        match self {
            Self::Grant { subject, update, .. }
            | Self::Block { subject, update }
            | Self::Retirement { subject, update, .. } => {
                subject.validate()?;
                update.body.validate()?;
                if update.body.subject != *subject
                    || update.body.recipient_root != manifest.account_anchor
                    || update.body.expected_revision >= manifest.admission_revision
                {
                    return Err(invalid("reach signed subject/revision mismatch"));
                }
            }
            Self::Decline { root, until, update } => {
                digest(root)?;
                safe(*until)?;
                update.body.validate()?;
                let minimum = update
                    .body
                    .issued_at
                    .checked_add(super::DECLINE_COOLDOWN)
                    .ok_or_else(|| invalid("decline overflow"))?;
                let maximum = update
                    .body
                    .expires_at
                    .checked_add(super::DECLINE_COOLDOWN)
                    .ok_or_else(|| invalid("decline overflow"))?;
                if update.body.recipient_root != manifest.account_anchor
                    || *until < minimum
                    || *until >= maximum
                    || update.body.expected_revision >= manifest.admission_revision
                {
                    return Err(invalid("reach decline deadline/revision mismatch"));
                }
            }
            Self::Floor { subject, revision, erase_generation, .. } => {
                subject.validate()?;
                safe(*revision)?;
                safe(*erase_generation)?;
                if *revision > manifest.admission_revision
                    || *erase_generation > manifest.admission_revision
                {
                    return Err(invalid("reach floor exceeds admission revision"));
                }
            }
            Self::Placement { conversation_id, revision, basis, .. } => {
                super::text(conversation_id)?;
                safe(*revision)?;
                if *revision > manifest.revision || basis.is_empty() || basis.len() > 2 {
                    return Err(invalid("reach placement revision/basis"));
                }
                for hash in basis {
                    digest(hash)?;
                }
            }
            Self::Conflict { scope, revision, first_hash, other_hash } => {
                safe(*revision)?;
                digest(first_hash)?;
                digest(other_hash)?;
                let maximum = match scope {
                    ConflictScope::Policy => manifest.policy_revision,
                    ConflictScope::Admission => manifest.admission_revision,
                };
                if first_hash == other_hash || *revision > maximum {
                    return Err(invalid("reach conflict record"));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Canonical ordering by kind, then stable subject/conversation identity.
    /// # Errors
    /// Propagates invalid subject serialization.
    pub fn order_key(&self) -> Result<(String, String), ProtocolError> {
        let (kind, key) = match self {
            Self::Policy { .. } => ("policy", String::new()),
            Self::AdmissionMeta { .. } => ("admission_meta", String::new()),
            Self::Grant { subject, .. } => ("grant", subject.key()?),
            Self::Block { subject, .. } => ("block", subject.key()?),
            Self::Decline { root, .. } => ("decline", root.clone()),
            Self::Retirement { subject, .. } => ("retirement", subject.key()?),
            Self::Placement { conversation_id, .. } => ("placement", conversation_id.clone()),
            Self::Floor { subject, .. } => ("floor", subject.key()?),
            Self::Conflict { scope, .. } => (
                "conflict",
                match scope {
                    ConflictScope::Policy => "policy",
                    ConflictScope::Admission => "admission",
                }
                .into(),
            ),
        };
        Ok((kind.into(), key))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateManifest {
    pub version: u32,
    pub account_anchor: String,
    pub requesting_device: DeviceRef,
    pub home_head_hash: String,
    pub authority_head_hash: String,
    pub revision: u64,
    pub policy_revision: u64,
    pub admission_revision: u64,
    pub snapshot_id: String,
    pub page_count: u64,
    pub record_count: u64,
    pub pages_hash: String,
    pub state_hash: String,
    pub provenance_hash: String,
    pub provenance_count: u64,
    pub provenance_bytes: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl StateManifest {
    /// Validate bounded transport metadata, independent of its home signature.
    /// # Errors
    /// Refuses malformed digests, counters, leases or audience references.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for v in [
            &self.account_anchor,
            &self.home_head_hash,
            &self.authority_head_hash,
            &self.snapshot_id,
            &self.pages_hash,
            &self.state_hash,
            &self.provenance_hash,
        ] {
            digest(v)?;
        }
        actor(&self.requesting_device)?;
        for v in [self.revision, self.policy_revision, self.admission_revision] {
            safe(v)?;
        }
        if self.version != 1
            || !(1..=256).contains(&self.page_count)
            || !(2..=8192).contains(&self.record_count)
            || self.provenance_count > super::MAX_PROVENANCE_OBJECTS as u64
            || self.provenance_bytes > super::MAX_PROVENANCE_BYTES as u64
        {
            return Err(invalid("reach state counts or version"));
        }
        lifetime(self.issued_at, self.expires_at, 60)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePage {
    pub version: u32,
    pub snapshot_id: String,
    pub page: u64,
    pub records: Vec<StateRecord>,
    pub signers: Vec<super::SignerReference>,
}

/// Stable state hash excludes transport audience, lease, signatures and page boundaries.
/// # Errors
/// Refuses malformed root, unsafe revisions or canonical serialization failure.
pub fn state_hash(
    root: &str,
    revision: u64,
    policy_revision: u64,
    admission_revision: u64,
    records: &[StateRecord],
) -> Result<String, ProtocolError> {
    #[derive(Serialize)]
    struct Content<'a> {
        version: u32,
        account_anchor: &'a str,
        revision: u64,
        policy_revision: u64,
        admission_revision: u64,
        records: &'a [StateRecord],
    }
    digest(root)?;
    for value in [revision, policy_revision, admission_revision] {
        safe(value)?;
    }
    framed_hash(
        STATE_CONTENT_DOMAIN,
        &Content {
            version: 1,
            account_anchor: root,
            revision,
            policy_revision,
            admission_revision,
            records,
        },
    )
}

/// Verify complete transfer integrity before a caller verifies embedded authority and projects it.
/// # Errors
/// Refuses incomplete, reordered, duplicated or oversized records/pages and substituted content.
pub fn verify_pages(
    manifest: &StateManifest,
    pages: &[StatePage],
) -> Result<Vec<StateRecord>, ProtocolError> {
    manifest.validate()?;
    if pages.len() != usize::try_from(manifest.page_count).map_err(|_| invalid("page count"))?
        || crate::canonical_json_bytes(&pages)?.len() > MAX_STATE_BYTES
        || framed_hash(STATE_PAGES_DOMAIN, &pages)? != manifest.pages_hash
    {
        return Err(invalid("reach pages incomplete or hash mismatch"));
    }
    let mut records = Vec::new();
    for (index, page) in pages.iter().enumerate() {
        if page.version != 1
            || page.snapshot_id != manifest.snapshot_id
            || usize::try_from(page.page).ok() != Some(index)
            || page.records.is_empty()
            || page.records.len() > 32
            || crate::canonical_json_bytes(page)?.len() > 1024 * 1024
        {
            return Err(invalid("invalid reach page"));
        }
        records.extend(page.records.iter().cloned());
    }
    if u64::try_from(records.len()).ok() != Some(manifest.record_count) {
        return Err(invalid("reach record count mismatch"));
    }
    super::page_signers(pages)?;
    let mut previous = None;
    let mut policy = 0;
    let mut meta = 0;
    let mut counts = std::collections::BTreeMap::new();
    let mut unique = BTreeSet::new();
    for record in &records {
        record.validate_shape(manifest)?;
        let key = record.order_key()?;
        if previous.as_ref().is_some_and(|p| p >= &key) || !unique.insert(key.clone()) {
            return Err(invalid("reach records not canonical sorted unique"));
        }
        let count = counts.entry(key.0.clone()).or_insert(0_usize);
        *count += 1;
        let cap = if key.0 == "conflict" { 2 } else { super::MAX_SUBJECTS };
        if *count > cap {
            return Err(invalid("reach record class capacity"));
        }
        previous = Some(key);
        match record {
            StateRecord::Policy { revision, update } => {
                policy += 1;
                update.body.validate()?;
                if *revision != manifest.policy_revision
                    || update.body.revision != *revision
                    || update.body.account_anchor != manifest.account_anchor
                {
                    return Err(invalid("reach policy manifest mismatch"));
                }
            }
            StateRecord::AdmissionMeta { revision, .. } => {
                meta += 1;
                if *revision != manifest.admission_revision {
                    return Err(invalid("admission revision mismatch"));
                }
            }
            _ => {}
        }
    }
    if policy != 1
        || meta != 1
        || state_hash(
            &manifest.account_anchor,
            manifest.revision,
            manifest.policy_revision,
            manifest.admission_revision,
            &records,
        )? != manifest.state_hash
    {
        return Err(invalid("reach state incomplete or content mismatch"));
    }
    Ok(records)
}

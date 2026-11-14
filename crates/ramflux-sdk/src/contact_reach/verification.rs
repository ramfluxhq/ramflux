// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original account signatures and signed placement bases, independent of home assertions.
use super::{ReachReadContext, refused};
use crate::SdkError;
use ramflux_crypto::contact_reach as crypto;
use ramflux_protocol::{
    contact_reach::{
        Decision, OPERATION_HASH_DOMAIN, Placement, ReachMode, Reason, Relationship, StateManifest,
        StateRecord, Subject,
    },
    custody,
};
use std::collections::BTreeMap;

pub(super) fn verify_records<'a>(
    records: &'a [StateRecord],
    manifest: &StateManifest,
    context: &ReachReadContext<'_>,
) -> Result<BTreeMap<String, &'a StateRecord>, SdkError> {
    super::group_restrictions::verify_bindings(records)?;
    let mut bases = BTreeMap::new();
    for record in records {
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
                    || update.body.expected_revision >= manifest.admission_revision
                {
                    return Err(refused(Reason::ForeignSnapshotInvalid));
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
            StateRecord::Retirement { subject, revision, update, group_floor } => {
                bases.insert(custody::framed_hash(OPERATION_HASH_DOMAIN, update)?, record);
                let expected = if let Some(floor) = group_floor {
                    crypto::verify_group_retirement(update, floor, context.authority, context.now)?;
                    floor.block_control.as_ref().map_or(update.body.expected_revision, |control| {
                        control.body.expected_revision.max(update.body.expected_revision)
                    })
                } else {
                    crypto::verify_retained_admission(update, context.authority, context.now)?;
                    update.body.expected_revision
                };
                if &update.body.subject != subject
                    || update.body.decision == Decision::Allow
                    || expected.checked_add(1) != Some(*revision)
                    || *revision > manifest.admission_revision
                {
                    return Err(refused(Reason::ForeignSnapshotInvalid));
                }
            }
            _ => {}
        }
    }
    Ok(bases)
}

pub(super) fn verify_placements(
    records: &[StateRecord],
    manifest: &StateManifest,
    bases: &BTreeMap<String, &StateRecord>,
) -> Result<(), SdkError> {
    for record in records {
        if let StateRecord::Placement {
            conversation_id,
            revision,
            placement,
            relationship,
            basis,
            ..
        } = record
        {
            if *revision > manifest.revision
                || basis.is_empty()
                || basis.len() > 2
                || basis.iter().any(|hash| !bases.contains_key(hash))
            {
                return Err(refused(Reason::ForeignSnapshotInvalid));
            }
            let accepted = basis.iter().any(|hash| matches!(bases.get(hash),Some(StateRecord::Grant { subject:Subject::Friendship { root },.. }) if ramflux_protocol::message::dm_scope::derive(&manifest.account_anchor, root).is_ok_and(|id| id == *conversation_id)));
            let conversation = basis.iter().any(|hash| matches!(bases.get(hash),Some(StateRecord::Grant { subject:Subject::Conversation { conversation_id:id,.. },.. }) if id == conversation_id));
            let retired = basis.iter().any(|hash| match bases.get(hash) {
                Some(StateRecord::Retirement { subject: Subject::Friendship { root }, .. }) => {
                    ramflux_protocol::message::dm_scope::derive(&manifest.account_anchor, root)
                        .is_ok_and(|id| id == *conversation_id)
                }
                Some(StateRecord::Retirement {
                    subject: Subject::Conversation { conversation_id: id, .. },
                    ..
                }) => id == conversation_id,
                _ => false,
            });
            let open = basis.iter().any(|hash| matches!(bases.get(hash),Some(StateRecord::Policy { update,.. }) if update.body.mode == ReachMode::Open));
            if *relationship == Relationship::Accepted && !accepted
                || *placement == Placement::Direct && !accepted && !open
                || *placement == Placement::Strangers
                    && !accepted
                    && !conversation
                    && !retired
                    && !basis
                        .iter()
                        .any(|h| matches!(bases.get(h), Some(StateRecord::Policy { .. })))
            {
                return Err(refused(Reason::ForeignSnapshotInvalid));
            }
        }
    }
    Ok(())
}

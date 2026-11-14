// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Timed decline enforcement is separate from permanent revision and erasure floors.
use super::SavedReachState;
use ramflux_protocol::{
    contact_reach::{Admission, Decision, StateRecord, Subject},
    custody::Envelope,
};

impl SavedReachState {
    pub(super) fn floor_denies_now(&self, record: &StateRecord, now: u64) -> bool {
        let StateRecord::Floor { subject, revision, denied: true, .. } = record else {
            return false;
        };
        let Subject::Friendship { root } = subject else {
            return true;
        };
        // Only the exact, independently authenticated decline explains a timed floor.
        // Missing witnesses, a later floor or a block remain restrictive.
        self.records
            .iter()
            .chain(self.restrictions.values())
            .filter_map(|record| {
                let StateRecord::Decline { root: peer, until, update } = record else {
                    return None;
                };
                (peer == root
                    && update.body.decision == Decision::Decline
                    && &update.body.subject == subject
                    && update.body.expected_revision.checked_add(1) == Some(*revision))
                .then_some(*until)
            })
            .max()
            .is_none_or(|until| until > now)
    }

    pub(super) fn grant_above_peer_floors(
        &self,
        update: &Envelope<Admission>,
        peer: &str,
        conversation: &str,
    ) -> bool {
        let Some(grant_revision) = update.body.expected_revision.checked_add(1) else {
            return false;
        };
        self.records.iter().chain(self.restrictions.values()).all(|record| {
            let StateRecord::Floor { subject, revision, .. } = record else {
                return true;
            };
            let applies = match subject {
                Subject::Friendship { root } => root == peer,
                Subject::Conversation { root, conversation_id } => {
                    root == peer && conversation_id == conversation
                }
                _ => false,
            };
            !applies || grant_revision > *revision
        })
    }
}

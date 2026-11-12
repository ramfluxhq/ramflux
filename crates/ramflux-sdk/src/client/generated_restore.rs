// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Parked Edits whose target arrived through a restore or copy merge apply on the next pass.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use std::collections::BTreeSet;

const PENDING: &str = "routed/pending-edit/";
const PENDING_HISTORY: &str = "routed/pending-history-edit/";

impl RamfluxClient {
    /// Run the ordinary parked-Edit resolvers once after storage marked a merge for review.
    /// Authority, ordering and retirement stay with the resolvers; refused Edits are dropped there.
    pub(crate) fn review_parked_generated_edits_after_restore(&self) -> Result<usize, SdkError> {
        let db = self.account_db()?;
        if !db.load_actor_state::<bool>(ramflux_storage::PARKED_EDIT_REVIEW)?.unwrap_or(false) {
            return Ok(0);
        }
        let mut targets = BTreeSet::new();
        for key in db.actor_state_keys(PENDING)? {
            if let Some(target) = key.strip_prefix(PENDING).and_then(|rest| rest.split('/').next())
            {
                targets.insert(target.to_owned());
            }
        }
        let mut reviewed = 0;
        for target in targets {
            let Some(identity) = db.load_actor_state::<g::EventIdentity>(&format!(
                "routed/generated-identity/{target}"
            ))?
            else {
                continue;
            };
            let resolved = db.write_transaction(|| {
                self.resolve_generated_pending_edit(&identity.conversation_id, &target)
            });
            reviewed += settle(resolved)?;
        }
        for key in db.actor_state_keys(PENDING_HISTORY)? {
            let Some(target) = key.strip_prefix(PENDING_HISTORY) else {
                continue;
            };
            let resolved =
                db.write_transaction(|| self.resolve_generated_pending_history_edit(target));
            reviewed += settle(resolved)?;
        }
        db.write_transaction(|| -> Result<(), SdkError> {
            db.persist_actor_state(ramflux_storage::PARKED_EDIT_REVIEW, &false)?;
            Ok(())
        })?;
        Ok(reviewed)
    }
}

/// Local storage failures stop the review and keep the marker; a refused Edit stays parked.
fn settle(resolved: Result<(), SdkError>) -> Result<usize, SdkError> {
    match resolved {
        Ok(()) => Ok(1),
        Err(SdkError::Storage(error)) => Err(SdkError::Storage(error)),
        Err(_) => Ok(0),
    }
}

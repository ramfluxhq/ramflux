// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recheck the original positive recipient signatures against current custody before use.
use super::{
    AccountReach, Placement, ReachClass, Reason, Result, Route, StateRecord, Subject, Traffic,
    refuse, storage,
};
use ramflux_crypto::{contact_reach as crypto, custody::VerifiedRecord};

impl AccountReach {
    pub(in crate::contact_reach) fn classify_current(
        &self,
        route: &Route,
        peer: &str,
        authority: &VerifiedRecord,
        now: u64,
    ) -> Result<(ReachClass, Placement)> {
        let decision = self.classify(route, peer, now)?;
        if route.recipient_root != authority.envelope().body.account_anchor {
            return Err(refuse(Reason::CustodyRefused));
        }
        // Same-root copies use current branch capabilities, never a foreign reach grant.
        if matches!(route.traffic, Traffic::OwnCopy | Traffic::SelfSync) {
            return Ok(decision);
        }
        crypto::verify_retained_policy(
            self.policy.as_ref().ok_or_else(|| refuse(Reason::ReachPolicyRequired))?,
            authority,
            now,
        )?;
        let subject = if route.traffic == Traffic::Group {
            let group = route.group.as_ref().ok_or_else(|| refuse(Reason::ReachRouteInvalid))?;
            // Group subject keys intentionally contain only the canonical group identifier.
            serde_json::to_string(&serde_json::json!(["group", group.group_id])).map_err(storage)?
        } else {
            match decision.0 {
                ReachClass::Unsolicited => return Ok(decision),
                ReachClass::Accepted => {
                    Subject::Friendship { root: route.source.account_anchor.clone() }.key()?
                }
                ReachClass::Replied => Subject::Conversation {
                    root: route.source.account_anchor.clone(),
                    conversation_id: route.conversation_id.clone(),
                }
                .key()?,
            }
        };
        let Some(StateRecord::Grant { update, .. }) = self.grants.get(&subject) else {
            return Err(refuse(Reason::ForeignReadRefused));
        };
        crypto::verify_retained_admission(update, authority, now)?;
        if route.traffic == Traffic::Group {
            let roster =
                self.rosters.get(&subject).ok_or_else(|| refuse(Reason::ForeignReadRefused))?;
            crypto::verify_group_roster(roster, update, authority, now)?;
        }
        Ok(decision)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-agent contact acceptance and card authority.
//!
//! A local agent record is a discovery hint. Acceptance and rendering also require the requester's
//! pinned current publication: `HeadlessAi`, the exact anchor and principal, and a published
//! custodian equal to this owner's current primary. Absent or stale evidence leaves the request
//! pending and the card unrendered.
use crate::prelude::*;
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::PrincipalKind;
use ramflux_protocol::custody::{CustodyKind, DeviceRef};
use ramflux_storage::ContactRequestRecord;

impl RamfluxClient {
    /// Whether `anchor` is this owner's non-retired agent under its pinned current publication.
    ///
    /// `verify_record` does not bind `profile.custodian`, so both that field and
    /// `primary_device_ref` must equal this owner's current primary.
    ///
    /// # Errors
    /// Returns storage and clock errors. A missing, stale or mismatched publication is `Ok(false)`.
    pub(crate) fn verified_own_agent(
        &self,
        anchor: &str,
        principal: &str,
        now: u64,
    ) -> Result<bool, SdkError> {
        let Some(owner) = self.born_v3_account.as_ref() else {
            return Ok(false);
        };
        let Some(primary) = owner_primary(owner) else {
            return Ok(false);
        };
        let agent = match self.current_custody_authority(anchor, now) {
            Ok(Some(agent)) => agent,
            Ok(None) => return Ok(false),
            Err(error @ SdkError::Storage(_)) => return Err(error),
            Err(error) => {
                tracing::debug!(%error, %anchor, "own-agent publication is not current");
                return Ok(false);
            }
        };
        Ok(publication_is_own_agent(&primary, principal, anchor, &agent)
            && owner.records_own_agent(anchor))
    }

    /// Accepts one still-open inbound request when [`Self::verified_own_agent`] holds.
    ///
    /// The record and the publication are read again immediately before the decision. This client
    /// is confined to the account thread, so retirement and this decision do not interleave here.
    /// Expired, blocked, declined and removed contacts are left unchanged.
    ///
    /// # Errors
    /// Returns storage or clock errors from the request row or the acceptance write.
    pub(crate) fn accept_pending_own_agent(
        &self,
        request: &ContactRequestRecord,
    ) -> Result<(), SdkError> {
        let Some(row) =
            self.open_own_agent_request(&request.contact_identity_commitment, &request.request_id)?
        else {
            return Ok(());
        };
        let now = crate::custody::network_now()?;
        if self.verified_own_agent(&row.contact_identity_commitment, &row.principal_id, now)? {
            self.decide_inbound_contact(&row, "accepted")?;
        }
        Ok(())
    }

    /// Reconsiders the single inbound request from `anchor` after its agent record changed.
    ///
    /// # Errors
    /// Returns storage or clock errors. A missing request is not an error.
    pub(crate) fn accept_own_agent_anchor(&self, anchor: &str) -> Result<(), SdkError> {
        let Some(row) = self.account_db()?.contact_request(anchor, "inbound")? else {
            return Ok(());
        };
        self.accept_pending_own_agent(&row)
    }

    /// Reconsiders the bounded pending inbound page. Maintenance calls this at most once a minute.
    ///
    /// # Errors
    /// Returns storage or clock errors from the page or from an acceptance write.
    pub(crate) fn accept_newly_eligible_own_agents(&self) -> Result<(), SdkError> {
        for row in self.account_db()?.pending_contact_requests()? {
            self.accept_pending_own_agent(&row)?;
        }
        Ok(())
    }

    fn open_own_agent_request(
        &self,
        root: &str,
        request_id: &str,
    ) -> Result<Option<ContactRequestRecord>, SdkError> {
        let db = self.account_db()?;
        let now = now_unix_timestamp();
        let Some(row) = db.contact_request(root, "inbound")? else {
            return Ok(None);
        };
        if row.request_id != request_id || row.state != "pending" || row.expires_at <= now {
            return Ok(None);
        }
        if db.contact_request_fence(root, now)?.is_some() || self.link_closed(&row.link_id)? {
            return Ok(None);
        }
        Ok(Some(row))
    }

    fn link_closed(&self, link_id: &str) -> Result<bool, SdkError> {
        let Some(link) = self.account_db()?.find_friend_link(link_id)? else {
            return Ok(false);
        };
        Ok(link.blocked
            || link.remove_scope.is_some()
            || link.capability_revoked_at.is_some()
            || matches!(link.state.as_str(), "removed" | "rejected" | "blocked"))
    }
}

fn owner_primary(owner: &crate::custody::BornAccount) -> Option<DeviceRef> {
    if owner.authority_blocked() || owner.record().body.principal_kind != PrincipalKind::Human {
        return None;
    }
    let primary = owner.record().body.master_certificate.body.primary_device_ref.clone();
    (primary.account_anchor == owner.record().body.account_anchor).then_some(primary)
}

fn publication_is_own_agent(
    primary: &DeviceRef,
    principal: &str,
    anchor: &str,
    agent: &VerifiedRecord,
) -> bool {
    let body = &agent.envelope().body;
    let master = &body.master_certificate.body;
    body.account_anchor == anchor
        && body.principal_id == principal
        && body.principal_kind == PrincipalKind::HeadlessAi
        && master.custody_kind == CustodyKind::ExternalHuman
        && master.primary_device_ref == *primary
        && body.profile.custodian.as_ref() == Some(primary)
}

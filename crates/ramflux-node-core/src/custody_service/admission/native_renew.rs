// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Re-admit a live native session with the same checks as the original grant.

use super::super::{
    CustodyRefusal, CustodyServerFrame, CustodyService, Scope, holder, invalid, object_hash,
    persistence, validate_bundle,
};

impl CustodyService {
    /// # Errors
    /// Refuses a missing lease, a failed possession check, or an expired window.
    pub(in super::super) fn renew_native_session(
        &self,
        scope: Scope<'_>,
        session_id: &str,
        connection_id: &str,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let Scope { router, store, peer, now, tick, .. } = scope;
        let holder = holder(peer, connection_id)?;
        let session = self.leases().session(session_id, &holder, now, tick)?;
        let publication = router
            .custody_record(&session.device_ref.account_anchor, now)
            .map_err(invalid)?
            .ok_or(CustodyRefusal::AuthorityUnavailable)?;
        let authority =
            router.verify_custody_possession_authority(&publication, now, true).map_err(invalid)?;
        let bundle = store
            .custody_prekey(&session.target_delivery_id)
            .map_err(persistence)?
            .ok_or(CustodyRefusal::AuthorityUnavailable)?;
        validate_bundle(&authority, &session.device_ref, &bundle, "message", now)?;
        let record_hash = object_hash(&publication.record).map_err(invalid)?;
        let expires_at = now.saturating_add(crate::NATIVE_SESSION_GRANT_SECONDS);
        let session = self.leases().renew_native(&crate::custody_sessions::NativeRenewal {
            id: session_id,
            holder: &holder,
            record_hash: &record_hash,
            expires_at,
            now,
            tick,
        })?;
        Ok(CustodyServerFrame::SessionEstablished { session })
    }
}

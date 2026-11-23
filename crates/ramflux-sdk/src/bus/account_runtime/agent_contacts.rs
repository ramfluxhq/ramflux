// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creating an agent makes it its owner's contact. The agent's account on the device that hosts
//! it sends the ordinary contact request to its custodian once (signed with the agent's own key,
//! `BornAccount::contact_signer`). The owner's primary accepts that request only when the agent's
//! pinned current publication names this owner and the local record is still live
//! (`contact_requests`). Acceptance creates the direct conversation. The owner's other devices
//! learn the contact by own-device sync.
use super::AccountRuntime;
use crate::bus::dispatch::contact::dispatch_contact_bus_request;
use crate::custody::load_account;
use crate::prelude::*;

impl AccountRuntime {
    /// Requests contact with this agent's custodian when the two have never been in contact. A
    /// refusal (networking not ready, node unreachable) leaves nothing behind and is retried on the
    /// next sync pass. Any other account is left alone.
    pub(super) async fn maintain_agent_owner_contact(&mut self) {
        let Some((principal_id, anchor)) = self.local_custodian() else { return };
        match self.contact_known(&anchor) {
            Ok(false) => {}
            Ok(true) => return,
            Err(error) => {
                tracing::debug!(%error, "agent owner contact state unreadable; deferred");
                return;
            }
        }
        let request = LocalBusFrame::request(
            "agent-owner-contact",
            Some(self.id.clone()),
            "contact",
            "contact.add",
            serde_json::json!({ "principal_id": principal_id }),
        );
        if let Err(error) = Box::pin(dispatch_contact_bus_request(&request, &mut self.state)).await
        {
            tracing::debug!(%error, "agent contact request to its owner deferred");
        }
    }

    /// The (principal id, anchor) of the human that custodies this account, when this account is
    /// a headless agent whose custodian's account is stored on this device.
    fn local_custodian(&self) -> Option<(String, String)> {
        let account = self.state.accounts.get(&self.id)?;
        let born = account.client.born_v3_account.as_ref()?;
        if born.record().body.principal_kind != ramflux_protocol::PrincipalKind::HeadlessAi
            || born.authority_blocked()
        {
            return None;
        }
        let owner_id = born.custodian_account_id()?;
        let now = super::super::custody_setup::now().ok()?;
        let owner = load_account(&self.state.config.data_root, owner_id, now).ok()?;
        let body = &owner.record().body;
        let named = born.record().body.profile.custodian.as_ref()?;
        (named.account_anchor == body.account_anchor)
            .then(|| (body.principal_id.clone(), body.account_anchor.clone()))
    }

    /// Whether this account already has, or once had, any contact state with `anchor`: a link in
    /// any state or a request in either direction. A contact that was removed is never requested
    /// again.
    fn contact_known(&self, anchor: &str) -> Result<bool, SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        let db = account.client.account_db()?;
        Ok(db.friend_link_for_peer(anchor)?.is_some()
            || db.contact_request(anchor, "outbound")?.is_some()
            || db.contact_request(anchor, "inbound")?.is_some())
    }
}

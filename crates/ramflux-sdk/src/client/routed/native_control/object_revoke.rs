// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `CONTROL_OBJECT_REVOKE` (operation 12): the root that shared an object with this account
//! withdraws access. The received reference is tombstoned through the native object store; an
//! object that was already erased stays erased (erasure is the stronger veto).
use super::{authority, content};
use crate::client::identity_authority::HeadUse;
use crate::client::routed::{Kind, Opened};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::message as g;

const MAX_REASON_BYTES: usize = 256;

impl RamfluxClient {
    /// Sender rule: the authenticated root owns the received reference and names this account
    /// as the recipient. Checked against the durable object record, never against the payload.
    pub(in crate::client::routed) fn authorize_received_object_revoke(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        revoke: &g::ObjectRevokeAccess,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        if opened.routing.kind != Kind::Control || opened.routing.group_id.is_some() {
            return Err(authority("object revoke requires a direct control route"));
        }
        if revoke.reason.len() > MAX_REASON_BYTES || revoke.effective_at <= 0 {
            return Err(content("object revoke reason or effective_at out of range"));
        }
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if source != opened.remote_device {
            return Err(authority("object revoke sender is not the pair-session peer"));
        }
        let (principal, _) = self.pinned_peer(&source)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let own = self.own_account_anchor()?;
        if revoke.recipient_principal_id != local.principal_id
            && revoke.recipient_principal_id != own
        {
            return Err(authority("object revoke names another recipient"));
        }
        let record = self.account_db()?.client_record("object", &revoke.object_id)?;
        let owner = record
            .as_ref()
            .and_then(|record| record.get("owner"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| authority("object revoke names no received reference"))?;
        let sender = if owner == source.root_commitment() {
            source.root_commitment()
        } else {
            principal.as_str()
        };
        crate::client::generated_control::authorize_object_revoke(sender, owner, revoke)
            .map_err(|_| authority("object revocation sender does not own the received reference"))?;
        Ok(source)
    }

    /// Native tombstone with revocation provenance, joined to the exact-replay ledger.
    pub(in crate::client::routed) fn apply_generated_object_revoke(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        identity: &g::EventIdentity,
        revoke: &g::ObjectRevokeAccess,
        exact_inner: &[u8],
    ) -> Result<bool, SdkError> {
        self.authorize_received_object_revoke(opened, entry, revoke)?;
        let db = self.account_db()?;
        self.apply_generated_peer_control_once(entry, identity, exact_inner, 12, |_| {
            db.set_object_tombstoned_with_revocation(
                &revoke.object_id,
                Some(&entry.envelope.source_principal_id),
                Some(&entry.envelope.envelope_id),
                crate::time::now_unix_timestamp(),
            )
            .map_err(|error| match error {
                ramflux_storage::StorageError::AuthorizationRejected => {
                    authority("object revocation has no admissible manifest source")
                }
                error => SdkError::from(error),
            })
        })
    }
}

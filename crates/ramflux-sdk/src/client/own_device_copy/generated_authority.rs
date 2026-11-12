// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native own-copy transport and nested origin checks precede every retention path.
use super::invalid;
use crate::client::identity_authority::{HeadUse, NativeOperation};
use crate::client::routed::Opened;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;

impl RamfluxClient {
    pub(crate) fn authorize_generated_own_message_copy(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        copy: &g::OwnMessageCopy,
    ) -> Result<(), SdkError> {
        crate::client::generated_control::validate_control_native(&g::Control {
            operation: 15,
            payload: Some(g::control::Payload::OwnMessageCopy(copy.clone())),
        })?;
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let local = self.owned_device_identity()?;
        let declared_source =
            copy.source.as_ref().ok_or_else(|| invalid("own copy source missing"))?;
        let declared_target =
            copy.target.as_ref().ok_or_else(|| invalid("own copy target missing"))?;
        let source_record = self
            .account_db()?
            .client_device_record(&source)?
            .ok_or_else(|| invalid("own copy source authority missing"))?;
        let local_epoch =
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch;
        let local_record = self
            .account_db()?
            .client_device_record(&local)?
            .ok_or_else(|| invalid("own copy local authority missing"))?;
        if local_record["device_epoch"].as_u64() != Some(local_epoch) {
            return Err(invalid("own copy local branch epoch differs from current authority"));
        }
        let outer = g::Inner::decode(opened.body.as_slice())
            .map_err(|_| invalid("own copy Inner missing"))?;
        if source != opened.remote_device
            || local != opened.local_device
            || source == local
            || source.root_commitment() != local.root_commitment()
            || declared_source.account_anchor != source.root_commitment()
            || declared_source.device_id != source.device_id()
            || source_record["device_epoch"].as_u64() != Some(declared_source.device_epoch)
            || outer.identity.as_ref().and_then(|identity| identity.author.as_ref())
                != Some(declared_source)
            || declared_target.account_anchor != local.root_commitment()
            || declared_target.device_id != local.device_id()
            || declared_target.device_epoch != local_epoch
        {
            return Err(invalid("own copy qualified endpoints differ from authenticated devices"));
        }
        self.require_native_operation(&source, NativeOperation::Sync)?;
        self.require_native_operation(&local, NativeOperation::Sync)?;
        let now = crate::time::now_unix_timestamp();
        if copy.created_at > now.saturating_add(300)
            || copy.expires_at < now
            || copy.expires_at <= copy.created_at
            || copy.expires_at
                > copy.created_at.saturating_add(i64::from(crate::DEFAULT_OFFLINE_RETENTION_SECS))
        {
            return Err(invalid("own copy lifetime mismatch"));
        }
        match copy.payload.as_ref() {
            Some(g::own_message_copy::Payload::Item(item)) => {
                let inner = g::Inner::decode(item.exact_inner.as_slice())
                    .map_err(|_| invalid("own history Inner missing"))?;
                let identity = if inner.kind == 3
                    || item.original_metadata_evidence.is_some()
                    || !item.exact_original_identity.is_empty()
                {
                    self.verify_generated_edited_history_item(item)?
                } else {
                    Self::verify_history_message_origin(item)?.0
                };
                if identity.conversation_id != opened.routing.conversation_id {
                    return Err(invalid("own history conversation differs from control"));
                }
                self.authorize_history_message_scope(&identity)?;
            }
            Some(g::own_message_copy::Payload::Sent(sent)) => {
                self.authorize_generated_own_sent(&source, &opened.routing.conversation_id, sent)?;
            }
            None => return Err(invalid("own copy payload missing")),
        }
        Ok(())
    }
}

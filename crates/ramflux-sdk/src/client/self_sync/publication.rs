// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{RamfluxClient, SdkError, State, g, key, refused, self_sync};
use prost::Message as _;

impl RamfluxClient {
    /// Caller joins the prepared outbox transaction. Every recipient reuses the same logical event.
    pub(crate) fn self_sync_publication_inner(
        &self,
        conversation: &str,
        value: &g::SelfSync,
    ) -> Result<Vec<u8>, SdkError> {
        self.require_backup_outbound_ready()?;
        let source = self.owned_device_identity()?;
        self.authorize_self_sync(&source, conversation)?;
        let epoch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch;
        let state_key = key(source.root_commitment(), conversation, value)?;
        let db = self.account_db()?;
        let mut state = db
            .load_actor_state::<State>(&state_key)?
            .ok_or_else(|| refused("publication has no committed register value"))?;
        let read_publication = state.value != *value;
        let body = if read_publication {
            state
                .read_marker_body
                .as_ref()
                .map(|body| body.exact_body.clone())
                .ok_or_else(|| refused("publication has no committed read marker"))?
        } else {
            state.exact_body.clone()
        };
        if self_sync::decode_stored_body(&body)
            .map_err(|_| refused("invalid stored publication body"))?
            != *value
        {
            return Err(refused("publication must use a current exact register value"));
        }
        let cached = if read_publication {
            &state.read_publication_identity
        } else {
            &state.publication_identity
        };
        let reuse = cached.as_ref().is_some_and(|identity| {
            identity.conversation_id == conversation
                && identity.device_sequence & (1 << 63) != 0
                && identity.author.as_ref().is_some_and(|author| {
                    author.account_anchor == source.root_commitment()
                        && author.device_id == source.device_id()
                        && author.device_epoch == epoch
                })
        });
        if !reuse {
            let identity = Some(self.allocate_generated_identity(
                conversation,
                crate::client::generated_identity::now_ms(),
                true,
            )?);
            if read_publication {
                state.read_publication_identity = identity;
            } else {
                state.publication_identity = identity;
            }
            db.persist_actor_state(&state_key, &state)?;
        }
        let identity = if read_publication {
            state.read_publication_identity
        } else {
            state.publication_identity
        }
        .ok_or_else(|| refused("publication identity missing"))?;
        g::identity::verify(&identity)
            .map_err(|_| refused("invalid stored publication identity"))?;
        Ok(g::Inner {
            layer: g::registry::COMPILED_LAYER,
            kind: 12,
            identity: Some(identity),
            body,
        }
        .encode_to_vec())
    }
}

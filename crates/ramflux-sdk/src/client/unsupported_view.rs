// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opaque UI handles; private source-qualified raw locators never cross the binding.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;

fn key(handle: &[u8]) -> String {
    format!("routed/raw-handle/{}", ramflux_protocol::encode_base64url(handle))
}
impl RamfluxClient {
    pub(crate) fn persist_generated_unsupported_view(
        &self,
        owner: &str,
        copy_id: &str,
        scanned: &g::validation::ScannedInner<'_>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let state_key = format!("routed/unsupported/{owner}");
        let previous = db.load_actor_state::<g::UnsupportedView>(&state_key)?;
        let handle = previous.filter(|view| view.raw_handle.len() == 16).map_or_else(
            || ramflux_crypto::random_32().map(|bytes| bytes[..16].to_vec()),
            |view| Ok(view.raw_handle),
        )?;
        let raw = db
            .raw_inner_copy(copy_id)?
            .ok_or_else(|| SdkError::InboundRejected("raw copy missing before commit".into()))?;
        let view = g::UnsupportedView {
            layer: scanned.layer,
            kind: scanned.kind,
            raw_digest: raw.digest.to_vec(),
            raw_length: u32::try_from(raw.bytes.len())
                .map_err(|_| SdkError::InboundRejected("raw length overflow".into()))?,
            raw_handle: handle.clone(),
            reason: g::unsupported::reason(scanned).into(),
        };
        // Both records join the receive transaction and owner erasure registration.
        db.persist_message_actor_state(owner, &key(&handle), &copy_id)?;
        db.persist_message_actor_state(owner, &state_key, &view)?;
        Ok(())
    }

    pub(crate) fn disarm_generated_unsupported_view(
        &self,
        owner: &str,
        removed_copy: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let state_key = format!("routed/unsupported/{owner}");
        let Some(mut view) = db.load_actor_state::<g::UnsupportedView>(&state_key)? else {
            return Ok(());
        };
        if !view.raw_handle.is_empty()
            && db.load_actor_state::<String>(&key(&view.raw_handle))?.as_deref()
                == Some(removed_copy)
        {
            db.remove_actor_state(&key(&view.raw_handle))?;
            // Keep only a non-actionable historical diagnostic. There is no longer
            // a raw row behind this view, so it must not advertise a fetch handle.
            view.raw_handle.clear();
            db.persist_message_actor_state(owner, &state_key, &view)?;
        }
        Ok(())
    }

    pub(crate) fn remove_generated_unsupported_view(&self, owner: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let state_key = format!("routed/unsupported/{owner}");
        if let Some(view) = db.load_actor_state::<g::UnsupportedView>(&state_key)? {
            db.remove_actor_state(&key(&view.raw_handle))?;
        }
        db.remove_actor_state(&state_key)?;
        Ok(())
    }
}

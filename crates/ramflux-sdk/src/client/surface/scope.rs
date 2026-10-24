// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conversation/author-scoped surface identity and checked local checkpoint reads.
use super::{StoredSurface, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::SurfaceState;

pub(crate) fn surface_reference(
    conversation: &str,
    author: &str,
    id: &str,
) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.surface.identity.v1",
        &ramflux_protocol::canonical_json_bytes(&(conversation, author, id))?,
    ))
}
impl super::Carrier {
    pub(crate) fn surface_reference(&self) -> Result<String, SdkError> {
        surface_reference(&self.conversation_id, &self.author_principal_id, &self.surface_id)
    }
}
impl RamfluxClient {
    pub(crate) fn resolve_surface_reference(
        &self,
        id: &str,
        conversation: Option<&str>,
        author: Option<&str>,
    ) -> Result<Option<String>, SdkError> {
        if let (Some(conversation), Some(author)) = (conversation, author) {
            let reference = surface_reference(conversation, author, id)?;
            return Ok(self.account_db()?.client_record("surface", &reference)?.map(|_| reference));
        }
        let db = self.account_db()?;
        let mut cursor = String::new();
        let mut found = None;
        for _ in 0..100 {
            let ids = db.client_directory_ids("surface", &cursor, 100)?;
            for reference in &ids {
                if let Some(view) = db.client_record("surface", reference)?
                    && view["surface_id"] == id
                    && conversation.is_none_or(|c| view["conversation_id"] == c)
                    && author.is_none_or(|a| view["author_principal_id"] == a)
                {
                    if found.is_some() {
                        return Err(invalid(
                            "ambiguous surface id; provide conversation_id and author_principal_id or surface_ref",
                        ));
                    }
                    found = Some(reference.clone());
                }
            }
            if ids.len() < 100 {
                return Ok(found);
            }
            cursor =
                ids.last().cloned().ok_or_else(|| invalid("surface directory cursor missing"))?;
        }
        Err(invalid(
            "surface lookup scan budget exceeded; provide conversation_id and author_principal_id",
        ))
    }
    #[cfg(test)]
    pub(crate) fn surface_state(
        &self,
        id: &str,
    ) -> Result<Option<(StoredSurface, SurfaceState)>, SdkError> {
        self.resolve_surface_reference(id, None, None)?
            .map(|reference| self.surface_state_ref(&reference))
            .transpose()
            .map(Option::flatten)
    }
    pub(crate) fn surface_state_scoped(
        &self,
        conversation: &str,
        author: &str,
        id: &str,
    ) -> Result<Option<(StoredSurface, SurfaceState)>, SdkError> {
        self.surface_state_ref(&surface_reference(conversation, author, id)?)
    }
    pub(crate) fn surface_state_ref(
        &self,
        reference: &str,
    ) -> Result<Option<(StoredSurface, SurfaceState)>, SdkError> {
        let db = self.account_db()?;
        let Some(record) = db.load_actor_state::<StoredSurface>(&key("state", reference))? else {
            if db
                .client_record("surface", reference)?
                .is_some_and(|view| view["version"].as_u64().is_some_and(|v| v > 0))
            {
                return Err(SdkError::SurfaceCheckpointMismatch);
            }
            return Ok(None);
        };
        let bytes = ramflux_protocol::decode_base64url(&record.checkpoint_base64)
            .map_err(|_| SdkError::SurfaceCheckpointMismatch)?;
        let state = SurfaceState::from_checkpoint_bytes(&bytes)
            .map_err(|_| SdkError::SurfaceCheckpointMismatch)?;
        let view =
            db.client_record("surface", reference)?.ok_or(SdkError::SurfaceCheckpointMismatch)?;
        if surface_reference(
            &record.conversation_id,
            &record.author_principal_id,
            &record.surface_id,
        )? != reference
            || state.content().is_none_or(|c| {
                c.surface_id != record.surface_id || view["fallback_text"] != c.fallback_text
            })
            || state.conversation_id() != Some(record.conversation_id.as_str())
            || view["surface_ref"] != reference
            || view["surface_id"] != record.surface_id
            || view["conversation_id"] != record.conversation_id
            || view["author_principal_id"] != record.author_principal_id
            || view["author_device_id"] != record.author_device_id
            || view["version"] != state.version()
            || view["surface_hash"].as_str() != state.hash()
            || view["closed"].as_bool() != Some(state.is_closed())
        {
            return Err(SdkError::SurfaceCheckpointMismatch);
        }
        Ok(Some((record, state)))
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attachment-only Images inherit the existing conversation's encrypted-reference authority.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{SurfaceReject, SurfaceState};
use serde_json::Value;
impl RamfluxClient {
    pub(super) fn validate_surface_attachments(
        &self,
        state: &SurfaceState,
    ) -> Result<Result<(), SurfaceReject>, SdkError> {
        let Some(snapshot) = state.content() else {
            return Ok(Err(SurfaceReject::NotCreated));
        };
        let Some(conversation) = state.conversation_id() else {
            return Ok(Err(SurfaceReject::NotCreated));
        };
        for component in &snapshot.components {
            if component.get("component").and_then(Value::as_str) != Some("Image") {
                continue;
            }
            let reference = component
                .get("attachment")
                .ok_or_else(|| super::invalid("validated Image attachment missing"))?;
            let Some(object) = reference.get("object_id").and_then(Value::as_str) else {
                return Ok(Err(SurfaceReject::Validation("Image attachment".into())));
            };
            let Some(manifest) = reference.get("manifest_digest").and_then(Value::as_str) else {
                return Ok(Err(SurfaceReject::Validation("Image attachment".into())));
            };
            if !self.surface_attachment_in_conversation(object, manifest, conversation)? {
                return Ok(Err(SurfaceReject::Validation("Image attachment conversation".into())));
            }
        }
        Ok(Ok(()))
    }
}

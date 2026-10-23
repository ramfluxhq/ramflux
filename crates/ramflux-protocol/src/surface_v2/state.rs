// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pure atomic surface transitions and current-content decision validation.

use super::{
    SurfaceAction, SurfaceBlockKind, SurfaceContent, SurfaceEvent, SurfaceLimit, SurfacePatchOp,
    SurfaceReject, limits, surface_args_hash, surface_hash,
};
use std::collections::BTreeSet;

/// Immutable projection. Rejected updates leave the original unchanged.
/// Text, Markdown and `LogStream` blocks start open when their data contains a `text` string.
/// Finalized IDs cannot be reopened by replacement, removal or reinsertion.
/// At most 64 finalized IDs are retained, including removed blocks, to bound replay tombstones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SurfaceState {
    content: Option<SurfaceContent>,
    version: u64,
    closed: bool,
    final_blocks: BTreeSet<String>,
}
impl SurfaceState {
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
    #[must_use]
    pub const fn content(&self) -> Option<&SurfaceContent> {
        self.content.as_ref()
    }
    #[must_use]
    pub fn hash(&self) -> Option<String> {
        self.content.as_ref().map(surface_hash)
    }

    /// Applies an event to a replacement state. Every mutation consumes exactly the next version.
    /// # Errors
    /// Rejects closed/uncreated surfaces, wrong IDs/versions, conflicting bases, invalid patches,
    /// finalized/nontext streams and content limits.
    pub fn apply(&self, event: &SurfaceEvent) -> Result<Self, SurfaceReject> {
        if self.closed {
            return Err(SurfaceReject::Closed);
        }
        if let SurfaceEvent::Create { surface_id, version, blocks, actions, fallback_text } = event
        {
            if self.content.is_some() {
                return Err(SurfaceReject::AlreadyCreated);
            }
            if *version != 1 {
                return Err(SurfaceReject::Version { expected: 1, actual: *version });
            }
            let content = SurfaceContent::new(
                surface_id.clone(),
                fallback_text.clone(),
                blocks.clone(),
                actions.clone(),
            )?;
            return Ok(Self { content: Some(content), version: 1, ..Self::default() });
        }
        let content = self.content.as_ref().ok_or(SurfaceReject::NotCreated)?;
        if event.surface_id() != content.surface_id() {
            return Err(SurfaceReject::WrongSurface);
        }
        let expected = self.version.checked_add(1).ok_or(SurfaceReject::VersionExhausted)?;
        if event.version() != expected {
            return Err(SurfaceReject::Version { expected, actual: event.version() });
        }
        let mut next = self.clone();
        let mut fields = content.fields.clone();
        match event {
            SurfaceEvent::Patch { base_hash, ops, .. } => {
                if base_hash != &surface_hash(content) {
                    return Err(SurfaceReject::Conflict);
                }
                if ops.len() > super::MAX_SURFACE_PATCH_OPS {
                    return Err(limits::exceeded(SurfaceLimit::PatchOperations));
                }
                for op in ops {
                    patch(&mut fields, op)?;
                }
            }
            SurfaceEvent::StreamAppend { block_id, text_delta, final_, .. } => {
                if self.final_blocks.contains(block_id) {
                    return Err(SurfaceReject::BlockClosed);
                }
                if text_delta.len() > super::MAX_SURFACE_TEXT_DELTA_BYTES {
                    return Err(limits::exceeded(SurfaceLimit::TextDeltaBytes));
                }
                let block = fields
                    .blocks
                    .iter_mut()
                    .find(|block| &block.id == block_id)
                    .ok_or(SurfaceReject::UnknownBlock)?;
                if !matches!(
                    block.kind,
                    SurfaceBlockKind::Text
                        | SurfaceBlockKind::Markdown
                        | SurfaceBlockKind::LogStream
                ) {
                    return Err(SurfaceReject::BlockNotStreamable);
                }
                let text = block
                    .data
                    .get_mut("text")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or(SurfaceReject::BlockNotStreamable)?;
                let mut appended = text;
                appended.push_str(text_delta);
                limits::text(&appended)?;
                block.data["text"] = serde_json::Value::String(appended);
                if *final_ {
                    if next.final_blocks.len() >= super::MAX_SURFACE_FINALIZED_BLOCKS {
                        return Err(limits::exceeded(SurfaceLimit::FinalizedBlocks));
                    }
                    next.final_blocks.insert(block_id.clone());
                }
            }
            SurfaceEvent::Close { .. } => next.closed = true,
            SurfaceEvent::Create { .. } => return Err(SurfaceReject::AlreadyCreated),
        }
        next.content = Some(SurfaceContent::from_fields(fields)?);
        next.version = expected;
        Ok(next)
    }

    /// Checks an authenticated decision against exactly the content currently reviewed.
    /// # Errors
    /// Rejects closed/uncreated surfaces, wrong IDs, stale version/hash, unknown/disabled actions,
    /// mismatched argument hashes or argument limits. Does not authenticate the sender.
    pub fn validate_action(&self, action: &SurfaceAction) -> Result<(), SurfaceReject> {
        if self.closed {
            return Err(SurfaceReject::Closed);
        }
        let content = self.content.as_ref().ok_or(SurfaceReject::NotCreated)?;
        if action.surface_id != content.surface_id() {
            return Err(SurfaceReject::WrongSurface);
        }
        if action.version != self.version || action.surface_hash != surface_hash(content) {
            return Err(SurfaceReject::Stale);
        }
        let definition = content
            .actions()
            .iter()
            .find(|definition| definition.id == action.action_id)
            .ok_or(SurfaceReject::UnknownAction)?;
        if definition.disabled_reason.is_some() {
            return Err(SurfaceReject::DisabledAction);
        }
        if action.args_hash != surface_args_hash(&action.values)? {
            return Err(SurfaceReject::ArgumentsHashMismatch);
        }
        Ok(())
    }
}

fn patch(
    content: &mut super::content::ContentFields,
    op: &SurfacePatchOp,
) -> Result<(), SurfaceReject> {
    match op {
        SurfacePatchOp::ReplaceBlock { block } => {
            let current = content
                .blocks
                .iter_mut()
                .find(|current| current.id == block.id)
                .ok_or(SurfaceReject::UnknownBlock)?;
            *current = block.clone();
        }
        SurfacePatchOp::InsertBlock { index, block } => {
            if *index > content.blocks.len() {
                return Err(SurfaceReject::InvalidInsertPosition);
            }
            if content.blocks.len() >= super::MAX_SURFACE_BLOCKS {
                return Err(limits::exceeded(SurfaceLimit::Blocks));
            }
            content.blocks.insert(*index, block.clone());
        }
        SurfacePatchOp::RemoveBlock { block_id } => {
            let index = content
                .blocks
                .iter()
                .position(|block| &block.id == block_id)
                .ok_or(SurfaceReject::UnknownBlock)?;
            content.blocks.remove(index);
        }
        SurfacePatchOp::SetActions { actions } => {
            if actions.len() > super::MAX_SURFACE_ACTIONS {
                return Err(limits::exceeded(SurfaceLimit::Actions));
            }
            content.actions.clone_from(actions);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_overflow_is_rejected_without_mutating_state() -> Result<(), SurfaceReject> {
        let content =
            SurfaceContent::new("s".to_owned(), "fallback".to_owned(), Vec::new(), Vec::new())?;
        let state =
            SurfaceState { content: Some(content), version: u64::MAX, ..SurfaceState::default() };
        assert_eq!(
            state.apply(&SurfaceEvent::Close { surface_id: "s".to_owned(), version: u64::MAX }),
            Err(SurfaceReject::VersionExhausted)
        );
        Ok(())
    }
}

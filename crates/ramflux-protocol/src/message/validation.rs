// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant structural validation, not native signature/role/consent admission.
//! Native field value sets and proof validation stay with the named §3.1 owners:
//! Surface P15, Call P16, Task P17, own-history P18 and `SelfSync` P19. No result
//! from this module authorizes side effects or ACK; authenticated retention is P10.
use super::{Content, Message, content, registry};
use unicode_segmentation::UnicodeSegmentation;

/// Maximum complete exact Inner bytes.
pub const MAX_INNER_BYTES: usize = 524_252;
/// Maximum nesting depth, independently of byte size.
pub const MAX_DEPTH: usize = 32;
/// Maximum UTF-8 text bytes.
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
/// Maximum entity count per message.
pub const MAX_ENTITIES: usize = 4096;
/// Maximum media count per message.
pub const MAX_MEDIA: usize = 32;
/// Maximum reaction-token UTF-8 bytes.
pub const MAX_REACTION_BYTES: usize = 64;

/// Invalid/unsafe structural input; Unsupported remains a separate scan outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// Truncated bytes, wrong wire types, or invalid scalar representation.
    #[error("malformed message encoding")]
    Malformed,
    /// Non-minimal varint, tag ordering, default scalar, or duplicate field.
    #[error("non-canonical message encoding")]
    NonCanonical,
    /// Byte, count or recursion budget exceeded.
    #[error("message resource limit exceeded")]
    Limit,
    /// A closed choice is missing or has multiple arms.
    #[error("invalid closed message choice")]
    MissingChoice,
    /// Control operation disagrees with its payload.
    #[error("control operation/payload mismatch")]
    Operation,
    /// Invalid reaction token or entity range.
    #[error("invalid message content")]
    Content,
    /// Embedded descriptor is invalid or the requested type is absent.
    #[error("invalid message descriptor")]
    Descriptor,
    /// The caller attempted typed decode of an unsupported body.
    #[error("body requires an unsupported schema")]
    Unsupported,
}

/// Structural recognition; unsupported bytes must be retained exactly by callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    /// All encoded fields and operations are structurally supported.
    Supported,
    /// Unknown constructor, field, enum/entity, or unimplemented layer.
    Unsupported,
}

/// Borrowed scan result; no prost re-encoding can replace the retained original.
#[derive(Debug)]
pub struct ScannedInner<'a> {
    /// Complete original authenticated Inner bytes.
    pub exact_inner: &'a [u8],
    /// Layer claimed by the Inner.
    pub layer: u32,
    /// Permanent kind number.
    pub kind: u32,
    /// Exact selected body bytes, never reconstructed.
    pub body: &'a [u8],
    /// Structural disposition only, never authorization.
    pub outcome: ScanOutcome,
}

/// Scan exact Inner and its descriptor-selected body before prost decoding.
/// # Errors
/// Returns an error for malformed/canonicality failures or resource exhaustion.
pub fn scan_inner(bytes: &[u8]) -> Result<ScannedInner<'_>, ValidationError> {
    let mut outcome = scan_message("Inner", bytes, registry::COMPILED_LAYER)?;
    let mut input = bytes;
    let (mut layer, mut kind, mut body) = (0, 0, &[][..]);
    while !input.is_empty() {
        let field = super::wire::field(&mut input)?;
        match field.tag {
            1 => layer = u32::try_from(field.scalar).map_err(|_| ValidationError::Malformed)?,
            2 => kind = u32::try_from(field.scalar).map_err(|_| ValidationError::Malformed)?,
            4 => body = field.bytes,
            _ => {}
        }
    }
    if let Some(binding) = registry::kind_binding(kind) {
        if layer < binding.first_layer
            || layer > registry::COMPILED_LAYER
            || scan_message(binding.body, body, layer)? == ScanOutcome::Unsupported
        {
            outcome = ScanOutcome::Unsupported;
        }
    } else {
        outcome = ScanOutcome::Unsupported;
    }
    Ok(ScannedInner { exact_inner: bytes, layer, kind, body, outcome })
}

/// Scan a generated schema leaf with explicit receiving-layer support.
/// # Errors
/// Returns an error for malformed encoding, noncanonical input or exceeded caps.
pub fn scan_message(name: &str, bytes: &[u8], layer: u32) -> Result<ScanOutcome, ValidationError> {
    if bytes.len() > MAX_INNER_BYTES {
        return Err(ValidationError::Limit);
    }
    super::scanner::scan(&registry::descriptor(name)?, bytes, layer, 0)
}

/// Validate reaction bytes without normalization on both add and remove.
/// # Errors
/// Returns an error unless the token is one non-control, nonblank grapheme.
pub fn validate_reaction_token(token: &str) -> Result<(), ValidationError> {
    if token.is_empty()
        || token.len() > MAX_REACTION_BYTES
        || token.chars().any(char::is_control)
        || token.chars().all(char::is_whitespace)
        || token.graphemes(true).count() != 1
    {
        return Err(ValidationError::Content);
    }
    Ok(())
}

/// Validate generated content scalar invariants. Native authorities stay separate.
/// # Errors
/// Returns an error for invalid scalar/count bounds, entities or control choices.
pub fn validate_content(content: &Content) -> Result<(), ValidationError> {
    match content.value.as_ref().ok_or(ValidationError::MissingChoice)? {
        content::Value::Message(message) => validate_message(message),
        content::Value::Edit(edit) => {
            validate_message(edit.replacement.as_ref().ok_or(ValidationError::Content)?)
        }
        content::Value::Reaction(reaction) => validate_reaction_token(&reaction.token),
        content::Value::Control(control) => {
            use prost::Message as _;
            let encoded = control.encode_to_vec();
            if scan_message("Control", &encoded, registry::COMPILED_LAYER)?
                != ScanOutcome::Supported
            {
                return Err(ValidationError::Unsupported);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Validate Unicode-scalar entity ranges in one pass over text plus entity rows.
/// # Errors
/// Returns an error for invalid bounds, unknown entity kinds or mixed sealed content.
pub fn validate_message(message: &Message) -> Result<(), ValidationError> {
    if message.text.len() > MAX_TEXT_BYTES
        || message.entities.len() > MAX_ENTITIES
        || message.media.len() > MAX_MEDIA
    {
        return Err(ValidationError::Limit);
    }
    if message.sealed_group.is_some()
        && (!message.text.is_empty()
            || !message.entities.is_empty()
            || !message.media.is_empty()
            || message.reply_to.is_some()
            || message.forward.is_some())
    {
        return Err(ValidationError::Content);
    }
    let scalars = message.text.chars().count();
    for entity in &message.entities {
        if !(1..=6).contains(&entity.kind) {
            return Err(ValidationError::Unsupported);
        }
        let end = entity.offset.checked_add(entity.length).ok_or(ValidationError::Content)?;
        if entity.length == 0
            || usize::try_from(end).map_err(|_| ValidationError::Content)? > scalars
        {
            return Err(ValidationError::Content);
        }
    }
    for media in &message.media {
        if media
            .inline_thumbnail
            .as_ref()
            .is_some_and(|image| image.encoded_image.len() > 16 * 1024)
        {
            return Err(ValidationError::Limit);
        }
    }
    Ok(())
}

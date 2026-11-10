// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant structural validation, not native signature/role/consent admission.
//! Native field value sets and proof validation stay with the named §3.1 owners:
//! Surface P15, Call P16, Task P17, own-history P18 and `SelfSync` P19. No result
//! from this module authorizes side effects or ACK; authenticated retention is P10.
use super::{
    Content, Delete, Edit, Entity, EntityKind, Message, MessageRef, Reaction, Receipt, Service,
    ServiceAction, content, registry,
};
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
/// Maximum `ENTITY_MENTION` rows on one Message.
pub const MAX_MENTIONS: usize = 16;
/// UTF-8 byte cap for mention-bearing text under this contract; general text stays `MAX_TEXT_BYTES`.
pub const MAX_MENTION_TEXT_BYTES: usize = 8192;
/// Unpadded base64url length of a 32-byte native account anchor.
pub const NATIVE_ACCOUNT_ANCHOR_CHARS: usize = 43;
/// Decoded native account anchor size.
pub const NATIVE_ACCOUNT_ANCHOR_BYTES: usize = 32;

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
    /// Invalid reaction token, entity range, missing Edit replacement, or empty `MessageRef`.
    #[error("invalid message content")]
    Content,
    /// Embedded descriptor is invalid or the requested type is absent.
    #[error("invalid message descriptor")]
    Descriptor,
    /// The caller attempted typed decode of an unsupported body.
    #[error("body requires an unsupported schema")]
    Unsupported,
    /// An `ENTITY_MENTION` row failed a named mention-span rule.
    #[error("invalid mention: {0}")]
    Mention(MentionError),
}

/// Exact mention-span rule that failed. Decoder never sorts or clamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MentionError {
    /// More than [`MAX_MENTIONS`] mention rows.
    #[error("mention count exceeds 16")]
    Count,
    /// Mention-bearing UTF-8 text exceeds [`MAX_MENTION_TEXT_BYTES`].
    #[error("mention-bearing text exceeds 8192 bytes")]
    TextLimit,
    /// Mention `value` is absent.
    #[error("mention is missing a native account anchor")]
    Missing,
    /// Mention `value` is not a canonical 43-character native account anchor.
    #[error("mention anchor is not a canonical 43-character native account")]
    Anchor,
    /// Mention `length` is zero.
    #[error("mention span has zero length")]
    ZeroLength,
    /// Mention span overflows or ends past the Unicode-scalar text length.
    #[error("mention span is outside the text")]
    Span,
    /// Two mention spans share a Unicode scalar.
    #[error("mention spans overlap")]
    Overlap,
    /// Mention rows are not strictly increasing by scalar offset.
    #[error("mention spans are unsorted")]
    Order,
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
        content::Value::Edit(edit) => validate_edit(edit),
        content::Value::Delete(delete) => validate_delete(delete),
        content::Value::Reaction(reaction) => validate_reaction(reaction),
        content::Value::Receipt(receipt) => validate_receipt(receipt),
        content::Value::Service(service) => validate_service(service),
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

/// Pin add/remove names exactly one target message; the target is never inferred.
/// Present `MessageRef` values must carry a non-empty id.
/// # Errors
/// Returns an error when a pin service kind has no target or any named ref is empty.
pub fn validate_service(service: &Service) -> Result<(), ValidationError> {
    let pin = service.action == ServiceAction::ServicePinAdded as i32
        || service.action == ServiceAction::ServicePinRemoved as i32;
    if pin && service.target.is_none() {
        return Err(ValidationError::Content);
    }
    validate_optional_message_ref(service.target.as_ref())
}

/// Validate Unicode-scalar entity ranges in one pass over text plus entity rows.
/// # Errors
/// Returns an error for invalid bounds, unknown entity kinds, mixed sealed content
/// or a failed mention-span rule.
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
    validate_optional_message_ref(message.reply_to.as_ref())?;
    if let Some(forward) = message.forward.as_ref() {
        validate_optional_message_ref(forward.original.as_ref())?;
    }
    validate_mention_spans(message)?;
    let scalars = message.text.chars().count();
    for entity in &message.entities {
        if entity.kind == EntityKind::EntityMention as i32 {
            continue;
        }
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

fn validate_edit(edit: &Edit) -> Result<(), ValidationError> {
    validate_optional_message_ref(edit.target.as_ref())?;
    validate_message(edit.replacement.as_ref().ok_or(ValidationError::Content)?)
}

fn validate_delete(delete: &Delete) -> Result<(), ValidationError> {
    delete.targets.iter().try_for_each(validate_message_ref)
}

fn validate_reaction(reaction: &Reaction) -> Result<(), ValidationError> {
    validate_optional_message_ref(reaction.target.as_ref())?;
    validate_reaction_token(&reaction.token)
}

fn validate_receipt(receipt: &Receipt) -> Result<(), ValidationError> {
    receipt.targets.iter().try_for_each(validate_message_ref)
}

/// A named target must identify one message; empty `id` does not name a target.
fn validate_message_ref(reference: &MessageRef) -> Result<(), ValidationError> {
    if reference.id.is_empty() {
        return Err(ValidationError::Content);
    }
    Ok(())
}

fn validate_optional_message_ref(reference: Option<&MessageRef>) -> Result<(), ValidationError> {
    reference.map_or(Ok(()), validate_message_ref)
}

fn mention_rule(error: MentionError) -> ValidationError {
    ValidationError::Mention(error)
}

/// Canonical 32-byte native account: 43 unpadded base64url characters, no aliases.
fn canonical_native_account_anchor(value: &str) -> Result<(), ValidationError> {
    if value.len() != NATIVE_ACCOUNT_ANCHOR_CHARS {
        return Err(mention_rule(MentionError::Anchor));
    }
    let raw = crate::decode_base64url(value).map_err(|_| mention_rule(MentionError::Anchor))?;
    if raw.len() != NATIVE_ACCOUNT_ANCHOR_BYTES || crate::encode_base64url(&raw) != value {
        return Err(mention_rule(MentionError::Anchor));
    }
    Ok(())
}

fn mention_span_end(entity: &Entity) -> Result<u32, ValidationError> {
    if entity.length == 0 {
        return Err(mention_rule(MentionError::ZeroLength));
    }
    entity.offset.checked_add(entity.length).ok_or(mention_rule(MentionError::Span))
}

fn mention_spans_overlap(left: &Entity, right: &Entity) -> Result<bool, ValidationError> {
    let left_end = mention_span_end(left)?;
    let right_end = mention_span_end(right)?;
    Ok(left.offset < right_end && right.offset < left_end)
}

fn mention_spans_are_sorted(mentions: &[&Entity]) -> bool {
    mentions.windows(2).all(|pair| pair[1].offset > pair[0].offset)
}

fn validate_mention_spans(message: &Message) -> Result<(), ValidationError> {
    let mentions: Vec<&Entity> = message
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::EntityMention as i32)
        .collect();
    if mentions.is_empty() {
        return Ok(());
    }
    if message.text.len() > MAX_MENTION_TEXT_BYTES {
        return Err(mention_rule(MentionError::TextLimit));
    }
    if mentions.len() > MAX_MENTIONS {
        return Err(mention_rule(MentionError::Count));
    }
    let scalars = message.text.chars().count();
    for entity in &mentions {
        let Some(value) = entity.value.as_deref() else {
            return Err(mention_rule(MentionError::Missing));
        };
        canonical_native_account_anchor(value)?;
        let end = mention_span_end(entity)?;
        if usize::try_from(end).map_err(|_| mention_rule(MentionError::Span))? > scalars {
            return Err(mention_rule(MentionError::Span));
        }
    }
    for (index, right) in mentions.iter().enumerate() {
        for left in &mentions[..index] {
            if mention_spans_overlap(left, right)? {
                return Err(mention_rule(MentionError::Overlap));
            }
        }
    }
    if !mention_spans_are_sorted(&mentions) {
        return Err(mention_rule(MentionError::Order));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_base64url;
    use prost::Message as _;

    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn anchor(byte: u8) -> String {
        encode_base64url([byte; NATIVE_ACCOUNT_ANCHOR_BYTES])
    }

    fn mention(offset: u32, length: u32, byte: u8) -> Entity {
        Entity { offset, length, kind: EntityKind::EntityMention as i32, value: Some(anchor(byte)) }
    }

    fn filled_mentions() -> Message {
        let count = u32::try_from(MAX_MENTIONS).unwrap_or(0);
        Message {
            text: "abcdefghijklmnop".into(),
            entities: (0_u32..count)
                .zip(1_u8..)
                .map(|(offset, byte)| mention(offset, 1, byte))
                .collect(),
            ..Default::default()
        }
    }

    fn assert_rule(message: &Message, error: MentionError) {
        assert_eq!(validate_message(message), Err(ValidationError::Mention(error)));
    }

    #[test]
    fn agent_mentions_bind_root_with_scalar_spans() -> Result {
        let message = filled_mentions();
        validate_message(&message)?;
        assert_eq!(message.entities.len(), MAX_MENTIONS);
        assert!(message.entities.iter().all(|entity| {
            entity.value.as_deref().is_some_and(|value| value.len() == NATIVE_ACCOUNT_ANCHOR_CHARS)
        }));

        let max_text = Message {
            text: "x".repeat(MAX_MENTION_TEXT_BYTES),
            entities: filled_mentions().entities,
            ..Default::default()
        };
        validate_message(&max_text)?;

        let emoji =
            Message {
                text: "A😀é".into(), entities: vec![mention(1, 1, 7)], ..Default::default()
            };
        validate_message(&emoji)?;
        let combining = Message {
            text: "e\u{301}".into(),
            entities: vec![mention(1, 1, 8)],
            ..Default::default()
        };
        validate_message(&combining)?;

        let body = message.encode_to_vec();
        let inner = super::super::Inner { layer: 2, kind: 1, body, identity: None };
        let wire = inner.encode_to_vec();
        let decoded = super::super::Inner::decode(wire.as_slice())?;
        assert_eq!(decoded.encode_to_vec(), wire);
        let decoded_message = Message::decode(decoded.body.as_slice())?;
        validate_message(&decoded_message)?;
        assert_eq!(decoded_message.encode_to_vec(), message.encode_to_vec());

        let mut unsorted = filled_mentions();
        unsorted.entities.swap(0, 1);
        let unsorted_bytes = unsorted.encode_to_vec();
        let unsorted_decoded = Message::decode(unsorted_bytes.as_slice())?;
        assert_eq!(
            validate_message(&unsorted_decoded),
            Err(ValidationError::Mention(MentionError::Order))
        );

        let mut over = filled_mentions();
        over.text.push('q');
        over.entities.push(mention(16, 1, 17));
        assert_rule(&over, MentionError::Count);

        let mut aliased = filled_mentions();
        let canonical = aliased.entities[0].value.clone().ok_or("anchor")?;
        let alias = canonical.replace('-', "+").replace('_', "/");
        if alias == canonical {
            aliased.entities[0].value = Some(anchor(255).replace('_', "/"));
        } else {
            aliased.entities[0].value = Some(alias);
        }
        assert_rule(&aliased, MentionError::Anchor);
        Ok(())
    }

    #[test]
    fn mention_rules_have_positive_bounds_and_exact_errors() {
        assert_eq!(validate_message(&filled_mentions()), Ok(()));
        let exact_anchor = mention(0, 1, 9);
        assert_eq!(exact_anchor.value.as_deref().map(str::len), Some(NATIVE_ACCOUNT_ANCHOR_CHARS));
        assert_eq!(
            validate_message(&Message {
                text: "x".into(),
                entities: vec![exact_anchor],
                ..Default::default()
            }),
            Ok(())
        );

        let mut missing = filled_mentions();
        missing.entities[0].value = None;
        assert_rule(&missing, MentionError::Missing);

        let mut short = filled_mentions();
        short.entities[0].value = Some(anchor(1)[..42].into());
        assert_rule(&short, MentionError::Anchor);

        let mut long = filled_mentions();
        long.entities[0].value = Some(format!("{}=", anchor(1)));
        assert_rule(&long, MentionError::Anchor);

        let mut zero = filled_mentions();
        zero.entities[0].length = 0;
        assert_rule(&zero, MentionError::ZeroLength);

        let mut outside = filled_mentions();
        outside.entities[0].offset = 16;
        assert_rule(&outside, MentionError::Span);

        let mut overflow = filled_mentions();
        overflow.entities[0].offset = u32::MAX;
        overflow.entities[0].length = 1;
        assert_rule(&overflow, MentionError::Span);

        let mut overlap = filled_mentions();
        overlap.entities[1].offset = 0;
        overlap.entities[1].length = 2;
        assert_rule(&overlap, MentionError::Overlap);

        let mut unsorted = filled_mentions();
        unsorted.entities.swap(0, 1);
        assert_rule(&unsorted, MentionError::Order);

        assert_rule(
            &Message {
                text: "x".repeat(MAX_MENTION_TEXT_BYTES + 1),
                entities: vec![mention(0, 1, 1)],
                ..Default::default()
            },
            MentionError::TextLimit,
        );
    }

    #[test]
    fn empty_message_ref_is_content_error() {
        let empty =
            MessageRef { id: vec![], conversation_id: "c".into(), author_anchor: "a".into() };
        let named =
            MessageRef { id: vec![7], conversation_id: "c".into(), author_anchor: "a".into() };
        assert_eq!(
            validate_message(&Message { reply_to: Some(empty.clone()), ..Default::default() }),
            Err(ValidationError::Content)
        );
        assert_eq!(
            validate_message(&Message {
                forward: Some(super::super::Forward {
                    original: Some(empty.clone()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            Err(ValidationError::Content)
        );
        assert_eq!(
            validate_service(&Service {
                action: ServiceAction::ServicePinAdded as i32,
                target: Some(empty.clone()),
                ..Default::default()
            }),
            Err(ValidationError::Content)
        );
        assert_eq!(
            validate_service(&Service {
                action: ServiceAction::ServicePinAdded as i32,
                target: Some(named.clone()),
                ..Default::default()
            }),
            Ok(())
        );
        assert_eq!(
            validate_content(&Content {
                value: Some(content::Value::Edit(Edit {
                    target: Some(empty.clone()),
                    replacement: Some(Message { text: "x".into(), ..Default::default() }),
                    ..Default::default()
                })),
            }),
            Err(ValidationError::Content)
        );
        assert_eq!(
            validate_content(&Content {
                value: Some(content::Value::Delete(Delete {
                    targets: vec![empty.clone()],
                    ..Default::default()
                })),
            }),
            Err(ValidationError::Content)
        );
        assert_eq!(
            validate_content(&Content {
                value: Some(content::Value::Reaction(Reaction {
                    target: Some(empty.clone()),
                    token: "👍".into(),
                    ..Default::default()
                })),
            }),
            Err(ValidationError::Content)
        );
        assert_eq!(
            validate_content(&Content {
                value: Some(content::Value::Receipt(Receipt {
                    targets: vec![empty],
                    state: 1,
                    ..Default::default()
                })),
            }),
            Err(ValidationError::Content)
        );
        assert_eq!(
            validate_message(&Message { reply_to: Some(named), ..Default::default() }),
            Ok(())
        );
    }
}

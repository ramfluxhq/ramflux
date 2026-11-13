// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical logical event identity, independent of recipient representation.
use super::{EventIdentity, QualifiedDevice, validation::ValidationError};

pub(super) fn lp(output: &mut Vec<u8>, field: &[u8]) -> Result<(), ValidationError> {
    output.extend_from_slice(
        &u32::try_from(field.len()).map_err(|_| ValidationError::Limit)?.to_be_bytes(),
    );
    output.extend_from_slice(field);
    Ok(())
}

/// Complete framed-domain event-id transcript (sweep audit r1 M2).
/// # Errors
/// Refuses incomplete identities and fields exceeding the LP framing bound.
pub fn event_transcript(
    author: &QualifiedDevice,
    conversation: &str,
    sequence: u64,
) -> Result<Vec<u8>, ValidationError> {
    if author.account_anchor.is_empty()
        || author.device_id.is_empty()
        || author.device_epoch == 0
        || conversation.is_empty()
        || sequence == 0
    {
        return Err(ValidationError::Content);
    }
    let mut bytes = Vec::new();
    lp(&mut bytes, crate::domain::MESSAGE_ID.as_bytes())?;
    lp(&mut bytes, author.account_anchor.as_bytes())?;
    lp(&mut bytes, author.device_id.as_bytes())?;
    bytes.extend_from_slice(&author.device_epoch.to_be_bytes());
    lp(&mut bytes, conversation.as_bytes())?;
    bytes.extend_from_slice(&sequence.to_be_bytes());
    Ok(bytes)
}

/// Derive the 32 raw identity bytes, shared by all copies of the logical event.
/// # Errors
/// Refuses incomplete identities and oversized fields.
pub fn derive(
    author: &QualifiedDevice,
    conversation: &str,
    sequence: u64,
) -> Result<[u8; 32], ValidationError> {
    Ok(*blake3::hash(&event_transcript(author, conversation, sequence)?).as_bytes())
}

/// Verify a durable author's claimed event id before retaining any bytes.
/// # Errors
/// Refuses invalid lengths, missing author or a transcript mismatch.
pub fn verify(identity: &EventIdentity) -> Result<(), ValidationError> {
    let author = identity.author.as_ref().ok_or(ValidationError::Content)?;
    if identity.id.as_slice()
        != derive(author, &identity.conversation_id, identity.device_sequence)?
    {
        return Err(ValidationError::Content);
    }
    Ok(())
}

/// Complete transcript binding a tombstone to its one logical Delete event.
/// # Errors
/// Refuses a non-32-byte logical event id.
pub fn tombstone_transcript(event_id: &[u8]) -> Result<Vec<u8>, ValidationError> {
    if event_id.len() != 32 {
        return Err(ValidationError::Content);
    }
    let mut bytes = Vec::new();
    lp(&mut bytes, crate::domain::MESSAGE_DELETE_TOMBSTONE.as_bytes())?;
    lp(&mut bytes, event_id)?;
    Ok(bytes)
}

/// Derive the Delete event's tombstone id.
/// # Errors
/// Refuses a non-32-byte event id.
pub fn delete_tombstone(event_id: &[u8]) -> Result<[u8; 32], ValidationError> {
    Ok(*blake3::hash(&tombstone_transcript(event_id)?).as_bytes())
}

#[cfg(test)]
#[path = "hash_vectors_tests.rs"]
mod tests;

/// Immutable Decision-10 order. Receive-time clock clipping never enters this key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EventOrder {
    /// Signed hybrid logical clock.
    pub hlc: u64,
    /// Original author's root.
    pub account_anchor: String,
    /// Original author's device.
    pub device_id: String,
    /// Original author's authorized device epoch.
    pub device_epoch: u64,
    /// Signed device sequence.
    pub device_sequence: u64,
    /// Raw event identifier used as the final tie break.
    pub id: Vec<u8>,
}

/// Construct the shared immutable order from an already authenticated durable identity.
/// # Errors
/// Refuses incomplete identity fields and transient sequence zero.
pub fn order_key(identity: &super::EventIdentity) -> Result<EventOrder, ValidationError> {
    let author = identity.author.as_ref().ok_or(ValidationError::Content)?;
    if identity.id.len() != 32
        || identity.device_sequence == 0
        || author.device_epoch == 0
        || author.account_anchor.is_empty()
        || author.device_id.is_empty()
    {
        return Err(ValidationError::Content);
    }
    Ok(EventOrder {
        hlc: identity.hlc,
        account_anchor: author.account_anchor.clone(),
        device_id: author.device_id.clone(),
        device_epoch: author.device_epoch,
        device_sequence: identity.device_sequence,
        id: identity.id.clone(),
    })
}

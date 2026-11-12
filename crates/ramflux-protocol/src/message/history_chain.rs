// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact-item history page transcripts; hashing does not authorize any item.
use super::{identity::lp, validation::ValidationError};

/// Complete history-page transcript, preserving exact received `HistoryItem` bytes.
/// # Errors
/// Refuses invalid fixed-size fields, item counts or the four-MiB page bound.
pub fn transcript(
    transfer: &[u8],
    page: u64,
    previous: &[u8],
    items: &[&[u8]],
) -> Result<Vec<u8>, ValidationError> {
    if transfer.len() != 32 || previous.len() != 32 || items.len() > 32 {
        return Err(ValidationError::Content);
    }
    let mut bytes = Vec::new();
    lp(&mut bytes, crate::domain::MESSAGE_HISTORY_PAGE.as_bytes())?;
    lp(&mut bytes, transfer)?;
    bytes.extend_from_slice(&page.to_be_bytes());
    lp(&mut bytes, previous)?;
    bytes.extend_from_slice(
        &u32::try_from(items.len()).map_err(|_| ValidationError::Limit)?.to_be_bytes(),
    );
    for item in items {
        lp(&mut bytes, item)?;
    }
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(ValidationError::Limit);
    }
    Ok(bytes)
}

/// Hash a page's exact item sequence. Native origin proof is checked separately.
/// # Errors
/// Refuses invalid transcript fields and bounds.
pub fn digest(
    transfer: &[u8],
    page: u64,
    previous: &[u8],
    items: &[&[u8]],
) -> Result<[u8; 32], ValidationError> {
    Ok(*blake3::hash(&transcript(transfer, page, previous, items)?).as_bytes())
}

/// Verify the digest over the exact wire items before decoding any `HistoryItem`.
/// Unknown item fields remain part of the digest; decode/re-encode is never a hash oracle.
/// # Errors
/// Refuses malformed/duplicate page headers, digest mismatch and page resource limits.
pub fn verify_page(bytes: &[u8]) -> Result<super::HistoryPage, ValidationError> {
    use prost::Message as _;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(ValidationError::Limit);
    }
    let mut input = bytes;
    let (mut transfer, mut page, mut previous, mut expected) = (None, None, None, None);
    let mut items = Vec::new();
    while !input.is_empty() {
        let field = super::wire::field(&mut input)?;
        match (field.tag, field.wire) {
            (1, 2) if transfer.is_none() => transfer = Some(field.bytes),
            (2, 0) if page.is_none() => page = Some(field.scalar),
            (3, 2) if previous.is_none() => previous = Some(field.bytes),
            (4, 2) if items.len() < 32 => items.push(field.bytes),
            (5, 2) if expected.is_none() => expected = Some(field.bytes),
            (1..=5, _) => return Err(ValidationError::Content),
            _ => (),
        }
    }
    let computed = digest(
        transfer.ok_or(ValidationError::Content)?,
        page.unwrap_or(0),
        previous.ok_or(ValidationError::Content)?,
        &items,
    )?;
    if expected != Some(computed.as_slice()) {
        return Err(ValidationError::Content);
    }
    super::HistoryPage::decode(bytes).map_err(|_| ValidationError::Malformed)
}

/// Verify an own-history Control without normalizing its exact nested item bytes.
/// # Errors
/// Refuses a non-history operation, duplicate operation/page fields or invalid page digest.
pub fn verify_control(bytes: &[u8]) -> Result<super::HistoryPage, ValidationError> {
    let mut input = bytes;
    let (mut operation, mut page) = (None, None);
    while !input.is_empty() {
        let field = super::wire::field(&mut input)?;
        match (field.tag, field.wire) {
            (1, 0) if operation.is_none() => operation = Some(field.scalar),
            (22, 2) if page.is_none() => page = Some(field.bytes),
            (1 | 16..=31, _) => return Err(ValidationError::Content),
            _ => (),
        }
    }
    if operation != Some(7) {
        return Err(ValidationError::Content);
    }
    verify_page(page.ok_or(ValidationError::Content)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    #[test]
    fn history_page_hashes_exact_items_before_decoding_or_normalizing()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut item =
            super::super::HistoryItem { exact_inner: vec![1, 2, 3], ..Default::default() }
                .encode_to_vec();
        item.extend_from_slice(&[0xa0, 0x06, 0x01]); // Unknown item field 100 must remain hashed.
        let transfer = [7; 32];
        let previous = [0; 32];
        let computed = digest(&transfer, 0, &previous, &[&item])?;
        let mut bytes = super::super::HistoryPage {
            transfer_id: transfer.to_vec(),
            previous_page_digest: previous.to_vec(),
            page_digest: computed.to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        bytes.push(0x22); // HistoryPage.items, wire2; this fixture is shorter than 128 bytes.
        bytes.push(u8::try_from(item.len())?);
        bytes.extend_from_slice(&item);
        let decoded = verify_page(&bytes)?;
        assert_eq!(decoded.items.len(), 1);
        let mut control = vec![8, 7, 0xb2, 1];
        prost::encoding::encode_varint(u64::try_from(bytes.len())?, &mut control);
        control.extend_from_slice(&bytes);
        assert_eq!(verify_control(&control)?, decoded);
        let mut duplicate = control.clone();
        duplicate.extend_from_slice(&[8, 7]);
        assert!(verify_control(&duplicate).is_err());
        let mut wrong_operation = control;
        wrong_operation[1] = 6;
        assert!(verify_control(&wrong_operation).is_err());
        assert!(
            verify_page(&decoded.encode_to_vec()).is_err(),
            "normalization dropped signed item bytes"
        );
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(verify_page(&bytes).is_err(), "changed exact item must fail the page digest");
        Ok(())
    }
}

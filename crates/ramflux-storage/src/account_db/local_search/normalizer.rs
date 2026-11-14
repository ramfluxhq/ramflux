// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Streaming Unicode 16 normalization; encoded ASCII terms never expose MATCH grammar.
use super::cjk::is_cjk;
use super::{
    MAX_DOCUMENT_TERMS, MAX_NORMALIZED_BYTES, MAX_SOURCE_BYTES, MAX_TOKEN_BYTES, MAX_WORD_BYTES,
    SearchControl, SearchError, SearchResult, SearchText,
};
use caseless::Caseless as _;
use search_normalization::UnicodeNormalization as _;
use search_segmentation::UnicodeSegmentation as _;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use zeroize::Zeroizing;

pub struct NormalizedDocument {
    pub tokens: SearchText,
    pub normalized: SearchText,
    pub truncated: bool,
    pub(crate) terms: BTreeSet<SearchText>,
}

pub(super) fn tables_available() -> bool {
    search_normalization::UNICODE_VERSION == (16, 0, 0)
        && search_segmentation::UNICODE_VERSION == (16, 0, 0)
        && caseless::UNICODE_VERSION == (16, 0, 0)
}

pub(super) fn normalize(text: &str, control: &SearchControl) -> SearchResult<Zeroizing<String>> {
    if !tables_available() {
        return Err(SearchError::IndexUnavailable);
    }
    let mut output = Zeroizing::new(String::new());
    for (count, ch) in text.nfkc().default_case_fold().nfkc().enumerate() {
        if count % 1_000 == 0 {
            control.check()?;
        }
        if output.len().checked_add(ch.len_utf8()).is_none_or(|len| len > MAX_NORMALIZED_BYTES) {
            return Err(SearchError::Capacity);
        }
        output.push(ch);
    }
    control.check()?;
    Ok(output)
}

/// Takes a source prefix without looking beyond the bounded input slice.
/// The final prefix grapheme is discarded on truncation: it may continue in the original.
pub(super) fn source_slice(text: &str) -> SearchResult<(&str, bool)> {
    if text.len() <= MAX_SOURCE_BYTES {
        return Ok((text, false));
    }
    let mut end = MAX_SOURCE_BYTES;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let prefix = text.get(..end).ok_or(SearchError::IndexUnavailable)?;
    let end = prefix.grapheme_indices(true).next_back().map_or(0, |(offset, _)| offset);
    Ok((text.get(..end).ok_or(SearchError::IndexUnavailable)?, true))
}

pub(super) fn visit_segments(
    text: &str,
    mut visit: impl FnMut(&str, bool, bool) -> SearchResult<bool>,
) -> SearchResult<()> {
    let mut start = 0;
    let mut mode = None;
    for (offset, ch) in text.char_indices() {
        let next = is_cjk(ch);
        if mode.is_some_and(|current| current != next) {
            let segment = text.get(start..offset).ok_or(SearchError::IndexUnavailable)?;
            if !visit(segment, mode == Some(true), false)? {
                return Ok(());
            }
            start = offset;
        }
        mode = Some(next);
    }
    if let Some(cjk) = mode {
        let segment = text.get(start..).ok_or(SearchError::IndexUnavailable)?;
        visit(segment, cjk, true)?;
    }
    Ok(())
}

pub(super) fn encode_term(prefix: char, value: &str) -> SearchResult<SearchText> {
    let mut term = Zeroizing::new(String::new());
    term.push(prefix);
    for byte in value.bytes() {
        term.push(char::from_digit(u32::from(byte >> 4), 16).ok_or(SearchError::IndexUnavailable)?);
        term.push(char::from_digit(u32::from(byte & 15), 16).ok_or(SearchError::IndexUnavailable)?);
    }
    Ok(std::mem::take(&mut *term).into())
}

/// Indexes only a bounded, grapheme-safe slice and never invents an exact word at its cut.
/// # Errors
/// Returns cancellation/deadline, unsupported Unicode tables, or an invariant refusal.
pub fn normalize_document(
    source: &str,
    control: &SearchControl,
) -> SearchResult<NormalizedDocument> {
    let (source, mut truncated) = source_slice(source)?;
    let mut normalized = match normalize(source, control) {
        Ok(value) => value,
        Err(SearchError::Capacity) => {
            return Ok(NormalizedDocument {
                tokens: SearchText::default(),
                normalized: SearchText::default(),
                truncated: true,
                terms: BTreeSet::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let mut terms = BTreeSet::new();
    let mut bytes = 0usize;
    let mut insert = |term: SearchText| -> SearchResult<bool> {
        control.check()?;
        if terms.contains(&term) {
            return Ok(true);
        }
        let charge = term.expose().len().saturating_add(1);
        if terms.len() >= MAX_DOCUMENT_TERMS || bytes.saturating_add(charge) > MAX_TOKEN_BYTES - 8 {
            return Ok(false);
        }
        bytes += charge;
        terms.insert(term);
        Ok(true)
    };
    let was_truncated = truncated;
    visit_segments(&normalized, |segment, cjk, last| {
        if cjk {
            let mut previous = None;
            for ch in segment.chars() {
                let mut scalar = [0; 4];
                if !insert(encode_term('u', ch.encode_utf8(&mut scalar))?)? {
                    truncated = true;
                    return Ok(false);
                }
                if let Some(previous) = previous {
                    let mut gram = Zeroizing::new(String::new());
                    gram.push(previous);
                    gram.push(ch);
                    if !insert(encode_term('b', &gram)?)? {
                        truncated = true;
                        return Ok(false);
                    }
                }
                previous = Some(ch);
            }
        } else {
            let mut words = segment.unicode_words().peekable();
            while let Some(word) = words.next() {
                if was_truncated && last && words.peek().is_none() {
                    continue;
                }
                if word.len() > MAX_WORD_BYTES {
                    truncated = true;
                    continue;
                }
                if !insert(encode_term('w', word)?)? {
                    truncated = true;
                    return Ok(false);
                }
            }
        }
        Ok(true)
    })?;
    let mut tokens = Zeroizing::new(String::new());
    for term in &terms {
        if !tokens.is_empty() {
            tokens.push(' ');
        }
        tokens.write_str(term.expose()).map_err(|_| SearchError::IndexUnavailable)?;
    }
    Ok(NormalizedDocument {
        tokens: std::mem::take(&mut *tokens).into(),
        normalized: std::mem::take(&mut *normalized).into(),
        truncated,
        terms,
    })
}

/// Plain original-text excerpt, bounded at complete Unicode 16 grapheme boundaries.
#[must_use]
pub fn search_excerpt(text: &str) -> SearchText {
    let (prefix, _) = source_slice(text).unwrap_or(("", true));
    let mut output = zeroize::Zeroizing::new(String::new());
    for grapheme in prefix.graphemes(true).take(super::MAX_SNIPPET_GRAPHEMES) {
        if output.len().saturating_add(grapheme.len()) > super::MAX_SNIPPET_BYTES {
            break;
        }
        output.push_str(grapheme);
    }
    std::mem::take(&mut *output).into()
}

/// Removes concealed scalar ranges and every word they intersect, preserving separators.
/// Partial hidden words must not manufacture an exact visible prefix match.
/// # Errors
/// Refuses malformed spans, oversized inputs and cancellation/deadline failures.
pub fn visible_source_text(
    source: &str,
    concealed: &[(u32, u32)],
    control: &SearchControl,
) -> SearchResult<SearchText> {
    const MAX_CONCEALED_RANGES: usize = 1024;
    if source.len() > MAX_NORMALIZED_BYTES || concealed.len() > MAX_CONCEALED_RANGES {
        return Err(SearchError::Capacity);
    }
    control.check()?;
    if concealed.is_empty() {
        return Ok(source.into());
    }
    let mut ranges = concealed.to_vec();
    if ranges.iter().any(|(start, end)| start >= end) {
        return Err(SearchError::IndexUnavailable);
    }
    ranges.sort_unstable();
    let mut range = 0usize;
    let mut offset = 0u32;
    let mut hidden_previous = false;
    let mut output = Zeroizing::new(String::new());
    for segment in source.split_word_bounds() {
        control.check()?;
        let end = offset
            .checked_add(u32::try_from(segment.chars().count()).map_err(|_| SearchError::Capacity)?)
            .ok_or(SearchError::Capacity)?;
        while ranges.get(range).is_some_and(|(_, end)| *end <= offset) {
            range += 1;
        }
        let hidden = ranges.get(range).is_some_and(|(start, _)| *start < end);
        if hidden {
            if !hidden_previous {
                output.push(' ');
            }
        } else {
            output.push_str(segment);
        }
        hidden_previous = hidden;
        offset = end;
    }
    if ranges.iter().any(|(_, end)| *end > offset) {
        return Err(SearchError::IndexUnavailable);
    }
    Ok(std::mem::take(&mut *output).into())
}

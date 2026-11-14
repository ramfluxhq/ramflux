// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed exact-word/CJK query grammar. The final word never generates a prefix operator.
use super::normalizer::{encode_term, normalize, visit_segments};
use super::{
    MAX_QUERY_CLAUSES, MAX_QUERY_TERMS, MAX_WORD_BYTES, NormalizedDocument, SearchControl,
    SearchError, SearchQuery, SearchResult, SearchText,
};
use search_segmentation::UnicodeSegmentation as _;
use std::collections::BTreeSet;
use std::fmt::Write as _;

pub struct CompiledQuery {
    pub expression: SearchText,
    pub fingerprint: [u8; 32],
    pub(crate) terms: BTreeSet<SearchText>,
    cjk_runs: Vec<SearchText>,
}
impl CompiledQuery {
    /// Revalidates the entire query against currently authorized, bounded source text.
    /// # Errors
    /// Returns cancellation or the cooperative deadline, never stale-index fallback results.
    pub fn matches(
        &self,
        source: &NormalizedDocument,
        control: &SearchControl,
    ) -> SearchResult<bool> {
        for term in &self.terms {
            control.check()?;
            if !source.terms.contains(term) {
                return Ok(false);
            }
        }
        for run in &self.cjk_runs {
            control.check()?;
            if !source.normalized.expose().contains(run.expose()) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn whitespace(ch: char) -> bool {
    matches!(ch, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{0085}' | '\u{00a0}'
        | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}'
        | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// Compiles at most sixteen AND clauses into bound, quoted ASCII terms.
/// # Errors
/// Rejects empty, oversized or overexpanded inputs before any database acquisition.
pub fn compile_query(
    request: &SearchQuery,
    control: &SearchControl,
) -> SearchResult<CompiledQuery> {
    request.validate()?;
    control.check()?;
    let mut clauses = 0;
    let mut term_count = 0usize;
    let mut terms = BTreeSet::new();
    let mut cjk_runs = Vec::new();
    for clause in request.query.expose().split(whitespace).filter(|value| !value.is_empty()) {
        clauses += 1;
        if clauses > MAX_QUERY_CLAUSES {
            return Err(SearchError::InvalidQuery);
        }
        let clause = normalize(clause, control).map_err(|error| match error {
            SearchError::Capacity => SearchError::InvalidQuery,
            other => other,
        })?;
        let mut semantic = false;
        visit_segments(&clause, |segment, cjk, _| {
            if cjk {
                semantic = true;
                cjk_runs.push(SearchText::from(segment));
                let mut chars = segment.chars();
                if let Some(mut previous) = chars.next() {
                    let mut more = false;
                    for ch in chars {
                        more = true;
                        let mut gram = zeroize::Zeroizing::new(String::new());
                        gram.push(previous);
                        gram.push(ch);
                        terms.insert(encode_term('b', &gram)?);
                        term_count += 1;
                        previous = ch;
                        if term_count > MAX_QUERY_TERMS {
                            return Err(SearchError::InvalidQuery);
                        }
                    }
                    if !more {
                        let mut scalar = [0; 4];
                        terms.insert(encode_term('u', previous.encode_utf8(&mut scalar))?);
                        term_count += 1;
                    }
                }
            } else {
                for word in segment.unicode_words() {
                    semantic = true;
                    if word.len() > MAX_WORD_BYTES {
                        return Err(SearchError::InvalidQuery);
                    }
                    terms.insert(encode_term('w', word)?);
                    term_count += 1;
                    if term_count > MAX_QUERY_TERMS {
                        return Err(SearchError::InvalidQuery);
                    }
                }
            }
            if term_count > MAX_QUERY_TERMS {
                return Err(SearchError::InvalidQuery);
            }
            Ok(true)
        })?;
        if !semantic {
            return Err(SearchError::InvalidQuery);
        }
    }
    if terms.is_empty() {
        return Err(SearchError::InvalidQuery);
    }
    let mut expression = zeroize::Zeroizing::new(String::new());
    for term in &terms {
        if !expression.is_empty() {
            expression.push_str(" AND ");
        }
        write!(&mut *expression, "\"{}\"", term.expose())
            .map_err(|_| SearchError::IndexUnavailable)?;
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"ramflux.local-search.query.v1");
    hash.update(
        &u64::try_from(expression.len()).map_err(|_| SearchError::InvalidQuery)?.to_le_bytes(),
    );
    hash.update(expression.as_bytes());
    hash.update(
        &u64::try_from(cjk_runs.len()).map_err(|_| SearchError::InvalidQuery)?.to_le_bytes(),
    );
    for run in &cjk_runs {
        hash.update(
            &u64::try_from(run.expose().len())
                .map_err(|_| SearchError::InvalidQuery)?
                .to_le_bytes(),
        );
        hash.update(run.expose().as_bytes());
    }
    hash.update(
        &u64::try_from(request.kinds.len()).map_err(|_| SearchError::InvalidQuery)?.to_le_bytes(),
    );
    for kind in &request.kinds {
        hash.update(&kind.ordinal().to_le_bytes());
    }
    hash.update(&[u8::from(request.conversation_id.is_some())]);
    if let Some(scope) = &request.conversation_id {
        hash.update(
            &u64::try_from(scope.len()).map_err(|_| SearchError::InvalidQuery)?.to_le_bytes(),
        );
        hash.update(scope.as_bytes());
    }
    hash.update(&[u8::from(request.include_snippets)]);
    Ok(CompiledQuery {
        expression: std::mem::take(&mut *expression).into(),
        fingerprint: *hash.finalize().as_bytes(),
        terms,
        cjk_runs,
    })
}

impl CompiledQuery {
    /// Maps normalized matches back to complete original-text graphemes in a bounded excerpt.
    /// # Errors
    /// Returns work/cancellation failures without displaying normalized text.
    pub fn highlights(
        &self,
        excerpt: &str,
        control: &SearchControl,
    ) -> SearchResult<Vec<super::SearchHighlight>> {
        if excerpt.len() > super::MAX_SNIPPET_BYTES {
            return Err(SearchError::Capacity);
        }
        let mut normalized = zeroize::Zeroizing::new(String::new());
        let mut mapping = Vec::new();
        for (offset, grapheme) in excerpt.grapheme_indices(true).take(super::MAX_SNIPPET_GRAPHEMES)
        {
            let value = normalize(grapheme, control)?;
            let start = normalized.len();
            normalized.push_str(&value);
            mapping.push((start, normalized.len(), offset, offset + grapheme.len()));
        }
        let mut ranges = std::collections::BTreeSet::new();
        let mut offset = 0usize;
        visit_segments(&normalized, |segment, cjk, _| {
            if !cjk {
                for (start, word) in segment.unicode_word_indices() {
                    if word.len() <= MAX_WORD_BYTES && self.terms.contains(&encode_term('w', word)?)
                    {
                        ranges.insert((offset + start, offset + start + word.len()));
                    }
                }
            }
            offset += segment.len();
            Ok(true)
        })?;
        for run in &self.cjk_runs {
            for (start, value) in normalized.match_indices(run.expose()) {
                ranges.insert((start, start + value.len()));
            }
        }
        let mut highlights = Vec::new();
        for (start, end) in ranges.into_iter().take(super::MAX_SNIPPET_GRAPHEMES) {
            control.check()?;
            let Some(first) = mapping.iter().find(|(_, to, _, _)| *to > start) else { continue };
            let Some(last) = mapping.iter().rev().find(|(from, _, _, _)| *from < end) else {
                continue;
            };
            highlights.push(super::SearchHighlight {
                start: u32::try_from(first.2).map_err(|_| SearchError::IndexUnavailable)?,
                end: u32::try_from(last.3).map_err(|_| SearchError::IndexUnavailable)?,
            });
        }
        Ok(highlights)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_search::{MAX_QUERY_BYTES, normalize_document};
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn compiler_exact_words_cjk_and_unicode16() -> TestResult {
        for (query, text, expected) in [
            ("中", "中文", true),
            ("中文", "中 文", false),
            ("東京都", "東京 都", false),
            ("東京都", "東京都", true),
            ("甲乙丙", "甲乙 乙丙", false),
            ("中文 abc", "ＡＢＣ 中文", true),
            ("STRASSE", "Straße", true),
            ("café", "cafe\u{301}", true),
            ("cafe", "café", false),
            ("cat", "catalog", false),
            ("alpha OR beta", "alpha beta", false),
            ("alpha OR beta", "alpha or beta", true),
            ("한국", "한국어", true),
            ("かな", "か な", false),
        ] {
            let control = SearchControl::new();
            let query = compile_query(&SearchQuery::new("request", query), &control)?;
            let document = normalize_document(text, &control)?;
            assert_eq!(
                query.matches(&document, &control)?,
                expected,
                "complete exact-word/contiguous-script matching violated"
            );
            assert!(
                !query.expression.expose().contains('*'),
                "compiler must never generate a prefix operator"
            );
        }
        let mut left = SearchQuery::new("left", "cat");
        left.kinds = vec![super::super::SearchKind::Message];
        left.conversation_id = Some(format!("{}thread", "\0".repeat(8)));
        let mut right = SearchQuery::new("right", "cat");
        right.kinds =
            vec![super::super::SearchKind::Message, super::super::SearchKind::Conversation];
        right.conversation_id = Some("thread".into());
        assert_ne!(
            compile_query(&left, &SearchControl::new())?.fingerprint,
            compile_query(&right, &SearchControl::new())?.fingerprint,
            "cursor fingerprints must frame kind counts and scope bytes without concatenation ambiguity"
        );
        let request = SearchQuery::new("request", "a".repeat(MAX_QUERY_BYTES + 1));
        assert!(
            matches!(
                compile_query(&request, &SearchControl::new()),
                Err(SearchError::InvalidQuery)
            ),
            "over-limit query must be rejected before SQL"
        );
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate keyset traversal, full-query source verification and page byte accounting.
use super::{Admission, LocalSearch, SearchCompletion, hydration};
use crate::{RamfluxClient, SdkError};
use ramflux_storage::local_search::{
    CompiledQuery, MAX_CANDIDATES, MAX_PAGE_BYTES, SearchCandidate, SearchControl, SearchCoverage,
    SearchError, SearchItem, SearchKind, SearchPage, SearchQuery, SearchText, compile_query,
    normalize_document, search_excerpt,
};
struct PageWork<'a> {
    client: &'a RamfluxClient,
    request: &'a SearchQuery,
    compiled: &'a CompiledQuery,
    control: &'a SearchControl,
}
struct Collected {
    items: Vec<SearchItem>,
    kind: SearchKind,
    before: i64,
    finished: bool,
}
impl LocalSearch {
    pub(crate) fn execute_query(
        &self,
        client: &RamfluxClient,
        owner: u64,
        request: &SearchQuery,
        admission: Admission,
    ) -> Result<SearchCompletion, SdkError> {
        request.validate()?;
        if !admission.belongs_to(owner, &request.request_id) {
            return Err(SearchError::PermissionDenied.into());
        }
        let control = &admission.control;
        let compiled = compile_query(request, control)?;
        let epoch = self.epoch(client, control)?;
        let stamp = self.watch.stamp();
        let position = if let Some(cursor) = request.cursor.as_ref() {
            self.cursors.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take(
                owner,
                &self.account,
                compiled.fingerprint,
                epoch,
                cursor.expose(),
            )?
        } else {
            (SearchKind::Conversation, i64::MAX)
        };
        let collected = self
            .collect_page(&PageWork { client, request, compiled: &compiled, control }, position)?;
        let next_cursor = if collected.finished {
            None
        } else {
            Some(self.cursors.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(
                owner,
                &self.account,
                compiled.fingerprint,
                epoch,
                (collected.kind, collected.before),
            )?)
        };
        let status = client.account_db()?.search_index_status(&self.activation, control)?;
        if self.epoch(client, control)? != epoch || self.watch.stamp() != stamp {
            return Err(SearchError::CursorStale.into());
        }
        let page = SearchPage {
            items: collected.items,
            next_cursor,
            view_epoch: epoch,
            coverage: status.coverage,
            incomplete: !collected.finished || status.coverage != SearchCoverage::Complete,
        };
        self.register_completion(client, (owner, &request.request_id), page, stamp, admission)
    }
    fn collect_page(
        &self,
        work: &PageWork<'_>,
        (mut kind, mut before): (SearchKind, i64),
    ) -> Result<Collected, SdkError> {
        let db = work.client.account_db()?;
        let limit = usize::try_from(work.request.limit).map_err(|_| SearchError::InvalidQuery)?;
        let mut items = Vec::new();
        let mut used = 0usize;
        let mut examined = 0;
        while examined < MAX_CANDIDATES {
            work.control.check()?;
            if !work.request.kinds.contains(&kind) {
                if let Some(next) = next_kind(kind) {
                    kind = next;
                    before = i64::MAX;
                    continue;
                }
                return Ok(Collected { items, kind, before, finished: true });
            }
            let candidates =
                db.search_candidates(&self.activation, work.compiled, kind, before, work.control)?;
            if candidates.is_empty() {
                if let Some(next) = next_kind(kind) {
                    kind = next;
                    before = i64::MAX;
                    continue;
                }
                return Ok(Collected { items, kind, before, finished: true });
            }
            for candidate in candidates {
                work.control.check()?;
                if examined >= MAX_CANDIDATES || items.len() >= limit {
                    return Ok(Collected { items, kind, before, finished: false });
                }
                examined += 1;
                if let Some(item) = self.hydrate_candidate(work, &candidate)? {
                    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&item)?);
                    if used.saturating_add(encoded.len()) > MAX_PAGE_BYTES - 2048 {
                        return Ok(Collected { items, kind, before, finished: false });
                    }
                    used = used.saturating_add(encoded.len());
                    items.push(item);
                }
                before = candidate.doc_id;
            }
        }
        Ok(Collected { items, kind, before, finished: false })
    }
    fn hydrate_candidate(
        &self,
        work: &PageWork<'_>,
        candidate: &SearchCandidate,
    ) -> Result<Option<SearchItem>, SdkError> {
        if work
            .request
            .conversation_id
            .as_ref()
            .is_some_and(|scope| *scope != candidate.conversation_id)
        {
            return Ok(None);
        }
        let sources = hydration::sources(
            work.client,
            &self.activation,
            candidate.kind,
            &candidate.source_key,
            work.control,
        )?;
        let Some(source) = sources.into_iter().find(|source| {
            source.kind == candidate.kind
                && source.source_ref == candidate.source_ref
                && source.conversation_id == candidate.conversation_id
                && source.message_id == candidate.message_id
                && source.revision == candidate.source_revision
                && source.fingerprint() == candidate.source_hash
        }) else {
            return Ok(None);
        };
        let normalized = normalize_document(source.text.expose(), work.control)?;
        if !work.compiled.matches(&normalized, work.control)? {
            return Ok(None);
        }
        let snippet = work.request.include_snippets.then(|| search_excerpt(source.text.expose()));
        let highlights = snippet
            .as_ref()
            .map(|snippet| work.compiled.highlights(snippet.expose(), work.control))
            .transpose()?
            .unwrap_or_default();
        Ok(Some(SearchItem {
            kind: source.kind,
            id: source.source_ref.into(),
            conversation_id: source.conversation_id.into(),
            message_id: source.message_id.map(SearchText::from),
            source_revision: source.revision,
            timestamp: source.timestamp,
            title: (source.kind == SearchKind::Conversation)
                .then(|| search_excerpt(source.text.expose())),
            snippet,
            highlights,
        }))
    }
}
fn next_kind(kind: SearchKind) -> Option<SearchKind> {
    match kind {
        SearchKind::Conversation => Some(SearchKind::Message),
        SearchKind::Message => Some(SearchKind::Attachment),
        SearchKind::Attachment => None,
    }
}

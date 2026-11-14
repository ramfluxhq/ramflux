// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared SDK search values and fixed resource ceilings. Payloads redact Debug and erase on drop.
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Volatile identity of one open account writer; query readers share it.
/// It is never serialized into an account archive or reused on unlock/reopen.
#[derive(Clone, Default)]
pub struct SearchAccountIncarnation(std::sync::Arc<()>);
impl PartialEq for SearchAccountIncarnation {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for SearchAccountIncarnation {}
impl PartialOrd for SearchAccountIncarnation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SearchAccountIncarnation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        std::sync::Arc::as_ptr(&self.0).cmp(&std::sync::Arc::as_ptr(&other.0))
    }
}

/// Deliberately independent of the message protocol generation and default-off.
pub const LOCAL_SEARCH_V1: bool = false;
/// Qualification is a separate controller decision backed by pinned-engine corpus measurements.
pub const LOCAL_SEARCH_ENGINE_QUALIFIED: bool = false;
pub const SEARCH_FORMAT: u32 = 1;
pub const MAX_QUERY_BYTES: usize = 1_024;
pub const MAX_QUERY_CLAUSES: usize = 16;
pub const MAX_QUERY_TERMS: usize = 128;
pub const MAX_WORD_BYTES: usize = 256;
pub const MAX_SOURCE_BYTES: usize = 32 * 1_024;
pub const MAX_NORMALIZED_BYTES: usize = 128 * 1_024;
pub const MAX_TOKEN_BYTES: usize = 64 * 1_024;
pub const MAX_DOCUMENT_TERMS: usize = 4_096;
pub const MAX_DOCUMENTS: u64 = 1_000_000;
pub const MAX_INDEX_BYTES: u64 = 512 * 1_024 * 1_024;
pub const MAX_CANDIDATES: usize = 128;
pub const MAX_PAGE_BYTES: usize = 64 * 1_024;
pub const MAX_SNIPPET_BYTES: usize = 512;
pub const MAX_SNIPPET_GRAPHEMES: usize = 160;
pub const MAX_CURSORS: usize = 8;
pub const MAX_CURSOR_BYTES: usize = 32 * 1_024;
pub const MAX_VM_STEPS: usize = 2_000_000;
pub const VM_CALLBACK_STEPS: i32 = 1_000;
pub const MAX_DIRTY_SOURCES: usize = 4_096;
pub const MAX_REBUILD_SOURCES: usize = 128;
pub const MAX_REBUILD_BYTES: usize = 256 * 1_024;

/// A confidential string. Debug never prints its contents.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SearchText(String);
impl SearchText {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl From<String> for SearchText {
    fn from(value: String) -> Self {
        Self(value)
    }
}
impl From<&str> for SearchText {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}
impl std::borrow::Borrow<str> for SearchText {
    fn borrow(&self) -> &str {
        self.expose()
    }
}
impl AsRef<str> for SearchText {
    fn as_ref(&self) -> &str {
        self.expose()
    }
}
impl std::fmt::Debug for SearchText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SearchText([redacted])")
    }
}
impl Drop for SearchText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Refusals never carry the query, token stream or snippet.
#[derive(thiserror::Error)]
pub enum SearchError {
    #[error("SearchInvalidQuery")]
    InvalidQuery,
    #[error("SearchNotActivated")]
    NotActivated,
    #[error("AccountLocked")]
    AccountLocked,
    #[error("PermissionDenied")]
    PermissionDenied,
    #[error("SearchDeadlineExceeded")]
    Deadline,
    #[error("SearchCapacity")]
    Capacity,
    #[error("SearchCancelled")]
    Cancelled,
    #[error("SearchCursorStale")]
    CursorStale,
    #[error("SearchIndexUnavailable")]
    IndexUnavailable,
    #[error("search storage operation failed")]
    Storage(#[from] crate::StorageError),
}
impl std::fmt::Debug for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl From<rusqlite::Error> for SearchError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.into())
    }
}

/// Sealed activation proof; production callers cannot override generation zero.
#[derive(Clone)]
pub struct SearchActivation {
    _private: (),
    test_only: bool,
}
impl SearchActivation {
    /// # Errors
    /// Refuses before account acquisition while the compiled capability is dormant.
    pub fn configured() -> SearchResult<Self> {
        if !LOCAL_SEARCH_V1 {
            return Err(SearchError::NotActivated);
        }
        if !LOCAL_SEARCH_ENGINE_QUALIFIED {
            return Err(SearchError::IndexUnavailable);
        }
        Ok(Self { _private: (), test_only: false })
    }
    pub(super) fn permits_owner(&self, db: &super::super::AccountDb) -> bool {
        self.test_only || db.search_restore_admitted
    }
    #[cfg(any(
        test,
        all(
            feature = "test-instrumentation",
            ramflux_itest,
            not(ramflux_release_profile),
            not(ramflux_production)
        )
    ))]
    #[doc(hidden)]
    #[must_use]
    pub fn testing() -> Self {
        Self { _private: (), test_only: true }
    }
}

pub type SearchResult<T> = Result<T, SearchError>;
impl SearchError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidQuery => "SearchInvalidQuery",
            Self::NotActivated => "SearchNotActivated",
            Self::AccountLocked => "AccountLocked",
            Self::PermissionDenied => "PermissionDenied",
            Self::Deadline => "SearchDeadlineExceeded",
            Self::Capacity => "SearchCapacity",
            Self::Cancelled => "SearchCancelled",
            Self::CursorStale => "SearchCursorStale",
            Self::IndexUnavailable => "SearchIndexUnavailable",
            Self::Storage(_) => "Storage",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
    Conversation,
    Message,
    Attachment,
}
impl SearchKind {
    #[must_use]
    pub const fn ordinal(self) -> i64 {
        match self {
            Self::Conversation => 0,
            Self::Message => 1,
            Self::Attachment => 2,
        }
    }
    /// # Errors
    /// Refuses corrupt derived index values.
    pub fn from_ordinal(value: i64) -> SearchResult<Self> {
        match value {
            0 => Ok(Self::Conversation),
            1 => Ok(Self::Message),
            2 => Ok(Self::Attachment),
            _ => Err(SearchError::IndexUnavailable),
        }
    }
}
fn all_kinds() -> Vec<SearchKind> {
    vec![SearchKind::Conversation, SearchKind::Message, SearchKind::Attachment]
}
const fn default_limit() -> u32 {
    20
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    pub request_id: String,
    pub query: SearchText,
    #[serde(default = "all_kinds")]
    pub kinds: Vec<SearchKind>,
    pub conversation_id: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: u32,
    pub cursor: Option<SearchText>,
    #[serde(default)]
    pub include_snippets: bool,
}
impl SearchQuery {
    #[must_use]
    pub fn new(request_id: impl Into<String>, query: impl Into<SearchText>) -> Self {
        Self {
            request_id: request_id.into(),
            query: query.into(),
            kinds: all_kinds(),
            conversation_id: None,
            limit: default_limit(),
            cursor: None,
            include_snippets: false,
        }
    }
    /// Checks all input bounds before database work or derived allocation.
    /// # Errors
    /// Returns only a fixed query refusal, never an input-bearing diagnostic.
    pub fn validate(&self) -> SearchResult<()> {
        if self.query.expose().is_empty()
            || self.query.expose().len() > MAX_QUERY_BYTES
            || self.request_id.is_empty()
            || self.request_id.len() > 128
            || self.kinds.is_empty()
            || self.kinds.len() > 3
            || !(1..=50).contains(&self.limit)
            || self.conversation_id.as_ref().is_some_and(|id| id.is_empty() || id.len() > 256)
            || self.cursor.as_ref().is_some_and(|token| token.expose().len() > 128)
        {
            return Err(SearchError::InvalidQuery);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SearchViewEpoch {
    #[serde(with = "decimal")]
    pub unlock: u64,
    #[serde(with = "decimal")]
    pub publication: u64,
    #[serde(with = "decimal")]
    pub erasure: u64,
    #[serde(with = "decimal")]
    pub index: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchCoverage {
    Disabled,
    Building,
    Lagging,
    Complete,
    Truncated,
    QuotaLimited,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchRebuildState {
    Queued,
    Running,
    Paused,
    Cancelled,
    Failed,
    Complete,
    QuotaLimited,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchRebuildProgress {
    pub job_id: SearchText,
    pub state: SearchRebuildState,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchIndexStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebuild: Option<SearchRebuildProgress>,
    pub format: u32,
    pub normalizer: String,
    pub coverage: SearchCoverage,
    #[serde(with = "decimal")]
    pub indexed_documents: u64,
    pub view_epoch: Option<SearchViewEpoch>,
}
impl SearchIndexStatus {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            rebuild: None,
            format: SEARCH_FORMAT,
            normalizer: "unicode16-nfkc-casefold-1".to_owned(),
            coverage: SearchCoverage::Disabled,
            indexed_documents: 0,
            view_epoch: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchHighlight {
    pub start: u32,
    pub end: u32,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SearchItem {
    pub kind: SearchKind,
    pub id: SearchText,
    pub conversation_id: SearchText,
    pub message_id: Option<SearchText>,
    #[serde(with = "decimal")]
    pub source_revision: u64,
    pub timestamp: i64,
    pub title: Option<SearchText>,
    pub snippet: Option<SearchText>,
    pub highlights: Vec<SearchHighlight>,
}
#[derive(Serialize, Deserialize)]
pub struct SearchPage {
    pub items: Vec<SearchItem>,
    pub next_cursor: Option<SearchText>,
    pub view_epoch: SearchViewEpoch,
    pub coverage: SearchCoverage,
    pub incomplete: bool,
}

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(
        value: impl std::borrow::Borrow<u64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.borrow().to_string())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 20
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || value.len() > 1 && value.starts_with('0')
        {
            return Err(serde::de::Error::custom("invalid search counter"));
        }
        value.parse().map_err(|_| serde::de::Error::custom("invalid search counter"))
    }
}

/// Only IDs and locally authorized visible text enter index preparation. Never log this value.
pub struct SearchSource {
    pub kind: SearchKind,
    pub source_ref: String,
    pub source_key: String,
    pub conversation_id: String,
    pub message_id: Option<String>,
    pub revision: u64,
    pub timestamp: i64,
    pub expires_at: Option<i64>,
    pub text: SearchText,
    pub dependencies: Vec<SearchDependency>,
}
#[derive(Clone)]
pub struct SearchDependency {
    pub table: String,
    pub key: String,
}
impl SearchSource {
    /// # Errors
    /// Rejects oversized identifiers/dependencies before derived allocation or SQL.
    pub fn validate(&self) -> SearchResult<()> {
        if self.source_ref.is_empty()
            || self.source_ref.len() > MAX_QUERY_BYTES
            || self.source_key.is_empty()
            || self.source_key.len() > 256
            || self.conversation_id.is_empty()
            || self.conversation_id.len() > 256
            || self.message_id.as_ref().is_some_and(|id| id.is_empty() || id.len() > 256)
            || self.dependencies.len() > MAX_DOCUMENT_TERMS
        {
            return Err(SearchError::IndexUnavailable);
        }
        let mut bytes = 0usize;
        for dependency in &self.dependencies {
            bytes =
                bytes.saturating_add(dependency.table.len()).saturating_add(dependency.key.len());
            if dependency.table.len() > 128
                || dependency.key.len() > MAX_QUERY_BYTES
                || bytes > MAX_TOKEN_BYTES
            {
                return Err(SearchError::Capacity);
            }
        }
        Ok(())
    }
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"ramflux.local-search.source.v1");
        for field in [
            self.source_ref.as_str(),
            self.source_key.as_str(),
            self.conversation_id.as_str(),
            self.text.expose(),
        ] {
            hash.update(&(field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(&self.revision.to_le_bytes());
        hash.update(&[u8::from(self.expires_at.is_some())]);
        hash.update(&self.expires_at.unwrap_or_default().to_le_bytes());
        *hash.finalize().as_bytes()
    }
}

pub struct SearchCandidate {
    pub doc_id: i64,
    pub kind: SearchKind,
    pub source_ref: String,
    pub source_key: String,
    pub conversation_id: String,
    pub message_id: Option<String>,
    pub source_revision: u64,
    pub timestamp: i64,
    pub source_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchIndexRevision {
    pub epoch: i64,
    pub revision: i64,
    pub canonical: i64,
}

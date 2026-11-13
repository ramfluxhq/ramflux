// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-local search, shared by Rust and local-bus binding dispatch.
pub(crate) mod admission;
pub mod capability;
mod cursor;
mod hydration;
mod projection;
pub(crate) mod rebuild_job;
mod service;
pub use ramflux_storage::local_search::{
    SearchCoverage, SearchError, SearchHighlight, SearchIndexStatus, SearchItem, SearchKind,
    SearchPage, SearchQuery, SearchRebuildProgress, SearchRebuildState, SearchText,
    SearchViewEpoch,
};
pub use service::{LocalSearch, SearchCompletion};

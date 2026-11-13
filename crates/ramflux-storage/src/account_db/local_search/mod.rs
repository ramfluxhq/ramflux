// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-local, derived encrypted search. Activation is a separate owner decision.
mod cjk;
mod compact;
mod control;
pub(crate) mod lifecycle;
mod normalizer;
mod operations;
mod query;
mod rebuild;
pub use rebuild::SearchRebuildBatch;
mod schema;
mod sources;
pub use sources::SearchMessageInput;
mod types;
mod watch;
pub use control::SearchControl;
pub use normalizer::{NormalizedDocument, normalize_document, search_excerpt};
pub use query::{CompiledQuery, compile_query};
pub use types::*;
pub use watch::{SearchRegistration, SearchWatch};

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Startup state remains private until recovery durability has completed.
use ramflux_node_core::{RouterCore, RouterRedbStore};
use std::path::Path;

pub(crate) fn load(path: impl AsRef<Path>) -> anyhow::Result<(RouterCore, RouterRedbStore)> {
    let store = RouterRedbStore::open(path)?;
    let router = store.load_router()?.unwrap_or_default();
    Ok((router, store))
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent account couriers exchange owned network inputs with the writer.

pub(crate) mod directory;

pub(crate) mod pair_material;

pub(crate) mod writer;

pub(crate) mod runner;

pub(crate) mod federation;

pub(crate) mod primary;

#[cfg(test)]
pub(crate) mod test_pass;

pub(crate) mod surface;

pub(crate) mod reset;
pub(crate) mod self_sync;

#[cfg(test)]
mod tests;

pub(crate) mod head_refresh;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant independent checkpoint components. OS authentication, protected provisioning and
//! actual transport writers belong to the service integration; no public route is installed.
mod checkpoint;
pub use checkpoint::*;
mod config;
pub use config::*;
mod errors;
pub use errors::*;
mod transport;
pub use transport::*;
mod fence;
mod image;
pub use fence::*;
mod center;
mod transitions;
pub use center::*;
mod publication;
pub use publication::*;
mod checkpoint_batch;
mod checkpoint_group;
mod cleanup;
mod delete;
mod primary;
mod reporting;
pub use primary::*;
mod recovery;
pub use recovery::*;
mod schema;
pub use schema::*;
mod home;
pub use home::*;
#[cfg(test)]
mod checkpoint_tests;
#[cfg(test)]
use redb::ReadableTable;

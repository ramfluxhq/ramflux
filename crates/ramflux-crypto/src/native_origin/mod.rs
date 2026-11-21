// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable native origin proofs shared by SDK ingestion and storage transfer owners.
use ramflux_protocol::message::{self as g, original_header::EvidenceError};
mod authored;
mod authority;
pub use authored::OwnAuthoredCapture;
mod group;
mod original_header;
mod own_sent;
pub use original_header::{OriginalHeader, VerifiedOriginalHeader};
mod routing;
pub use authority::{Author, authority, verify_public_authority};
pub use own_sent::OwnSentAttestation;
pub use routing::{Kind, Provenance, Routing};

mod retained;
pub use retained::{RetainedOrigin, VerifiedOrigin};

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant native DM bootstrap components, separate from application message grammars.
//! Validation here establishes canonical framing, not signatures or current authority.
mod codec;
pub(crate) use codec::valid_custody_id;
pub use codec::{DecodeError, Field, Fields, Scanned, WireType, scan};

#[cfg(test)]
mod codec_tests;

mod publication;
pub use publication::{
    MAX_ADDITIVE_OPKS, MAX_RETIREMENT_REFS, NATIVE_PREKEY_PROFILE, OwnerPrekeyUpdate,
    PrekeyPublicationSnapshot, QualifiedBranch, RetirementRef, SignedNativeOpk,
    SignedNativePrekeyBase,
};

#[cfg(test)]
mod publication_tests;

mod lease;
pub use lease::{
    LeaseFallback, MAX_OWNER_STATUS_ENTRIES, OwnerPrekeyState, OwnerPrekeyStatus, OwnerStatusEntry,
    OwnerStatusQuery, PrekeyLeaseIntent, PrekeyLeaseResult, PublicPrekeyView,
};
mod deadline;
pub use deadline::{BootstrapMode, DeadlineError, DeadlineInputs, validate_bootstrap_deadline};
#[cfg(test)]
mod deadline_tests;
#[cfg(test)]
mod lease_tests;

mod request;
pub use request::{NativePrekeyAction, NativePrekeyRequest};
mod refusal;
pub use refusal::DmFsV3Refusal;
mod frames;
pub use frames::{
    NativePrekeyFrame, NativePrekeyLease, NativePrekeyPublish, NativePrekeyResult,
    NativePrekeyResultKind, NativePrekeyStatus,
};
mod header;
pub use header::{BootstrapHeader, BootstrapTranscript};
#[cfg(test)]
mod service_tests;

#[cfg(test)]
mod custody_tests;

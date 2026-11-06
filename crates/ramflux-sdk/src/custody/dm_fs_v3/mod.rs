// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant pure adapters. Current authority, clock trust and admission are caller-owned.
mod builders;
mod refusal;
mod verify;
pub use builders::{
    build_base, build_lease_intent, build_opk, build_owner_update, build_publication_snapshot,
    build_request,
};
pub use refusal::DmFsV3Refusal;
pub use verify::{verify_lease_result, verify_owner_status, verify_public_view};
// Reuse the existing scoped owners; never project secrets into SDK credentials or snapshots.
pub use ramflux_crypto::dm_fs_v3::{
    NativeInitiatorHandoff, NativeInitiatorInput, NativeRecipientHandoff, NativeRecipientInput,
    native_initiator, native_recipient,
};
#[cfg(test)]
mod tests;

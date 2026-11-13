// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed refusal while native A2I binding/grant authority has no durable contract.
use crate::{RamfluxClient, SdkError};

impl RamfluxClient {
    /// A signed document is not a durable native binding/grant authorization.
    /// # Errors
    /// Always returns the typed Authority refusal until a native contract exists.
    pub(crate) fn require_a2i_binding_authority() -> Result<(), SdkError> {
        Self::refuse_a2i_binding_authority()
    }

    /// Refuse an A2I result without introducing an impossible-success panic path.
    /// # Errors
    /// Always returns the same typed Authority refusal for every result type.
    pub(crate) fn refuse_a2i_binding_authority<T>() -> Result<T, SdkError> {
        Err(super::authority("a2i native binding/grant authority is not installed"))
    }
}

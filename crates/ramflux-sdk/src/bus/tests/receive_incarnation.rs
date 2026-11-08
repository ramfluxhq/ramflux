// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant incarnation reset adapter is linked for P20/P24. Named cells live in storage.
use crate::bus::sync_driver::source::reset::SourceReset;

#[test]
fn dormant_reset_adapter_is_linked() {
    assert!(std::mem::size_of::<SourceReset<'static>>() > 0);
}

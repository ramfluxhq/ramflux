// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant hold adapter is linked for P20. Named cells live in ramflux-storage `hold_tests`.
use crate::bus::sync_driver::source::hold::{HoldDisposition, SourceHold};

#[test]
fn dormant_hold_adapter_is_linked() {
    assert!(std::mem::size_of::<SourceHold<'static>>() > 0);
    assert_eq!(HoldDisposition::Paused, HoldDisposition::Paused);
}

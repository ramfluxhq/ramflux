// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant failure-policy adapter is linked for P20. Named cells live in ramflux-storage
//! `removal_tests`.
use crate::bus::sync_driver::source::failure::SourceFailure;
use ramflux_storage::ReceiveFailureReason;

#[test]
fn dormant_failure_adapter_is_linked() {
    assert!(std::mem::size_of::<SourceFailure<'static>>() > 0);
    assert_eq!(SourceFailure::expired(), ReceiveFailureReason::HeldExpired);
}

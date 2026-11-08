// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant WS adapter is linked for P20. Named cells live in ramflux-storage `settle_tests`.
use crate::bus::sync_driver::source::ws::SourceWs;

#[test]
fn dormant_ws_adapter_is_linked() {
    assert!(std::mem::size_of::<SourceWs<'static>>() > 0);
}

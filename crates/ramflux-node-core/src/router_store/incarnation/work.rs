// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Counts work at the actual cursor codec and compact-row write boundaries.
use std::cell::Cell;
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Work {
    pub reads: usize,
    pub read_bytes: usize,
    pub writes: usize,
    pub write_bytes: usize,
    pub metadata_writes: usize,
}
thread_local! { static WORK: Cell<Work> = const { Cell::new(Work { reads:0,read_bytes:0,writes:0,write_bytes:0,metadata_writes:0 }) }; }
pub(crate) fn read(bytes: usize) {
    WORK.with(|w| {
        let mut v = w.get();
        v.reads += 1;
        v.read_bytes += bytes;
        w.set(v);
    });
}
pub(crate) fn write(bytes: usize) {
    WORK.with(|w| {
        let mut v = w.get();
        v.writes += 1;
        v.write_bytes += bytes;
        w.set(v);
    });
}
pub(crate) fn metadata_write() {
    WORK.with(|w| {
        let mut v = w.get();
        v.metadata_writes += 1;
        w.set(v);
    });
}
pub(crate) fn take() -> Work {
    WORK.with(|w| w.replace(Work::default()))
}

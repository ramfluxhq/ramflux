// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Counted recovery work rejects re-reading the committed prefix at every acknowledgement.

use crate::bus::connection_manager::ConnectionHandle;
use ramflux_storage::SqlWorkProbe;

pub(super) fn assert_prefix_not_rescanned(probe: &SqlWorkProbe) {
    assert_eq!(
        probe.snapshot().ack_committed_prefix_reads,
        0,
        "recovery work budget: an ACK re-scanned the committed prefix"
    );
}

pub(super) fn assert_complete(handle: &ConnectionHandle, probe: &SqlWorkProbe, entries: usize) {
    let profile = handle.test_receive_profile();
    assert_eq!(
        profile.get("apply").map(|(count, _, _)| *count),
        Some(entries),
        "each authenticated entry must be applied exactly once"
    );
    assert_eq!(profile.get("source").map(|(count, _, _)| *count), Some(entries));
    assert_eq!(profile.get("projection").map(|(count, _, _)| *count), Some(entries));
    let count = u64::try_from(entries).unwrap_or(u64::MAX);
    let work = probe.snapshot();
    eprintln!("receive recovery work ({entries} entries): {work:?}");
    assert_prefix_not_rescanned(probe);
    // One authenticated sender can perform its initial replay-key migration; ACKs cannot.
    assert!(
        work.committed_prefix_reads <= 2,
        "prefix reads must remain fixed startup work: {work:?}"
    );
    assert!(
        work.source_read_rows >= count && work.source_read_steps >= count,
        "source observation must include real work: {work:?}"
    );
    assert_eq!(
        work.committed_state_writes,
        2 * count,
        "one commit and one projection claim per entry"
    );
    assert!(work.source_read_rows <= 64 * count + 64, "source row work must be linear: {work:?}");
    assert!(
        work.source_read_steps <= 16_384 * count + 1024,
        "source VM work must be linear: {work:?}"
    );
    assert!(
        work.committed_state_reads <= 16 * count + 64,
        "committed source reads must be linear: {work:?}"
    );
    assert!(
        work.committed_state_steps <= 1024 * count + 1024,
        "committed source VM work must be linear: {work:?}"
    );
}

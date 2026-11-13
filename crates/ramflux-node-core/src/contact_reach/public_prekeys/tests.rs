// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real writer/reopen proof for allocation counters, independent of source snapshot eligibility.
use super::*;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const NOW: u64 = 1_760_000_000;
#[test]
fn cr_public_prekey_target_cap_survives_peer_sybils_and_reopen() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("prekeys.redb");
    let target = ramflux_protocol::qualified_device_id(
        &ramflux_protocol::encode_base64url([1; 32]),
        "phone",
    )?;
    {
        let store = crate::RouterRedbStore::open_without_wal(&path)?;
        for index in 0..20 {
            let tx = store.begin_write()?;
            reserve(&tx, &format!("peer-{index}.example"), &target, NOW)?;
            tx.commit()?;
        }
    }
    let store = crate::RouterRedbStore::open_without_wal(&path)?;
    {
        let tx = store.begin_write()?;
        assert!(
            matches!(
                reserve(&tx, "new-peer.example", &target, NOW + 60),
                Err(super::super::ReachError::Refused(Reason::ForeignRateLimited))
            ),
            "new authenticated node identities cannot reset the global per-device allocation cap"
        );
    }
    {
        let tx = store.begin_write()?;
        reserve(&tx, "new-peer.example", &target, NOW + 3600)?;
        tx.commit()?;
    }
    Ok(())
}
#[test]
fn cr_public_prekey_minute_is_sliding_and_independent_of_other_targets() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let store = crate::RouterRedbStore::open_without_wal(dir.path().join("prekeys.redb"))?;
    let tx = store.begin_write()?;
    reserve(&tx, "peer.example", "qualified-target-a", NOW)?;
    tx.commit()?;
    {
        let tx = store.begin_write()?;
        assert!(
            reserve(&tx, "peer.example", "qualified-target-a", NOW + 59).is_err(),
            "minute boundaries cannot shorten the one-minute peer-target cooldown"
        );
    }
    let tx = store.begin_write()?;
    reserve(&tx, "peer.example", "qualified-target-a", NOW + 60)?;
    reserve(&tx, "peer.example", "qualified-target-b", NOW + 60)?;
    tx.commit()?;
    Ok(())
}

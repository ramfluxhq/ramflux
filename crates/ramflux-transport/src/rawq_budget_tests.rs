// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::unwrap_used, clippy::expect_used)]
use crate::rawq_budget::{
    ListenerRole::{Gateway, Mesh},
    *,
};
use crate::rawq_budget::{add, mul, platform_size};
use std::sync::{Arc, Barrier};

fn request(id: &str, role: ListenerRole, slice: Option<u64>) -> ListenerRequest {
    ListenerRequest { id: id.into(), role, slice, frame_ceiling: None }
}
fn plan(ram: u64, requests: Vec<ListenerRequest>) -> FrozenBudget {
    FrozenBudget::prepare(|| Ok(ram), None, requests).unwrap()
}

const PROFILES: [(u64, ListenerRole, Profile, u64); 6] = [
    (
        1_000_000_000,
        Mesh,
        Profile {
            slice: 250_000_000,
            z: 262_144,
            crypto: 65_536,
            window: 1_048_576,
            stream_window: 262_144,
            streams: 8,
            frame: 262_144,
            auth: 262_144,
            output: 65_536,
            raw_items: 64,
            control_items: 128,
            raw: 278_528,
            control: 131_072,
            owner: 2_969_600,
            incoming: 132_095,
            response: 66_048,
            preauth: 0,
            unit: 3_167_743,
            owners: 38,
            phases: [(38, 8), (38, 4), (16, 4), (0, 0), (0, 0)],
            sources: [38, 76, 38],
            active_cids: 8,
            queues: [9_961_472, 2432, 2_490_368, 4864],
            responses: [2_490_368, 38],
            derived: 244_942_772,
        },
        5_057_228,
    ),
    (
        1_000_000_000,
        Gateway,
        Profile {
            slice: 250_000_000,
            z: 262_144,
            crypto: 65_536,
            window: 1_048_576,
            stream_window: 262_144,
            streams: 8,
            frame: 262_144,
            auth: 262_144,
            output: 65_536,
            raw_items: 64,
            control_items: 128,
            raw: 278_528,
            control: 131_072,
            owner: 2_969_600,
            incoming: 132_095,
            response: 66_048,
            preauth: 1_441_800,
            unit: 4_609_543,
            owners: 26,
            phases: [(26, 8), (26, 4), (16, 4), (26, 4), (26, 4)],
            sources: [26, 52, 26],
            active_cids: 8,
            queues: [6_815_744, 1664, 1_703_936, 3328],
            responses: [1_703_936, 26],
            derived: 243_890_540,
        },
        6_109_460,
    ),
    (
        2_000_000_000,
        Mesh,
        Profile {
            slice: 500_000_000,
            z: 524_288,
            crypto: 131_072,
            window: 2_097_152,
            stream_window: 524_288,
            streams: 16,
            frame: 524_288,
            auth: 524_288,
            output: 65_536,
            raw_items: 64,
            control_items: 256,
            raw: 540_672,
            control: 262_144,
            owner: 5_558_272,
            incoming: 197_631,
            response: 66_048,
            preauth: 0,
            unit: 5_821_951,
            owners: 42,
            phases: [(42, 8), (42, 4), (16, 4), (0, 0), (0, 0)],
            sources: [42, 84, 42],
            active_cids: 8,
            queues: [22_020_096, 2688, 5_505_024, 10_752],
            responses: [2_752_512, 42],
            derived: 493_238_188,
        },
        6_761_812,
    ),
    (
        2_000_000_000,
        Gateway,
        Profile {
            slice: 500_000_000,
            z: 524_288,
            crypto: 131_072,
            window: 2_097_152,
            stream_window: 524_288,
            streams: 16,
            frame: 524_288,
            auth: 524_288,
            output: 65_536,
            raw_items: 64,
            control_items: 256,
            raw: 540_672,
            control: 262_144,
            owner: 5_558_272,
            incoming: 197_631,
            response: 66_048,
            preauth: 2_752_520,
            unit: 8_574_471,
            owners: 28,
            phases: [(28, 8), (28, 4), (16, 4), (28, 4), (28, 4)],
            sources: [28, 56, 28],
            active_cids: 8,
            queues: [14_680_064, 1792, 3_670_016, 7168],
            responses: [1_835_008, 28],
            derived: 484_364_680,
        },
        15_635_320,
    ),
    (
        8_000_000_000,
        Mesh,
        Profile {
            slice: 2_000_000_000,
            z: 1_048_576,
            crypto: 262_144,
            window: 4_194_304,
            stream_window: 1_048_576,
            streams: 32,
            frame: 1_048_576,
            auth: 1_048_576,
            output: 65_536,
            raw_items: 64,
            control_items: 256,
            raw: 1_064_960,
            control: 393_216,
            owner: 10_604_544,
            incoming: 328_703,
            response: 66_048,
            preauth: 0,
            unit: 10_999_295,
            owners: 64,
            phases: [(64, 8), (64, 4), (16, 4), (0, 0), (0, 0)],
            sources: [64, 128, 64],
            active_cids: 8,
            queues: [67_108_864, 4096, 16_777_216, 16_384],
            responses: [4_194_304, 64],
            derived: 1_412_104_064,
        },
        587_895_936,
    ),
    (
        8_000_000_000,
        Gateway,
        Profile {
            slice: 2_000_000_000,
            z: 1_048_576,
            crypto: 262_144,
            window: 4_194_304,
            stream_window: 1_048_576,
            streams: 32,
            frame: 1_048_576,
            auth: 1_048_576,
            output: 65_536,
            raw_items: 64,
            control_items: 256,
            raw: 1_064_960,
            control: 393_216,
            owner: 10_604_544,
            incoming: 328_703,
            response: 66_048,
            preauth: 5_373_960,
            unit: 16_373_255,
            owners: 60,
            phases: [(60, 8), (60, 4), (16, 4), (60, 4), (60, 4)],
            sources: [60, 120, 60],
            active_cids: 8,
            queues: [62_914_560, 3840, 15_728_640, 15_360],
            responses: [3_932_160, 60],
            derived: 1_968_984_904,
        },
        31_015_096,
    ),
];

#[test]
fn one_gb_profile_accounts_every_allocation() {
    // Literal reviewed fixtures cover both complete card tables, using the real entrypoint.
    for (ram, role, expected, unused) in PROFILES {
        let budget = plan(ram, vec![request("listener", role, None)]);
        assert_eq!(budget.listeners()[0].2, expected);
        assert_eq!(budget.host_bytes() - expected.derived, unused);
    }

    assert_eq!(ENDPOINT_COMPONENTS.iter().sum::<u64>(), ENDPOINT_BYTES);
    assert_eq!(CENSUS.len(), 17);
    for (index, entry) in CENSUS.iter().enumerate() {
        assert_ne!(entry.source, "");
        assert!((1..=4).contains(&entry.tokio_owner));
        assert!((6..=9).contains(&entry.compio_owner));
        assert!(!CENSUS[..index].iter().any(|other| other.class == entry.class));
    }
    assert_eq!(allocation_charge(1).unwrap(), 128);
    assert_eq!(allocation_charge(64).unwrap(), 128);
    assert_eq!(allocation_charge(65).unwrap(), 192);
}

#[test]
fn rejects_impossible_or_over_budget_before_listener_allocation() {
    use std::cell::Cell;
    let reads = Cell::new(0);
    let prepare = |host, requests| {
        FrozenBudget::prepare(
            || {
                reads.set(reads.get() + 1);
                Ok(1_000_000_000)
            },
            host,
            requests,
        )
    };
    assert!(prepare(Some(250_000_001), vec![request("m", Mesh, None)]).is_err());
    assert_eq!(reads.get(), 1);
    assert!(prepare(Some(0), vec![request("m", Mesh, None)]).is_err());
    assert!(
        prepare(
            None,
            vec![request("m", Mesh, Some(200_000_000)), request("g", Gateway, Some(200_000_000))]
        )
        .is_err()
    );
    assert!(prepare(None, vec![request("m", Mesh, Some(1))]).is_err());
    assert!(prepare(None, vec![request("m", Mesh, Some(0))]).is_err());
    assert!(
        prepare(None, vec![request("m", Mesh, Some(100_000_000)), request("g", Gateway, None)])
            .is_err()
    );
    assert!(
        prepare(None, vec![request("same", Mesh, None), request("same", Gateway, None)]).is_err()
    );
    assert!(prepare(None, vec![]).is_err());
    assert!(FrozenBudget::prepare(|| Ok(0), Some(1), vec![request("m", Mesh, None)]).is_err());
    assert!(
        FrozenBudget::prepare(
            || Err(BudgetError::Invalid("RAM unavailable")),
            Some(1),
            vec![request("m", Mesh, None)]
        )
        .is_err()
    );
    let mut lower = request("g", Gateway, None);
    lower.frame_ceiling = Some(128 * 1024);
    let lowered = prepare(None, vec![lower.clone()]).unwrap();
    assert_eq!(lowered.listeners()[0].2.frame, 128 * 1024);
    assert_eq!(lowered.listeners()[0].2.derived, 243_890_540);
    lower.frame_ceiling = Some(1024 * 1024);
    assert!(prepare(None, vec![lower.clone()]).is_err());
    lower.frame_ceiling = Some(0);
    assert!(prepare(None, vec![lower]).is_err());
    // prepare has no socket/task/runtime factory or startup capability.
    let original = prepare(None, vec![request("g", Gateway, None)]).unwrap();
    assert_ne!(original.digest(), lowered.digest());
}

#[test]
fn checked_arithmetic_rejects_overflow() {
    assert!(add(u64::MAX, 1).is_err());
    assert!(mul(u64::MAX, 2).is_err());
    assert!(allocation_charge(u64::MAX).is_err());
    assert!(allocation_charge(u64::MAX - 63).is_err());
    assert!(platform_size(u64::from(u32::MAX) + 1, u64::from(u32::MAX)).is_err());
    assert_eq!(platform_size(u64::from(u32::MAX), u64::from(u32::MAX)).unwrap(), u32::MAX as usize);
    assert!(Profile::derive(0, Mesh, None).is_err());
    assert!(Profile::derive(512 * 128 * 1024 - 1, Mesh, None).is_err());
}

#[test]
fn listeners_and_processes_share_one_host_budget() {
    if let Ok(path) = std::env::var("RAWQ_CHILD_LEDGER") {
        let budget = plan(1_000_000_000, vec![request("other-process", Mesh, Some(125_000_000))]);
        let result = reserve_host_slice(std::path::Path::new(&path), &budget, 0);
        if std::env::var_os("RAWQ_ABANDON").is_some() {
            let _lease = result.unwrap();
            std::process::exit(0); // Actual process death without userspace destruction.
        }
        assert!(result.is_err(), "second process must refuse live/stale overlap");
        return;
    }
    let budget =
        plan(1_000_000_000, vec![request("mesh", Mesh, None), request("gateway", Gateway, None)]);
    assert_eq!(budget.reserved_bytes(), 250_000_000);
    let profiles = budget.listeners(); // canonical gateway then mesh
    assert_eq!(
        (profiles[0].2.z, profiles[0].2.owners, profiles[0].2.derived),
        (131_072, 23, 123_155_778)
    );
    assert_eq!(
        (profiles[1].2.z, profiles[1].2.owners, profiles[1].2.derived),
        (131_072, 32, 121_470_912)
    );
    assert_eq!(profiles.iter().map(|l| l.2.derived).sum::<u64>(), 244_626_690);
    let reversed =
        plan(1_000_000_000, vec![request("gateway", Gateway, None), request("mesh", Mesh, None)]);
    assert_eq!(budget.digest(), reversed.digest());
    let nonce =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("rawq-budget-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("host.ledger");
    let left = Arc::new(plan(1_000_000_000, vec![request("mesh", Mesh, Some(125_000_000))]));
    let right = Arc::new(plan(1_000_000_000, vec![request("gateway", Gateway, Some(125_000_000))]));
    // Provision before simultaneous transactions; ledger creation also fails closed on crash.
    drop(reserve_host_slice(&path, &left, 0).unwrap());
    let barrier = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        let mut joins = vec![];
        for config in [left.clone(), left.clone()] {
            let barrier = barrier.clone();
            let path = &path;
            joins.push(scope.spawn(move || {
                barrier.wait();
                reserve_host_slice(path, &config, 0)
            }));
        }
        barrier.wait();
        let results: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let lease = results.into_iter().find_map(Result::ok).unwrap();
        let retained = lease.clone();
        drop(lease);
        assert_eq!(retained.owners(), 1);
        assert!(reserve_host_slice(&path, &left, 0).is_err());
        let disjoint = reserve_host_slice(&path, &right, 125_000_000).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "rawq_budget_tests::listeners_and_processes_share_one_host_budget",
                "--nocapture",
            ])
            .env("RAWQ_CHILD_LEDGER", &path)
            .status()
            .unwrap();
        assert!(child.success());
        drop(disjoint);
        drop(retained);
    });
    let reacquired = reserve_host_slice(&path, &left, 0).unwrap();
    drop(reacquired);
    let crashed = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "rawq_budget_tests::listeners_and_processes_share_one_host_budget"])
        .env("RAWQ_CHILD_LEDGER", &path)
        .env("RAWQ_ABANDON", "1")
        .status()
        .unwrap();
    assert!(crashed.success());
    assert!(reserve_host_slice(&path, &left, 0).is_err());
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "rawq_budget_tests::listeners_and_processes_share_one_host_budget"])
        .env("RAWQ_CHILD_LEDGER", &path)
        .status()
        .unwrap();
    assert!(child.success());
    let mismatched = plan(2_000_000_000, vec![request("m", Mesh, Some(125_000_000))]);
    assert!(reserve_host_slice(&path, &mismatched, 125_000_000).is_err());
    std::fs::write(&path, b"torn ledger").unwrap();
    assert!(reserve_host_slice(&path, &right, 125_000_000).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

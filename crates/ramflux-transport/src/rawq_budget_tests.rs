// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::unwrap_used, clippy::expect_used)]
use crate::rawq_budget::{
    ListenerRole::{Gateway, Mesh},
    *,
};
use crate::rawq_budget::{add, mul, platform_size};
use AllocationClass as A;
use Pool as P;
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
            incoming: 132_095,
            response: 66_048,
            preauth: 0,
            unit: 4_128_255,
            owners: 29,
            phases: [(29, 8), (29, 4), (16, 4), (0, 0), (0, 0)],
            sources: [29, 58, 29],
            active_cids: 8,
            queues: [7_602_176, 1_856, 1_900_544, 3_712],
            responses: [1_900_544, 29],
            derived: 243_633_094,
            owner_base: 2_969_600,
            unit_base: 3_167_743,
            metadata: MetadataBudget { reference_units: 1_748, base: 960_512, ceiling: 1_921_024 },
        },
        6_366_906,
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
            incoming: 132_095,
            response: 66_048,
            preauth: 1_441_800,
            unit: 5_570_055,
            owners: 22,
            phases: [(22, 8), (22, 4), (16, 4), (22, 4), (22, 4)],
            sources: [22, 44, 22],
            active_cids: 8,
            queues: [5_767_168, 1_408, 1_441_792, 2_816],
            responses: [1_441_792, 22],
            derived: 249_276_724,
            owner_base: 2_969_600,
            unit_base: 4_609_543,
            metadata: MetadataBudget { reference_units: 1_748, base: 960_512, ceiling: 1_921_024 },
        },
        723_276,
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
            incoming: 197_631,
            response: 66_048,
            preauth: 0,
            unit: 7_677_439,
            owners: 32,
            phases: [(32, 8), (32, 4), (16, 4), (0, 0), (0, 0)],
            sources: [32, 64, 32],
            active_cids: 8,
            queues: [16_777_216, 2_048, 4_194_304, 8_192],
            responses: [2_097_152, 32],
            derived: 495_550_400,
            owner_base: 5_558_272,
            unit_base: 5_821_951,
            metadata: MetadataBudget {
                reference_units: 3_496,
                base: 1_855_488,
                ceiling: 3_710_976,
            },
        },
        4_449_600,
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
            incoming: 197_631,
            response: 66_048,
            preauth: 2_752_520,
            unit: 10_429_959,
            owners: 23,
            phases: [(23, 8), (23, 4), (16, 4), (23, 4), (23, 4)],
            sources: [23, 46, 23],
            active_cids: 8,
            queues: [12_058_624, 1_472, 3_014_656, 5_888],
            responses: [1_507_328, 23],
            derived: 483_972_418,
            owner_base: 5_558_272,
            unit_base: 8_574_471,
            metadata: MetadataBudget {
                reference_units: 3_496,
                base: 1_855_488,
                ceiling: 3_710_976,
            },
        },
        16_027_582,
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
            incoming: 328_703,
            response: 66_048,
            preauth: 0,
            unit: 14_644_223,
            owners: 64,
            phases: [(64, 8), (64, 4), (16, 4), (0, 0), (0, 0)],
            sources: [64, 128, 64],
            active_cids: 8,
            queues: [67_108_864, 4_096, 16_777_216, 16_384],
            responses: [4_194_304, 64],
            derived: 1_878_654_848,
            owner_base: 10_604_544,
            unit_base: 10_999_295,
            metadata: MetadataBudget {
                reference_units: 6_991,
                base: 3_644_928,
                ceiling: 7_289_856,
            },
        },
        121_345_152,
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
            incoming: 328_703,
            response: 66_048,
            preauth: 5_373_960,
            unit: 20_018_183,
            owners: 49,
            phases: [(49, 8), (49, 4), (16, 4), (49, 4), (49, 4)],
            sources: [49, 98, 49],
            active_cids: 8,
            queues: [51_380_224, 3_136, 12_845_056, 12_544],
            responses: [3_211_264, 49],
            derived: 1_965_976_238,
            owner_base: 10_604_544,
            unit_base: 16_373_255,
            metadata: MetadataBudget {
                reference_units: 6_991,
                base: 3_644_928,
                ceiling: 7_289_856,
            },
        },
        34_023_762,
    ),
];
const SPLIT_PROFILES: [Profile; 2] = [
    Profile {
        slice: 125_000_000,
        z: 131_072,
        crypto: 32_768,
        window: 524_288,
        stream_window: 131_072,
        streams: 4,
        frame: 131_072,
        auth: 131_072,
        output: 32_768,
        raw_items: 32,
        control_items: 64,
        raw: 139_264,
        control: 65_536,
        incoming: 99_327,
        response: 66_048,
        preauth: 753_672,
        unit: 3_099_143,
        owners: 19,
        phases: [(19, 8), (19, 4), (16, 4), (19, 4), (19, 4)],
        sources: [19, 38, 19],
        active_cids: 8,
        queues: [2_490_368, 608, 622_592, 1_216],
        responses: [1_245_184, 19],
        derived: 121_961_738,
        owner_base: 1_667_072,
        unit_base: 2_586_119,
        metadata: MetadataBudget { reference_units: 874, base: 513_024, ceiling: 1_026_048 },
    },
    Profile {
        slice: 125_000_000,
        z: 131_072,
        crypto: 32_768,
        window: 524_288,
        stream_window: 131_072,
        streams: 4,
        frame: 131_072,
        auth: 131_072,
        output: 32_768,
        raw_items: 32,
        control_items: 64,
        raw: 139_264,
        control: 65_536,
        incoming: 99_327,
        response: 66_048,
        preauth: 0,
        unit: 2_345_471,
        owners: 25,
        phases: [(25, 8), (25, 4), (16, 4), (0, 0), (0, 0)],
        sources: [25, 50, 25],
        active_cids: 8,
        queues: [3_276_800, 800, 819_200, 1_600],
        responses: [1_638_400, 25],
        derived: 121_467_854,
        owner_base: 1_667_072,
        unit_base: 1_832_447,
        metadata: MetadataBudget { reference_units: 874, base: 513_024, ceiling: 1_026_048 },
    },
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
    let classes = [
        A::Socket,
        A::EndpointState,
        A::Runtime,
        A::Incoming,
        A::RawEvents,
        A::Controls,
        A::Terminal,
        A::Crypto,
        A::Tls,
        A::ProtocolFixed,
        A::StreamPayload,
        A::StreamState,
        A::Sources,
        A::Tasks,
        A::Responses,
        A::Preauth,
        A::SharedConfig,
        A::SentRecords,
        A::SentFrameMetadata,
        A::RetransmitOwners,
        A::SendSegments,
        A::SendRanges,
        A::StreamAssemblers,
        A::CryptoAssemblers,
        A::UnorderedHistory,
        A::PendingRetransmits,
        A::PendingAcks,
        A::AckScratch,
        A::LossScratch,
    ];
    assert_eq!(CENSUS.len(), classes.len());
    for class in classes {
        let expected = match class {
            A::Socket | A::EndpointState | A::Runtime | A::SharedConfig => (P::Endpoint, 1, 7),
            A::Incoming => (P::Incoming, 1, 7),
            A::RawEvents => (P::Raw, 1, 7),
            A::Controls => (P::Control, 1, 7),
            A::Terminal => (P::Terminal, 1, 7),
            A::Crypto => (P::Crypto, 1, 7),
            A::Tls => (P::TlsOwner, 1, 7),
            A::StreamPayload => (P::Windows, 1, 7),
            A::ProtocolFixed => (P::Residual, 1, 7),
            A::StreamState => (P::Streams, 1, 7),
            A::Sources => (P::Sources, 1, 7),
            A::Tasks => (P::Tasks, 1, 7),
            A::Responses => (P::Response, 1, 6),
            A::Preauth => (P::Preauth, 1, 7),
            A::SentRecords
            | A::SentFrameMetadata
            | A::RetransmitOwners
            | A::SendSegments
            | A::SendRanges
            | A::StreamAssemblers
            | A::CryptoAssemblers
            | A::UnorderedHistory
            | A::PendingRetransmits
            | A::PendingAcks
            | A::AckScratch
            | A::LossScratch => (P::Metadata, 1, 7),
        };
        let entries: Vec<_> = CENSUS.iter().filter(|entry| entry.class == class).collect();
        assert_eq!(entries.len(), 1, "{class:?}");
        let entry = entries[0];
        assert_ne!(entry.source, "");
        assert_ne!(entry.exhaustion, "");
        assert_eq!((entry.pool, entry.tokio_owner, entry.compio_owner), expected);
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
    lower.frame_ceiling = Some(128 * 1_024);
    let lowered = prepare(None, vec![lower.clone()]).unwrap();
    assert_eq!(lowered.listeners()[0].2.frame, 128 * 1_024);
    assert_eq!(lowered.listeners()[0].2.derived, 249_276_724);
    lower.frame_ceiling = Some(1_024 * 1_024);
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
    assert!(matches!(
        FrozenBudget::prepare(
            || Ok(u64::MAX),
            None,
            vec![
                request("a", Mesh, Some(u64::MAX / 2 + 1)),
                request("b", Mesh, Some(u64::MAX / 2 + 1))
            ]
        ),
        Err(BudgetError::Overflow)
    ));
    let budget = plan(1_000_000_000, vec![request("m", Mesh, None)]);
    assert!(matches!(
        reserve_host_slice(std::path::Path::new("unused-overflow-ledger"), &budget, u64::MAX),
        Err(BudgetError::Overflow)
    ));
    assert!(Profile::derive(0, Mesh, None).is_err());
    assert!(Profile::derive(512 * 128 * 1_024 - 1, Mesh, None).is_err());
}

#[test]
fn listeners_and_processes_share_one_host_budget() {
    if let Ok(path) = std::env::var("RAWQ_CHILD_LEDGER") {
        let budget = plan(1_000_000_000, vec![request("other-process", Mesh, Some(125_000_000))]);
        let result = reserve_host_slice(std::path::Path::new(&path), &budget, 0);
        if std::env::var_os("RAWQ_ABANDON").is_some() {
            let _lease = result.unwrap();
            std::process::exit(42); // Actual process death without userspace destruction.
        }
        assert!(result.is_err(), "second process must refuse live/stale overlap");
        std::process::exit(42); // Sentinel proves the exact child filter ran this branch.
    }
    let budget =
        plan(1_000_000_000, vec![request("mesh", Mesh, None), request("gateway", Gateway, None)]);
    assert_eq!(budget.reserved_bytes(), 250_000_000);
    let profiles = budget.listeners(); // canonical gateway then mesh
    assert_eq!(profiles[0].2, SPLIT_PROFILES[0]);
    assert_eq!(profiles[1].2, SPLIT_PROFILES[1]);
    assert_eq!(profiles.iter().map(|l| l.2.derived).sum::<u64>(), 243_429_592);
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
        assert_eq!(child.code(), Some(42));
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
    assert_eq!(crashed.code(), Some(42));
    assert!(reserve_host_slice(&path, &left, 0).is_err());
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "rawq_budget_tests::listeners_and_processes_share_one_host_budget"])
        .env("RAWQ_CHILD_LEDGER", &path)
        .status()
        .unwrap();
    assert_eq!(child.code(), Some(42));
    let mismatched = plan(2_000_000_000, vec![request("m", Mesh, Some(125_000_000))]);
    assert!(reserve_host_slice(&path, &mismatched, 125_000_000).is_err());
    // Correct size and policy, but remove the stale claim without updating checksum.
    let mut corrupt = std::fs::read(&path).unwrap();
    corrupt[32..40].fill(0);
    std::fs::write(&path, &corrupt).unwrap();
    assert!(matches!(
        reserve_host_slice(&path, &right, 125_000_000),
        Err(BudgetError::Invalid("ledger checksum/stale state"))
    ));
    std::fs::write(&path, b"torn ledger").unwrap();
    assert!(reserve_host_slice(&path, &right, 125_000_000).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn metadata_byte_credit_scales_with_windows() {
    let mut previous = 0;
    for (z, unit_base, metadata_base) in [
        (128 * 1_024, 1_832_447, 513_024),
        (256 * 1_024, 3_167_743, 960_512),
        (512 * 1_024, 5_821_951, 1_855_488),
        (1_024 * 1_024, 10_999_295, 3_644_928),
    ] {
        let budget = plan(z * 512 * 4, vec![request("m", Mesh, None)]);
        let p = &budget.listeners()[0].2;
        assert_eq!(p.z, z);
        assert_eq!(p.unit_base, unit_base);
        assert_eq!(p.metadata.reference_units, (2 * p.window).div_ceil(1_200));
        assert_eq!(p.metadata.base, metadata_base);
        assert_eq!(p.metadata.ceiling, 2 * metadata_base);
        assert_eq!(p.unit, unit_base + metadata_base);
        assert_eq!(
            p.derived,
            ENDPOINT_BYTES + p.owners * (2 * unit_base + p.metadata.ceiling),
            "metadata factor two must appear exactly once"
        );
        assert!(p.metadata.ceiling > previous);
        previous = p.metadata.ceiling;
    }
    assert_eq!(MetadataBudget::derive(1_199, 0).unwrap().reference_units, 1);
    assert_eq!(MetadataBudget::derive(1_200, 0).unwrap().reference_units, 1);
    assert_eq!(MetadataBudget::derive(1_201, 0).unwrap().reference_units, 2);
    assert!(matches!(MetadataBudget::derive(u64::MAX, 1), Err(BudgetError::Overflow)));
}

#[test]
fn metadata_census_covers_all_r8_classes() {
    use MetadataMultiplicity as M;
    let expected = [
        (A::SentRecords, M::PacketSpaces(3)),
        (A::SentFrameMetadata, M::RetainedPacketsAndBuilders),
        (A::RetransmitOwners, M::RetainedPacketAndPendingChildren),
        (A::SendSegments, M::SendHalves),
        (A::SendRanges, M::SendRangeSets(2)),
        (A::StreamAssemblers, M::ReceiveHalves),
        (A::CryptoAssemblers, M::PacketSpaces(3)),
        (A::UnorderedHistory, M::UnorderedAssemblers),
        (A::PendingRetransmits, M::PacketSpaces(3)),
        (A::PendingAcks, M::PacketSpaces(3)),
        (A::AckScratch, M::ConcurrentScratch),
        (A::LossScratch, M::ConcurrentScratch),
    ];
    let entries: Vec<_> = CENSUS.iter().filter(|e| e.pool == Pool::Metadata).collect();
    assert_eq!(entries.len(), expected.len());
    for (class, multiplicity) in expected {
        let found: Vec<_> = entries.iter().filter(|e| e.class == class).collect();
        assert_eq!(found.len(), 1, "{class:?}");
        let e = found[0];
        assert_eq!(e.metadata_multiplicity, Some(multiplicity));
        assert_eq!((e.pool, e.tokio_owner, e.compio_owner), (Pool::Metadata, 1, 7));
        let source = match class {
            A::SentRecords => {
                "p 0.11.18 src/connection/spaces.rs:20-54,218-255,283-305; src/connection/packet_builder.rs:32-44,184-216; all tracked packets and outstanding builders"
            }
            A::SentFrameMetadata => {
                "p 0.11.18 src/frame.rs:468-509; src/connection/spaces.rs:283-305; variable StreamMetaVec capacity per retained packet/builder"
            }
            A::RetransmitOwners => {
                "p 0.11.18 src/connection/spaces.rs:309-338,383-408,428-454; boxed owners and all vector/set/deque children including transfer overlap"
            }
            A::SendSegments => {
                "p 0.11.18 src/connection/send_buffer.rs:9-40,43-77,147-174; every retained deque cell/backing capacity across S send halves"
            }
            A::SendRanges => {
                "p 0.11.18 src/connection/send_buffer.rs:21-27,43-77,171-174; src/range_set/btree_range_set.rs:13-15,26-38; ACK/retransmit nodes survive record removal"
            }
            A::StreamAssemblers => {
                "p 0.11.18 src/connection/streams/recv.rs:15-27,274-300; src/connection/assembler.rs:13-23,105-147,153-219,255-280; chunks, descriptors, backing and compaction peaks"
            }
            A::CryptoAssemblers => {
                "p 0.11.18 src/connection/spaces.rs:20-54,80-91; src/connection/mod.rs:2128-2137; src/connection/assembler.rs:13-23,105-147,153-219,255-280; three additional CRYPTO assemblers"
            }
            A::UnorderedHistory => {
                "p 0.11.18 src/connection/assembler.rs:40-55,85-97,166-182,332-340; q 0.11.11 src/recv_stream.rs:163-180; c 0.8.0 src/recv_stream.rs:279-296; recvd trees persist after chunk consumption"
            }
            A::PendingRetransmits => {
                "p 0.11.18 src/connection/spaces.rs:20-28,383-408; src/connection/mod.rs:1779-1793; pending collections plus transferred backing until actual free"
            }
            A::PendingAcks => {
                "p 0.11.18 src/connection/spaces.rs:610-654,794-803,924; src/range_set/array_range_set.rs:20-38; preserve steady64/transient65 pruning, charge actual capacity"
            }
            A::AckScratch => {
                "p 0.11.18 src/connection/mod.rs:1493-1501; src/range_set/array_range_set.rs:20-38; every simultaneous ACK allocation and replacement backing"
            }
            A::LossScratch => {
                "p 0.11.18 src/connection/mod.rs:1695-1696,1730-1735,1779-1793; lost_packets capacity plus simultaneous pending transfers"
            }
            _ => unreachable!("non-metadata class in exhaustive fixture"),
        };
        assert_eq!(e.source, source, "{class:?} pinned citation changed");
        for policy in [
            "ResourceExhausted before growth",
            "abort frame/coalesced/build",
            "one local error",
            "handshake APPLICATION_ERROR",
            "wake waiters",
            "Close timer to Drained",
            "retain charges until final destruction",
        ] {
            assert!(e.exhaustion.contains(policy), "{class:?} lacks {policy}");
        }
    }
    for e in CENSUS.iter().filter(|e| e.pool != Pool::Metadata) {
        assert!(e.metadata_multiplicity.is_none());
    }
}

#[test]
fn release_refuses_replaced_claim_identity() {
    let nonce =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("rawq-release-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let budget = plan(1_000_000_000, vec![request("m", Mesh, Some(125_000_000))]);
    for offset in [0, 8, 16, 24] {
        // start, end, PID and digest, independently
        let path = dir.join(format!("identity-{offset}"));
        let lease = reserve_host_slice(&path, &budget, 0).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[24 + offset] ^= 1;
        let body = bytes.len() - 32;
        let checksum = blake3::hash(&bytes[..body]);
        bytes[body..].copy_from_slice(checksum.as_bytes());
        std::fs::write(&path, &bytes).unwrap();
        drop(lease);
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "release cleared another claim: {offset}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

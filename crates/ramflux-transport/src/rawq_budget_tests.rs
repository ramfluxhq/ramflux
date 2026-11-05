// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2_026 Span Brain

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
            sent_records: 1_748,
            sent_record_bytes: 449_024,
            ack_ranges_per_space: 64,
            ack_range_bytes: 6_240,
            window_pool: 22_598_592,
            stream_window: 262_144,
            streams: 8,
            frame: 262_144,
            auth: 262_144,
            output: 65_536,
            raw_items: 64,
            control_items: 128,
            raw: 278_528,
            control: 131_072,
            owner: 12_171_744,
            incoming: 132_095,
            response: 66_048,
            preauth: 0,
            unit: 12_369_887,
            owners: 9,
            phases: [(9, 8), (9, 4), (9, 4), (0, 0), (0, 0)],
            sources: [9, 18, 9],
            active_cids: 8,
            queues: [2_359_296, 576, 589_824, 1_152],
            responses: [589_824, 9],
            derived: 226_852_270,
            s_pto: 2,
            k_pto: 3,
            ack_only_records: 2,
            t_np: NoProgressDeadline { pto_multiple: 3, minimum_ms: 10_000 },
            tracked_records: 1_754,
            metadata: MetadataBudget {
                frames_per_packet: 32,
                ranges_per_stream: 64,
                segments_per_stream: 64,
                scratch_entries: 1_754,
                charges: [
                    MetadataCharge {
                        class: AllocationClass::SentFrameMetadata,
                        count: 56_128,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 7_184_384,
                    },
                    MetadataCharge {
                        class: AllocationClass::RetransmitOwner,
                        count: 1_754,
                        capacity: 512,
                        item_charge: 576,
                        bytes: 1_010_304,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendRanges,
                        count: 1_024,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 131_072,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendSegments,
                        count: 512,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 65_536,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveRanges,
                        count: 512,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 65_536,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveSegments,
                        count: 512,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 65_536,
                    },
                    MetadataCharge {
                        class: AllocationClass::AckLossScratch,
                        count: 1_754,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 224_512,
                    },
                ],
                total: 8_746_880,
            },
            delta_unit: 9_202_144,
        },
        23_147_730,
    ),
    (
        1_000_000_000,
        Gateway,
        Profile {
            slice: 250_000_000,
            z: 262_144,
            crypto: 65_536,
            window: 1_048_576,
            sent_records: 1_748,
            sent_record_bytes: 449_024,
            ack_ranges_per_space: 64,
            ack_range_bytes: 6_240,
            window_pool: 22_598_592,
            stream_window: 262_144,
            streams: 8,
            frame: 262_144,
            auth: 262_144,
            output: 65_536,
            raw_items: 64,
            control_items: 128,
            raw: 278_528,
            control: 131_072,
            owner: 12_171_744,
            incoming: 132_095,
            response: 66_048,
            preauth: 1_441_800,
            unit: 13_811_687,
            owners: 8,
            phases: [(8, 8), (8, 4), (8, 4), (8, 4), (8, 4)],
            sources: [8, 16, 8],
            active_cids: 8,
            queues: [2_097_152, 512, 524_288, 1_024],
            responses: [524_288, 8],
            derived: 225_181_296,
            s_pto: 2,
            k_pto: 3,
            ack_only_records: 2,
            t_np: NoProgressDeadline { pto_multiple: 3, minimum_ms: 10_000 },
            tracked_records: 1_754,
            metadata: MetadataBudget {
                frames_per_packet: 32,
                ranges_per_stream: 64,
                segments_per_stream: 64,
                scratch_entries: 1_754,
                charges: [
                    MetadataCharge {
                        class: AllocationClass::SentFrameMetadata,
                        count: 56_128,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 7_184_384,
                    },
                    MetadataCharge {
                        class: AllocationClass::RetransmitOwner,
                        count: 1_754,
                        capacity: 512,
                        item_charge: 576,
                        bytes: 1_010_304,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendRanges,
                        count: 1_024,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 131_072,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendSegments,
                        count: 512,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 65_536,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveRanges,
                        count: 512,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 65_536,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveSegments,
                        count: 512,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 65_536,
                    },
                    MetadataCharge {
                        class: AllocationClass::AckLossScratch,
                        count: 1_754,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 224_512,
                    },
                ],
                total: 8_746_880,
            },
            delta_unit: 9_202_144,
        },
        24_818_704,
    ),
    (
        2_000_000_000,
        Mesh,
        Profile {
            slice: 500_000_000,
            z: 524_288,
            crypto: 131_072,
            window: 2_097_152,
            sent_records: 3_496,
            sent_record_bytes: 896_512,
            ack_ranges_per_space: 64,
            ack_range_bytes: 6_240,
            window_pool: 45_124_032,
            stream_window: 524_288,
            streams: 16,
            frame: 524_288,
            auth: 524_288,
            output: 65_536,
            raw_items: 64,
            control_items: 256,
            raw: 540_672,
            control: 262_144,
            owner: 23_925_984,
            incoming: 197_631,
            response: 66_048,
            preauth: 0,
            unit: 24_189_663,
            owners: 10,
            phases: [(10, 8), (10, 4), (10, 4), (0, 0), (0, 0)],
            sources: [10, 20, 10],
            active_cids: 8,
            queues: [5_242_880, 640, 1_310_720, 2_560],
            responses: [655_360, 10],
            derived: 487_987_564,
            s_pto: 2,
            k_pto: 3,
            ack_only_records: 2,
            t_np: NoProgressDeadline { pto_multiple: 3, minimum_ms: 10_000 },
            tracked_records: 3_502,
            metadata: MetadataBudget {
                frames_per_packet: 32,
                ranges_per_stream: 64,
                segments_per_stream: 64,
                scratch_entries: 3_502,
                charges: [
                    MetadataCharge {
                        class: AllocationClass::SentFrameMetadata,
                        count: 112_064,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 14_344_192,
                    },
                    MetadataCharge {
                        class: AllocationClass::RetransmitOwner,
                        count: 3_502,
                        capacity: 512,
                        item_charge: 576,
                        bytes: 2_017_152,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendRanges,
                        count: 2_048,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 262_144,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendSegments,
                        count: 1_024,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 131_072,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveRanges,
                        count: 1_024,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 131_072,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveSegments,
                        count: 1_024,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 131_072,
                    },
                    MetadataCharge {
                        class: AllocationClass::AckLossScratch,
                        count: 3_502,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 448_256,
                    },
                ],
                total: 17_464_960,
            },
            delta_unit: 18_367_712,
        },
        12_012_436,
    ),
    (
        2_000_000_000,
        Gateway,
        Profile {
            slice: 500_000_000,
            z: 524_288,
            crypto: 131_072,
            window: 2_097_152,
            sent_records: 3_496,
            sent_record_bytes: 896_512,
            ack_ranges_per_space: 64,
            ack_range_bytes: 6_240,
            window_pool: 45_124_032,
            stream_window: 524_288,
            streams: 16,
            frame: 524_288,
            auth: 524_288,
            output: 65_536,
            raw_items: 64,
            control_items: 256,
            raw: 540_672,
            control: 262_144,
            owner: 23_925_984,
            incoming: 197_631,
            response: 66_048,
            preauth: 2_752_520,
            unit: 26_942_183,
            owners: 9,
            phases: [(9, 8), (9, 4), (9, 4), (9, 4), (9, 4)],
            sources: [9, 18, 9],
            active_cids: 8,
            queues: [4_718_592, 576, 1_179_648, 2_304],
            responses: [589_824, 9],
            derived: 489_153_598,
            s_pto: 2,
            k_pto: 3,
            ack_only_records: 2,
            t_np: NoProgressDeadline { pto_multiple: 3, minimum_ms: 10_000 },
            tracked_records: 3_502,
            metadata: MetadataBudget {
                frames_per_packet: 32,
                ranges_per_stream: 64,
                segments_per_stream: 64,
                scratch_entries: 3_502,
                charges: [
                    MetadataCharge {
                        class: AllocationClass::SentFrameMetadata,
                        count: 112_064,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 14_344_192,
                    },
                    MetadataCharge {
                        class: AllocationClass::RetransmitOwner,
                        count: 3_502,
                        capacity: 512,
                        item_charge: 576,
                        bytes: 2_017_152,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendRanges,
                        count: 2_048,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 262_144,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendSegments,
                        count: 1_024,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 131_072,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveRanges,
                        count: 1_024,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 131_072,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveSegments,
                        count: 1_024,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 131_072,
                    },
                    MetadataCharge {
                        class: AllocationClass::AckLossScratch,
                        count: 3_502,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 448_256,
                    },
                ],
                total: 17_464_960,
            },
            delta_unit: 18_367_712,
        },
        10_846_402,
    ),
    (
        8_000_000_000,
        Mesh,
        Profile {
            slice: 2_000_000_000,
            z: 1_048_576,
            crypto: 262_144,
            window: 4_194_304,
            sent_records: 6_991,
            sent_record_bytes: 1_791_232,
            ack_ranges_per_space: 64,
            ack_range_bytes: 6_240,
            window_pool: 90_164_800,
            stream_window: 1_048_576,
            streams: 32,
            frame: 1_048_576,
            auth: 1_048_576,
            output: 65_536,
            raw_items: 64,
            control_items: 256,
            raw: 1_064_960,
            control: 393_216,
            owner: 47_298_336,
            incoming: 328_703,
            response: 66_048,
            preauth: 0,
            unit: 47_693_087,
            owners: 20,
            phases: [(20, 8), (20, 4), (16, 4), (0, 0), (0, 0)],
            sources: [20, 40, 20],
            active_cids: 8,
            queues: [20_971_520, 1_280, 5_242_880, 5_120],
            responses: [1_310_720, 20],
            derived: 1_911_917_784,
            s_pto: 2,
            k_pto: 3,
            ack_only_records: 2,
            t_np: NoProgressDeadline { pto_multiple: 3, minimum_ms: 10_000 },
            tracked_records: 6_997,
            metadata: MetadataBudget {
                frames_per_packet: 32,
                ranges_per_stream: 64,
                segments_per_stream: 64,
                scratch_entries: 6_997,
                charges: [
                    MetadataCharge {
                        class: AllocationClass::SentFrameMetadata,
                        count: 223_904,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 28_659_712,
                    },
                    MetadataCharge {
                        class: AllocationClass::RetransmitOwner,
                        count: 6_997,
                        capacity: 512,
                        item_charge: 576,
                        bytes: 4_030_272,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendRanges,
                        count: 4_096,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 524_288,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendSegments,
                        count: 2_048,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 262_144,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveRanges,
                        count: 2_048,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 262_144,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveSegments,
                        count: 2_048,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 262_144,
                    },
                    MetadataCharge {
                        class: AllocationClass::AckLossScratch,
                        count: 6_997,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 895_616,
                    },
                ],
                total: 34_896_320,
            },
            delta_unit: 36_693_792,
        },
        88_082_216,
    ),
    (
        8_000_000_000,
        Gateway,
        Profile {
            slice: 2_000_000_000,
            z: 1_048_576,
            crypto: 262_144,
            window: 4_194_304,
            sent_records: 6_991,
            sent_record_bytes: 1_791_232,
            ack_ranges_per_space: 64,
            ack_range_bytes: 6_240,
            window_pool: 90_164_800,
            stream_window: 1_048_576,
            streams: 32,
            frame: 1_048_576,
            auth: 1_048_576,
            output: 65_536,
            raw_items: 64,
            control_items: 256,
            raw: 1_064_960,
            control: 393_216,
            owner: 47_298_336,
            incoming: 328_703,
            response: 66_048,
            preauth: 5_373_960,
            unit: 53_067_047,
            owners: 18,
            phases: [(18, 8), (18, 4), (16, 4), (18, 4), (18, 4)],
            sources: [18, 36, 18],
            active_cids: 8,
            queues: [18_874_368, 1_152, 4_718_592, 4_608],
            responses: [1_179_648, 18],
            derived: 1_914_607_996,
            s_pto: 2,
            k_pto: 3,
            ack_only_records: 2,
            t_np: NoProgressDeadline { pto_multiple: 3, minimum_ms: 10_000 },
            tracked_records: 6_997,
            metadata: MetadataBudget {
                frames_per_packet: 32,
                ranges_per_stream: 64,
                segments_per_stream: 64,
                scratch_entries: 6_997,
                charges: [
                    MetadataCharge {
                        class: AllocationClass::SentFrameMetadata,
                        count: 223_904,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 28_659_712,
                    },
                    MetadataCharge {
                        class: AllocationClass::RetransmitOwner,
                        count: 6_997,
                        capacity: 512,
                        item_charge: 576,
                        bytes: 4_030_272,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendRanges,
                        count: 4_096,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 524_288,
                    },
                    MetadataCharge {
                        class: AllocationClass::SendSegments,
                        count: 2_048,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 262_144,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveRanges,
                        count: 2_048,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 262_144,
                    },
                    MetadataCharge {
                        class: AllocationClass::ReceiveSegments,
                        count: 2_048,
                        capacity: 64,
                        item_charge: 128,
                        bytes: 262_144,
                    },
                    MetadataCharge {
                        class: AllocationClass::AckLossScratch,
                        count: 6_997,
                        capacity: 32,
                        item_charge: 128,
                        bytes: 895_616,
                    },
                ],
                total: 34_896_320,
            },
            delta_unit: 36_693_792,
        },
        85_392_004,
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
        A::Protocol,
        A::ProtocolFixed,
        A::SentFrameMetadata,
        A::RetransmitOwner,
        A::SendRanges,
        A::SendSegments,
        A::ReceiveRanges,
        A::ReceiveSegments,
        A::AckLossScratch,
        A::StreamPayload,
        A::StreamState,
        A::Sources,
        A::Tasks,
        A::Responses,
        A::Preauth,
        A::SharedConfig,
    ];
    assert_eq!(CENSUS.len(), classes.len());
    for class in classes {
        // Exhaustive match forces future variants to declare their expected pool/owners.
        let expected = match class {
            A::Socket | A::EndpointState | A::Runtime | A::SharedConfig => (P::Endpoint, 1, 7),
            A::Incoming => (P::Incoming, 1, 7),
            A::RawEvents => (P::Raw, 1, 7),
            A::Controls => (P::Control, 1, 7),
            A::Terminal => (P::Terminal, 1, 7),
            A::Crypto => (P::Crypto, 1, 7),
            A::Tls => (P::TlsOwner, 1, 7),
            A::Protocol
            | A::StreamPayload
            | A::SentFrameMetadata
            | A::RetransmitOwner
            | A::SendRanges
            | A::SendSegments
            | A::ReceiveRanges
            | A::ReceiveSegments
            | A::AckLossScratch => (P::Windows, 1, 7),
            A::ProtocolFixed => (P::Residual, 1, 7),
            A::StreamState => (P::Streams, 1, 7),
            A::Sources => (P::Sources, 1, 7),
            A::Tasks => (P::Tasks, 1, 7),
            A::Responses => (P::Response, 1, 6),
            A::Preauth => (P::Preauth, 1, 7),
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
    assert_eq!(lowered.listeners()[0].2.derived, 225_181_296);
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
    assert_eq!(
        (profiles[0].2.z, profiles[0].2.owners, profiles[0].2.derived),
        (131_072, 8, 119_481_968)
    );
    assert_eq!(
        (profiles[1].2.z, profiles[1].2.owners, profiles[1].2.derived),
        (131_072, 9, 120_326_830)
    );
    assert_eq!(profiles.iter().map(|l| l.2.derived).sum::<u64>(), 239_808_798);
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
fn sent_record_and_ack_range_credit_scale_with_window() {
    let mut previous = 0;
    for (z, base_owner) in [
        (128 * 1_024, 1_667_072),
        (256 * 1_024, 2_969_600),
        (512 * 1_024, 5_558_272),
        (1_024 * 1_024, 10_604_544),
    ] {
        let budget = plan(z * 512 * 4, vec![request("m", Mesh, None)]);
        let p = &budget.listeners()[0].2;
        assert_eq!(p.z, z);
        assert_eq!(p.sent_records, p.window.div_ceil(600));
        assert_eq!((p.s_pto, p.k_pto, p.ack_only_records), (2, 3, 2));
        assert_eq!(p.tracked_records, p.sent_records + 6);
        assert_eq!(p.sent_record_bytes, (p.sent_records + 6) * 256);
        assert_eq!(p.ack_ranges_per_space, 64);
        assert_eq!(
            p.ack_range_bytes,
            65 * 32 * 3,
            "ACK backing is constant, including transient insertion"
        );
        assert_eq!(p.delta_unit, (p.sent_records + 6) * 256 + 65 * 32 * 3 + p.metadata.total);
        assert_eq!(p.owner, base_owner + p.delta_unit, "DeltaUnit must affect owner/unit/N");
        assert_eq!(p.window_pool, 2 * (2 * p.window + p.delta_unit));
        assert!(p.sent_record_bytes > previous);
        previous = p.sent_record_bytes;
        assert_eq!((p.t_np.pto_multiple, p.t_np.minimum_ms), (3, 10_000));
        assert_eq!(p.t_np.timeout_ms(2_000).unwrap(), 10_000);
        assert_eq!(p.t_np.timeout_ms(5_000).unwrap(), 15_000);
        assert!(matches!(p.t_np.timeout_ms(u64::MAX), Err(BudgetError::Overflow)));
    }
}

#[test]
fn metadata_caps_charge_each_shape_and_assign_exhaustion_policy() {
    for (ram, role, _, _) in PROFILES {
        let budget = plan(ram, vec![request("m", role, None)]);
        let p = &budget.listeners()[0].2;
        assert_eq!(
            (
                p.metadata.frames_per_packet,
                p.metadata.ranges_per_stream,
                p.metadata.segments_per_stream
            ),
            (32, 64, 64)
        );
        assert_eq!(p.metadata.scratch_entries, p.sent_records + 6);
        let expected = [
            (A::SentFrameMetadata, p.tracked_records * 32, 64, 128),
            (A::RetransmitOwner, p.tracked_records, 512, 576),
            (A::SendRanges, p.streams * 64 * 2, 32, 128),
            (A::SendSegments, p.streams * 64, 64, 128),
            (A::ReceiveRanges, p.streams * 64, 32, 128),
            (A::ReceiveSegments, p.streams * 64, 64, 128),
            (A::AckLossScratch, p.tracked_records, 32, 128),
        ];
        let mut total = 0;
        for (shape, (class, count, capacity, charge)) in p.metadata.charges.iter().zip(expected) {
            assert_eq!(
                (shape.class, shape.count, shape.capacity, shape.item_charge),
                (class, count, capacity, charge)
            );
            assert_eq!(shape.item_charge, allocation_charge(shape.capacity).unwrap() as u64);
            assert_eq!(shape.bytes, count * charge);
            total += shape.bytes;
            let entry = CENSUS.iter().find(|e| e.class == class).unwrap();
            assert_eq!((entry.pool, entry.tokio_owner, entry.compio_owner), (Pool::Windows, 1, 7));
            assert_ne!(entry.exhaustion, "");
        }
        assert_eq!(p.metadata.total, total);
        assert!(p.owners >= 2);
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

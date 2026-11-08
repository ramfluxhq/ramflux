// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! §7.1 receive-entrypoint classification. Fixture-only sites are allow-listed;
//! every other production match must be a named live writer P25 migrates.

/// How a scanned receive writer is classified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriterClass {
    /// Live production path. P25 routes it through the executor.
    ProductionLegacy,
    /// Test / fixture-only direct ACK or checkpoint seed.
    FixtureOnly,
}

/// One scanned call site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WriterSite {
    pub file: &'static str,
    pub symbol: &'static str,
    pub class: WriterClass,
    pub executor: &'static str,
    pub hook: &'static str,
}

/// P19-owned §7.1 inventory (API → executor path → guard hook).
pub(crate) const SITES: &[WriterSite] = &[
    WriterSite {
        file: "src/client/account.rs",
        symbol: "persist_gateway_receive_cursor",
        class: WriterClass::ProductionLegacy,
        executor: "persist_receive_checkpoint_in (W2/reset token)",
        hook: "SQL receive-checkpoint",
    },
    WriterSite {
        file: "src/client/dm.rs",
        symbol: "receive_gateway_deliveries",
        class: WriterClass::ProductionLegacy,
        executor: "request_inbox_in + cover_in",
        hook: "inbox-request",
    },
    WriterSite {
        file: "src/client/dm.rs",
        symbol: "receive_gateway_plaintext_deliveries",
        class: WriterClass::ProductionLegacy,
        executor: "request_inbox_in + cover_in + remove_unrouted_in",
        hook: "inbox-request / hold-delete",
    },
    WriterSite {
        file: "src/client/dm.rs",
        symbol: "ack_gateway_entry",
        class: WriterClass::ProductionLegacy,
        executor: "send_ack_in (WA token)",
        hook: "outgoing ACK",
    },
    WriterSite {
        file: "src/client/dm.rs",
        symbol: "ack_gateway_delivery",
        class: WriterClass::ProductionLegacy,
        executor: "managed_public_ack / send_ack_in",
        hook: "outgoing ACK (refusal produces none)",
    },
    WriterSite {
        file: "src/client/a2i.rs",
        symbol: "receive_a2i_control_events",
        class: WriterClass::ProductionLegacy,
        executor: "request_inbox_in + cover_in + send_ack_in",
        hook: "inbox-request / outgoing ACK",
    },
    WriterSite {
        file: "src/client/dm/legacy_receive.rs",
        symbol: "persist_gateway_receive_cursor",
        class: WriterClass::ProductionLegacy,
        executor: "persist_receive_checkpoint_in (W2/reset token)",
        hook: "SQL receive-checkpoint",
    },
    WriterSite {
        file: "src/client/group_quarantine.rs",
        symbol: "remove_unrouted",
        class: WriterClass::ProductionLegacy,
        executor: "remove_unrouted_in",
        hook: "hold-delete",
    },
    WriterSite {
        file: "src/bus/connection_manager/receive.rs",
        symbol: "engine.ack",
        class: WriterClass::ProductionLegacy,
        executor: "send_ack_in (WA token)",
        hook: "outgoing ACK",
    },
    WriterSite {
        file: "src/bus/dispatch/a2i_a2ui.rs",
        symbol: "a2i.list",
        class: WriterClass::ProductionLegacy,
        executor: "request_inbox_in (coalesced catch-up)",
        hook: "inbox-request",
    },
    WriterSite {
        file: "src/bus/dispatch/group.rs",
        symbol: "persist_gateway_receive_cursor",
        class: WriterClass::ProductionLegacy,
        executor: "cover_in / persist_receive_checkpoint_in",
        hook: "SQL receive-checkpoint",
    },
    WriterSite {
        file: "src/bus/dispatch/group.rs",
        symbol: "ack_gateway_entry",
        class: WriterClass::ProductionLegacy,
        executor: "send_ack_in (WA token)",
        hook: "outgoing ACK",
    },
    WriterSite {
        file: "src/bus/dispatch/group.rs",
        symbol: "remove_unrouted",
        class: WriterClass::ProductionLegacy,
        executor: "group_remove_unrouted_in",
        hook: "hold-delete",
    },
    WriterSite {
        file: "src/bus/dispatch/message.rs",
        symbol: "message.ack",
        class: WriterClass::ProductionLegacy,
        executor: "managed_public_ack",
        hook: "outgoing ACK (typed refusal, no frame)",
    },
    WriterSite {
        file: "src/bus/dispatch/message.rs",
        symbol: "ack_gateway_entry",
        class: WriterClass::ProductionLegacy,
        executor: "message_receive_ack_in (WA)",
        hook: "outgoing ACK",
    },
    WriterSite {
        file: "src/bus/dispatch/message.rs",
        symbol: "remove_unrouted",
        class: WriterClass::ProductionLegacy,
        executor: "remove_unrouted_in",
        hook: "hold-delete",
    },
    WriterSite {
        file: "src/bus/connection_manager/client.rs",
        symbol: "engine.ack",
        class: WriterClass::ProductionLegacy,
        executor: "send_ack_in (WA token)",
        hook: "outgoing ACK",
    },
    WriterSite {
        file: "src/bus/sync_driver.rs",
        symbol: "advance_cursor",
        class: WriterClass::ProductionLegacy,
        executor: "cover_in / persist_receive_checkpoint_in",
        hook: "SQL receive-checkpoint",
    },
    WriterSite {
        file: "src/bus/sync_driver.rs",
        symbol: "ack_gateway_entry",
        class: WriterClass::ProductionLegacy,
        executor: "send_ack_in (WA token)",
        hook: "outgoing ACK",
    },
    WriterSite {
        file: "src/bus/sync_driver.rs",
        symbol: "remove_unrouted",
        class: WriterClass::ProductionLegacy,
        executor: "remove_unrouted_in",
        hook: "hold-delete",
    },
    WriterSite {
        file: "src/bus/sync_driver/ack.rs",
        symbol: "remove_unrouted",
        class: WriterClass::ProductionLegacy,
        executor: "remove_unrouted_in",
        hook: "hold-delete",
    },
    WriterSite {
        file: "src/client/dm_session.rs",
        symbol: "persist_gateway_receive_cursor",
        class: WriterClass::FixtureOnly,
        executor: "test fixture seed (excluded from production guard)",
        hook: "classified fixture",
    },
    WriterSite {
        file: "src/client/routed/root_ack_tests.rs",
        symbol: "ack_gateway_entry",
        class: WriterClass::FixtureOnly,
        executor: "unmanaged raw protocol fixture",
        hook: "classified fixture",
    },
    WriterSite {
        file: "src/bus/receipt_tests/erasure.rs",
        symbol: "ack_gateway_entry",
        class: WriterClass::FixtureOnly,
        executor: "unmanaged raw protocol fixture",
        hook: "classified fixture",
    },
    WriterSite {
        file: "src/bus/dispatch/surface_own_tests/followups.rs",
        symbol: "ack_gateway_entry",
        class: WriterClass::FixtureOnly,
        executor: "unmanaged raw protocol fixture",
        hook: "classified fixture",
    },
];

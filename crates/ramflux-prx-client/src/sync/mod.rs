// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Paged sync snapshot and the durable journal frames.
//! The WebSocket itself is owned by the agent host. This module decodes the frames and the
//! snapshot pages. Stream frames and run approvals are recognized and skipped.

mod cursor;
mod frame;
mod op;
mod snapshot;

pub use cursor::{SyncCursor, format_cursor, parse_cursor};
pub use frame::{JournalEvent, PONG_FRAME, ServerFrame, ack_frame, decode_server, hello_frame};
pub use op::{EraseCopy, MirrorOp, TurnBody, TurnCopy};
pub use snapshot::{SNAPSHOT_MAX_BODY, SNAPSHOT_PAGE_LIMIT, SnapshotPage, SnapshotRow};

/// Loopback address of the daemon, for the sync WebSocket upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDial {
    /// `127.0.0.1` or `::1`, without brackets.
    pub host: String,
    /// TCP port. Never zero.
    pub port: u16,
}

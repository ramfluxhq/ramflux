// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home-owned nontransferable publication context, serialized with every restrictive local write.
use super::{HomeDirectory, HomeProfileView, LiveHomeRevalidation, ROOTS, read_root};
use crate::username_directory::{CheckpointError, Result, fixed, require, storage};
use redb::ReadableDatabase;

pub struct HomePublication {
    root: String,
    channel: String,
    expires: u64,
    created_wall: u64,
    deadline: std::time::Instant,
    epoch: u64,
    binding: Option<String>,
    profile: ramflux_protocol::username_directory::ProfileRef,
    bytes: Vec<u8>,
    offset: usize,
}

#[derive(Clone, Copy)]
pub struct HomePublicationTarget<'a> {
    pub root: &'a str,
    pub channel: &'a str,
}

impl HomeDirectory {
    pub(super) fn publication_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.serving.lock().map_err(|_| CheckpointError::Refused("home_publication_lock"))
    }

    /// Build from a fresh wrapper, then retain only the exact tuple and one channel's writer state.
    /// # Errors
    /// Refuses noncurrent/hidden profiles, malformed channels and oversized final response bytes.
    pub fn prepare_publication(
        &self,
        target: HomePublicationTarget<'_>,
        live: LiveHomeRevalidation,
        master: &ed25519_dalek::VerifyingKey,
        now: u64,
        encode: impl FnOnce(&HomeProfileView) -> Result<Vec<u8>>,
    ) -> Result<HomePublication> {
        let HomePublicationTarget { root, channel } = target;
        fixed(channel)?;
        let expires = live.result.expires_at;
        let view = self.visible_profile(root, live, master, now)?;
        let bytes = encode(&view)?;
        require(
            bytes.len() <= crate::username_directory::MAX_REPORT_BYTES + 16384,
            "home_response_bound",
        )?;
        let ttl = expires
            .checked_sub(now)
            .filter(|n| *n > 0 && *n <= 10)
            .ok_or(CheckpointError::Refused("home_publication_clock"))?;
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(ttl))
            .ok_or(CheckpointError::Refused("home_publication_clock"))?;
        Ok(HomePublication {
            root: root.into(),
            channel: channel.into(),
            expires,
            created_wall: now,
            deadline,
            epoch: view.receipt.body.epoch,
            binding: view.receipt.body.binding_hash.clone(),
            profile: view.receipt.body.profile,
            bytes,
            offset: 0,
        })
    }

    /// The caller owns this socket and must close/reset it on error. Keep the local publication
    /// mutex through this one nonblocking handoff so H1/H3 suppression cannot race the check.
    /// # Errors
    /// Refuses expired wrappers, changed floors, suppression/deletion, wrong channels or IO errors.
    pub fn write_publication_step(
        &self,
        call: &mut HomePublication,
        channel: &str,
        now: u64,
        mut write: impl FnMut(&[u8]) -> std::io::Result<usize>,
    ) -> Result<bool> {
        let _guard = self.publication_guard()?;
        require(
            call.channel == channel
                && now >= call.created_wall
                && now < call.expires
                && std::time::Instant::now() < call.deadline,
            "home_publication_expired",
        )?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(ROOTS).map_err(storage)?;
        let state = read_root(&table, &call.root)?
            .ok_or(CheckpointError::Refused("home_publication_missing"))?;
        require(
            !state.deleted
                && !state.suppressed
                && state.directory_epoch == call.epoch
                && state.binding_hash == call.binding
                && state.profile_floor == call.profile,
            "home_publication_changed",
        )?;
        let remaining = call
            .bytes
            .get(call.offset..)
            .ok_or(CheckpointError::Refused("home_publication_offset"))?;
        match write(remaining) {
            Ok(0) => Err(CheckpointError::Refused("home_transport_closed")),
            Ok(count) if count <= remaining.len() => {
                call.offset += count;
                Ok(call.offset == call.bytes.len())
            }
            Ok(_) => Err(CheckpointError::Refused("home_transport_count")),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

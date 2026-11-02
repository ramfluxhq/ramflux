// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node-bound capacity deadlines and their persisted and displayed representations.
use super::{
    BornAccount, CreationState, MAX_STORED_AUTHORITY_BYTES, directory, load_account, write_public,
};
use crate::custody::{CAPACITY_RETRY_AFTER_MS, capacity_hint};
use crate::{AccountNetworkingReason, SdkError};
use std::{fs, os::unix::fs::OpenOptionsExt, path::Path};
mod clock;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct NetworkingView {
    #[serde(flatten)]
    pub(crate) cause: AccountNetworkingReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resets_at: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    clamped: bool,
}

impl BornAccount {
    pub(crate) fn bind_capacity_node(
        &mut self,
        root: &Path,
        node_id: &str,
        node_public_key: &str,
        now: u64,
    ) -> Result<(), SdkError> {
        let identity = capacity_hint::node_identity(node_id, node_public_key);
        self.update_networking(root, now, |current| {
            if current.stored.networking_node.as_ref() != Some(&identity) {
                // Old unbound hints cannot establish which node owns their deadline.
                current.stored.networking_node = Some(identity);
                current.stored.networking_reason = None;
                current.stored.capacity_retry_at = None;
                return true;
            }

            false
        })
    }

    #[cfg(test)]
    pub(crate) fn set_networking_reason(
        &mut self,
        root: &Path,
        reason: Option<AccountNetworkingReason>,
    ) -> Result<(), SdkError> {
        self.set_networking_reason_at(root, reason, capacity_hint::unix_now())
    }

    pub(crate) fn set_networking_reason_at(
        &mut self,
        root: &Path,
        mut reason: Option<AccountNetworkingReason>,
        now: u64,
    ) -> Result<(), SdkError> {
        if let Some(AccountNetworkingReason::NodeBusy { retry_after_ms, capacity: Some(hint) }) =
            reason.as_mut()
        {
            let accepted = capacity_hint::accepted(*hint, now);
            *retry_after_ms = CAPACITY_RETRY_AFTER_MS;
            if accepted.is_none() {
                reason = Some(AccountNetworkingReason::NodeBusy {
                    retry_after_ms: CAPACITY_RETRY_AFTER_MS,
                    capacity: None,
                });
            }
        }
        self.update_networking(root, now, |current| {
            let deadline = match reason.as_ref() {
                Some(AccountNetworkingReason::NodeBusy { retry_after_ms, capacity })
                    if capacity.is_some() || *retry_after_ms == CAPACITY_RETRY_AFTER_MS =>
                {
                    let active = current
                        .networking_view(now)
                        .and_then(|view| view.remaining_ms)
                        .is_some_and(|remaining| remaining > 0);
                    if current.stored.networking_reason == reason && active {
                        current.stored.capacity_retry_at
                    } else {
                        // A new refusal may share a wall timestamp after a clock correction.
                        clock::begin_refusal(&current.networking_path);
                        Some(
                            capacity
                                .map_or(0, |hint| hint.resets_at_unix)
                                .max(now.saturating_add(300)),
                        )
                    }
                }
                _ => None,
            };
            if current.stored.networking_reason == reason
                && current.stored.capacity_retry_at == deadline
            {
                return false;
            }
            current.stored.networking_reason = reason;
            current.stored.capacity_retry_at = deadline;
            true
        })
    }

    pub(crate) fn check_capacity_deadline(&self, now: u64) -> Result<(), SdkError> {
        if let Some(view) = self.networking_view(now)
            && self.stored.capacity_retry_at.is_some()
            && view.remaining_ms.is_some_and(|remaining| remaining > 0)
        {
            if let AccountNetworkingReason::NodeBusy { capacity: Some(capacity), .. } = view.cause {
                return Err(SdkError::CustodyCapacity { capacity });
            }
            return Err(ramflux_protocol::custody::CustodyRefusal::Capacity.into());
        }
        Ok(())
    }

    pub(crate) fn networking_view(&self, now: u64) -> Option<NetworkingView> {
        clock::view(
            self.networking_reason(),
            self.stored.capacity_retry_at,
            self.stored.networking_node.as_deref(),
            &self.networking_path,
            now,
        )
    }

    fn update_networking<F>(&mut self, root: &Path, now: u64, change: F) -> Result<(), SdkError>
    where
        F: FnOnce(&mut Self) -> bool,
    {
        if self.state() == CreationState::Live {
            return Ok(());
        }
        let dir = directory(root, self.local_account_id())?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join(".authority.lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let mut current = load_account(root, self.local_account_id(), now)?;
        if current.record() != self.record() || current.state() == CreationState::Live {
            return Ok(());
        }
        let clamped = clock::clamp(&mut current.stored, now);
        if change(&mut current) || clamped {
            let bytes = ramflux_protocol::canonical_json_bytes(&current.stored)?;
            if bytes.len() > MAX_STORED_AUTHORITY_BYTES {
                return Err(super::invalid());
            }
            let temp = dir.join(format!(
                ".authority-{}",
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
            ));
            write_public(&temp, &bytes)?;
            fs::rename(temp, dir.join("authority.json"))?;
            fs::File::open(&dir)?.sync_all()?;
            if clamped {
                clock::persisted(&dir, &current.stored);
            }
        }
        self.stored.networking_reason = current.stored.networking_reason;
        self.stored.networking_node = current.stored.networking_node;
        self.stored.capacity_retry_at = current.stored.capacity_retry_at;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

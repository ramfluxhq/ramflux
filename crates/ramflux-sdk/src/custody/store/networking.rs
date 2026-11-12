// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node-bound capacity deadlines and their persisted and displayed representations.
use super::{
    BornAccount, CreationState, MAX_STORED_AUTHORITY_BYTES, create_private_temp, directory,
    load_account,
};
use crate::custody::{CAPACITY_RETRY_AFTER_MS, CAPACITY_RETRY_AFTER_SECS, capacity_hint};
use crate::{AccountNetworkingReason, SdkError};
use std::{fs, path::Path};
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

    #[cfg(test)]
    pub(crate) fn set_networking_reason_at(
        &mut self,
        root: &Path,
        reason: Option<AccountNetworkingReason>,
        now: u64,
    ) -> Result<(), SdkError> {
        let shared_capacity = matches!(reason.as_ref(),
            Some(AccountNetworkingReason::NodeBusy { retry_after_ms, capacity })
                if capacity.is_some() || *retry_after_ms == CAPACITY_RETRY_AFTER_MS);
        self.persist_networking_reason_at(root, reason, now, shared_capacity)
    }

    pub(crate) fn set_networking_error_at(
        &mut self,
        root: &Path,
        reason: Option<AccountNetworkingReason>,
        error: &SdkError,
        now: u64,
    ) -> Result<(), SdkError> {
        let shared_capacity = matches!(
            error,
            SdkError::CustodyAdmission {
                code: ramflux_protocol::custody::CustodyRefusal::Capacity,
                ..
            } | SdkError::CustodyCapacity { .. }
                | SdkError::CustodyNetwork(ramflux_protocol::custody::CustodyRefusal::Capacity)
        );
        self.persist_networking_reason_at(root, reason, now, shared_capacity)
    }

    fn persist_networking_reason_at(
        &mut self,
        root: &Path,
        mut reason: Option<AccountNetworkingReason>,
        now: u64,
        shared_capacity: bool,
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
        let share_deadline = shared_capacity
            && matches!(reason.as_ref(), Some(AccountNetworkingReason::NodeBusy { .. }));
        self.update_networking(root, now, |current| {
            if share_deadline
                && current.stored.capacity_retry_at.is_some()
                && current.networking_view(now).is_some_and(|view| {
                    view.remaining_ms.is_some_and(|remaining| remaining > 0)
                        && Some(&view.cause) == reason.as_ref()
                })
            {
                return false;
            }
            let deadline = match reason.as_ref() {
                Some(AccountNetworkingReason::NodeBusy { retry_after_ms, capacity })
                    if share_deadline =>
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
                        Some(capacity.map_or(0, |hint| hint.resets_at_unix).max(
                            now.saturating_add(if capacity.is_some() {
                                CAPACITY_RETRY_AFTER_SECS
                            } else {
                                (*retry_after_ms).clamp(1000, 3_600_000).div_ceil(1000)
                            }),
                        ))
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
            if let AccountNetworkingReason::NodeBusy { retry_after_ms, capacity: None } = view.cause
                && matches!(self.networking_reason(), Some(AccountNetworkingReason::NodeBusy {
                    retry_after_ms, capacity: None
                }) if *retry_after_ms != CAPACITY_RETRY_AFTER_MS)
            {
                return Err(SdkError::CustodyAdmission {
                    code: ramflux_protocol::custody::CustodyRefusal::Capacity,
                    retry: ramflux_protocol::custody::RetryHint::new(
                        ramflux_protocol::custody::RetryScope::NodeCapacity,
                        u32::try_from(retry_after_ms).unwrap_or(u32::MAX),
                    ),
                });
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
        let lock = crate::platform::fs::open_owner_only_read_write(&dir.join(".authority.lock"))?;
        crate::platform::fs::lock_exclusive(&lock)?;
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
            create_private_temp(&temp, &bytes)?;
            fs::rename(temp, dir.join("authority.json"))?;
            crate::platform::fs::sync_path(&dir)?;
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

#[cfg(all(test, unix))]
mod tests;

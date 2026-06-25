// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]

use crate::NodeCoreError;
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SessionLifecycle {
    Authed,
    Live,
    Draining,
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionDescriptor {
    pub target_delivery_id: String,
    pub device_id: String,
    pub gateway_id: String,
    pub session_id: String,
    pub device_epoch: u64,
    pub session_seq: u64,
    pub last_cursor: Option<String>,
    pub push_alias_hash: Option<String>,
    pub lifecycle: SessionLifecycle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WakeHint {
    pub target_delivery_id: String,
    pub push_alias_hash: Option<String>,
    pub delivery_class: ramflux_protocol::DeliveryClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeliveryDecision {
    Online { gateway_id: String, session_id: String, target_delivery_id: String },
    OfflineWake(WakeHint),
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionRegistry {
    sessions_by_target: BTreeMap<String, SessionDescriptor>,
}

impl SessionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn upsert_session(&mut self, descriptor: SessionDescriptor) -> Result<(), NodeCoreError> {
        if let Some(existing) = self.sessions_by_target.get(&descriptor.target_delivery_id)
            && is_stale_session_update(existing, &descriptor)
        {
            return Err(NodeCoreError::StaleSessionUpdate {
                target_delivery_id: descriptor.target_delivery_id,
            });
        }
        self.sessions_by_target.insert(descriptor.target_delivery_id.clone(), descriptor);
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mark_live(&mut self, target_delivery_id: &str) -> Result<(), NodeCoreError> {
        self.update_lifecycle(target_delivery_id, SessionLifecycle::Live)
    }

    /// # Errors
    /// Returns an error when the target session does not exist.
    pub fn mark_draining(&mut self, target_delivery_id: &str) -> Result<(), NodeCoreError> {
        self.update_lifecycle(target_delivery_id, SessionLifecycle::Draining)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn close_session(&mut self, target_delivery_id: &str) -> Result<(), NodeCoreError> {
        self.update_lifecycle(target_delivery_id, SessionLifecycle::Closed)
    }

    /// # Errors
    /// Returns an error when the target session does not exist.
    pub fn update_cursor(
        &mut self,
        target_delivery_id: &str,
        cursor_id: &str,
    ) -> Result<(), NodeCoreError> {
        let session = self
            .sessions_by_target
            .get_mut(target_delivery_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(target_delivery_id.to_owned()))?;
        session.last_cursor = Some(cursor_id.to_owned());
        Ok(())
    }

    #[must_use]
    pub fn resume_cursor(&self, target_delivery_id: &str) -> Option<&str> {
        self.sessions_by_target
            .get(target_delivery_id)
            .and_then(|session| session.last_cursor.as_deref())
    }

    #[must_use]
    pub fn session(&self, target_delivery_id: &str) -> Option<&SessionDescriptor> {
        self.sessions_by_target.get(target_delivery_id)
    }

    pub(crate) fn restore_session(&mut self, descriptor: SessionDescriptor) {
        self.sessions_by_target.insert(descriptor.target_delivery_id.clone(), descriptor);
    }

    pub(crate) fn sessions(&self) -> impl Iterator<Item = &SessionDescriptor> {
        self.sessions_by_target.values()
    }

    pub(crate) fn merge_from(&mut self, other: &Self) {
        self.sessions_by_target.extend(
            other
                .sessions_by_target
                .iter()
                .map(|(target, session)| (target.clone(), session.clone())),
        );
    }

    #[must_use]
    pub fn route_envelope(&self, envelope: &ramflux_protocol::Envelope) -> DeliveryDecision {
        self.route_target(&envelope.target_delivery_id, envelope.delivery_class.clone())
    }

    #[must_use]
    pub fn route_target(
        &self,
        target_delivery_id: &str,
        delivery_class: ramflux_protocol::DeliveryClass,
    ) -> DeliveryDecision {
        if let Some(session) = self.sessions_by_target.get(target_delivery_id)
            && session.lifecycle == SessionLifecycle::Live
        {
            return DeliveryDecision::Online {
                gateway_id: session.gateway_id.clone(),
                session_id: session.session_id.clone(),
                target_delivery_id: session.target_delivery_id.clone(),
            };
        }
        DeliveryDecision::OfflineWake(WakeHint {
            target_delivery_id: target_delivery_id.to_owned(),
            push_alias_hash: self
                .sessions_by_target
                .get(target_delivery_id)
                .and_then(|session| session.push_alias_hash.clone()),
            delivery_class,
        })
    }

    fn update_lifecycle(
        &mut self,
        target_delivery_id: &str,
        lifecycle: SessionLifecycle,
    ) -> Result<(), NodeCoreError> {
        let session = self
            .sessions_by_target
            .get_mut(target_delivery_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(target_delivery_id.to_owned()))?;
        session.lifecycle = lifecycle;
        Ok(())
    }

    pub(crate) fn remove_target(&mut self, target_delivery_id: &str) -> bool {
        self.sessions_by_target.remove(target_delivery_id).is_some()
    }

    #[must_use]
    pub(crate) fn contains_target(&self, target_delivery_id: &str) -> bool {
        self.sessions_by_target.contains_key(target_delivery_id)
    }
}

fn is_stale_session_update(existing: &SessionDescriptor, incoming: &SessionDescriptor) -> bool {
    incoming.device_epoch < existing.device_epoch
        || (incoming.device_epoch == existing.device_epoch
            && incoming.session_seq < existing.session_seq)
}

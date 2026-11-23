// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Witness-owned live authority. Every transport write rechecks the same nontransferable context.
use super::{CheckpointError, CheckpointHead, CheckpointTime, Result, fixed, require};
use std::collections::BTreeMap;
mod refusal;

const LEASE_MILLIS: u64 = 10_000;
const CALL_MILLIS: u64 = 10_000;
const MAX_RESPONSE_BYTES: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterIdentity {
    pub generation: u64,
    pub witness_boot: String,
    pub incarnation: String,
}

/// Exact facts sampled by the witness for this handoff; this is no serving capability.
#[derive(Clone, Copy)]
pub struct ServingState<'a> {
    pub identity: &'a WriterIdentity,
    pub head: &'a CheckpointHead,
    pub time: CheckpointTime,
}

struct Lease {
    identity: WriterIdentity,
    deadline: u64,
}

/// A call is bound to one already authenticated channel and exact request.
#[derive(Clone)]
pub struct ServingCall {
    pub root: String,
    pub home: String,
    pub channel: String,
    pub request: super::DirectoryRequest,
}

struct Call {
    owner: Option<ServingCall>,
    channel: String,
    refusal: Option<ramflux_protocol::username_directory::DirectoryCode>,
    deadline: u64,
    head: CheckpointHead,
    identity: WriterIdentity,
    bytes: Option<Vec<u8>>,
    written: usize,
}

/// Owned by the witness/front-door actor. There is no serializable READY flag or permit.
pub struct ServingFence {
    generation: u64,
    boot: String,
    lease: Option<Lease>,
    applied: Option<CheckpointHead>,
    calls: BTreeMap<String, Call>,
    last_monotonic: u64,
}

impl ServingFence {
    /// # Errors
    /// Refuses an invalid trust generation or unavailable system randomness.
    pub fn new(generation: u64) -> Result<Self> {
        require(
            generation > 0 && generation <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "generation",
        )?;
        Ok(Self {
            generation,
            boot: random_id()?,
            lease: None,
            applied: None,
            calls: BTreeMap::new(),
            last_monotonic: 0,
        })
    }

    /// Authenticated peer loss invalidates every context, even if the old lease time remains.
    pub fn disconnect(&mut self) {
        self.lease = None;
        self.applied = None;
        self.calls.clear();
    }

    fn observe_clock(&mut self, time: CheckpointTime) -> Result<()> {
        if time.monotonic < self.last_monotonic
            || time.wall > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        {
            self.disconnect();
            return Err(CheckpointError::Refused("clock"));
        }
        self.last_monotonic = time.monotonic;
        if self.lease.as_ref().is_some_and(|l| time.monotonic >= l.deadline) {
            self.disconnect();
        }
        self.calls.retain(|_, call| time.monotonic < call.deadline);
        Ok(())
    }

    /// Acquires a fresh incarnation only; primary reconciliation is a separate durable barrier.
    /// # Errors
    /// Refuses an occupied lease, unsafe clock, overflow or unavailable randomness.
    pub fn acquire(&mut self, time: CheckpointTime) -> Result<WriterIdentity> {
        self.observe_clock(time)?;
        require(self.lease.is_none(), "writer_busy")?;
        let identity = WriterIdentity {
            generation: self.generation,
            witness_boot: self.boot.clone(),
            incarnation: random_id()?,
        };
        let deadline =
            time.monotonic.checked_add(LEASE_MILLIS).ok_or(CheckpointError::Refused("clock"))?;
        self.lease = Some(Lease { identity: identity.clone(), deadline });
        self.applied = None;
        self.calls.clear();
        Ok(identity)
    }

    /// # Errors
    /// An expired, foreign or disconnected incarnation cannot be renewed into serving authority.
    pub fn renew(&mut self, identity: &WriterIdentity, time: CheckpointTime) -> Result<()> {
        self.check_writer(identity, time)?;
        let deadline =
            time.monotonic.checked_add(LEASE_MILLIS).ok_or(CheckpointError::Refused("clock"))?;
        if let Some(lease) = &mut self.lease {
            lease.deadline = deadline;
        }
        Ok(())
    }

    /// # Errors
    /// Refuses retired identities and expiry using the witness's own clock.
    pub fn check_writer(&mut self, identity: &WriterIdentity, time: CheckpointTime) -> Result<()> {
        self.observe_clock(time)?;
        require(
            self.lease.as_ref().is_some_and(|lease| lease.identity == *identity),
            "writer_fenced",
        )
    }

    /// Head advance immediately invalidates every candidate and primary-applied marker.
    pub fn advancing_head(&mut self) {
        self.applied = None;
        self.calls.clear();
    }

    /// Called only by the authenticated current writer after its matching primary fsync.
    /// # Errors
    /// Refuses stale callbacks, wrong boots/heads and foreign generations.
    pub fn primary_applied(
        &mut self,
        identity: &WriterIdentity,
        primary: &CheckpointHead,
        witness: &CheckpointHead,
        time: CheckpointTime,
    ) -> Result<()> {
        self.check_writer(identity, time)?;
        require(primary == witness && witness.generation == self.generation, "primary_mismatch")?;
        self.applied = Some(primary.clone());
        Ok(())
    }

    pub(super) fn check_ready(
        &mut self,
        identity: &WriterIdentity,
        head: &CheckpointHead,
        time: CheckpointTime,
    ) -> Result<()> {
        self.check_writer(identity, time)?;
        require(self.applied.as_ref() == Some(head), "primary_unapplied")
    }

    /// No response buffer or call ID is allocated until authority and per-owner caps pass.
    /// # Errors
    /// Refuses stale authority, malformed owner/channel facts and saturated context quotas.
    pub fn admit(
        &mut self,
        identity: &WriterIdentity,
        head: &CheckpointHead,
        owner: ServingCall,
        time: CheckpointTime,
    ) -> Result<String> {
        self.check_ready(identity, head, time)?;
        fixed(&owner.root)?;
        fixed(&owner.channel)?;
        super::config::validate_node(&owner.home)?;
        owner.request.validate()?;
        require(
            self.calls.len() < 64
                && self
                    .calls
                    .values()
                    .filter(|c| c.owner.as_ref().is_some_and(|call| call.root == owner.root))
                    .count()
                    < 4
                && self
                    .calls
                    .values()
                    .filter(|c| c.owner.as_ref().is_some_and(|call| call.home == owner.home))
                    .count()
                    < 16,
            "serving_capacity",
        )?;
        let id = random_id()?;
        require(!self.calls.contains_key(&id), "call_collision")?;
        let deadline =
            time.monotonic.checked_add(CALL_MILLIS).ok_or(CheckpointError::Refused("clock"))?;
        self.calls.insert(
            id.clone(),
            Call {
                channel: owner.channel.clone(),
                owner: Some(owner),
                refusal: None,
                deadline,
                head: head.clone(),
                identity: identity.clone(),
                bytes: None,
                written: 0,
            },
        );
        Ok(id)
    }

    /// Consume a response candidate after the witness has verified it against its current image.
    /// No bytes or transferable publication permit are returned to the centre daemon.
    /// # Errors
    /// Refuses wrong tuple/call/head/channel correlation, duplicate candidates or excessive size.
    pub(crate) fn queue(
        &mut self,
        state: ServingState<'_>,
        call_id: &str,
        channel: &str,
        bytes: Vec<u8>,
    ) -> Result<()> {
        require(
            self.calls.get(call_id).is_some_and(|call| call.owner.is_some()),
            "anonymous_response",
        )?;
        self.queue_inner(state, call_id, channel, bytes)
    }

    fn queue_inner(
        &mut self,
        state: ServingState<'_>,
        call_id: &str,
        channel: &str,
        bytes: Vec<u8>,
    ) -> Result<()> {
        let ServingState { identity, head, time } = state;
        self.check_ready(identity, head, time)?;
        require(bytes.len() <= MAX_RESPONSE_BYTES, "candidate_size")?;
        let call = self.calls.get_mut(call_id).ok_or(CheckpointError::Refused("call_missing"))?;
        require(
            call.identity == *identity
                && call.head == *head
                && call.channel == channel
                && call.bytes.is_none(),
            "call_mismatch",
        )?;
        call.bytes = Some(bytes);
        Ok(())
    }

    /// One bounded nonblocking transport handoff, with no await or released permit between
    /// checking the live authority and invoking the witness-owned writer.
    /// The adapter must close/reset its stream on any error, including a partial response.
    /// # Errors
    /// Refuses stale/expired calls, newer heads and transport errors; drops the entire context.
    pub fn write_step(
        &mut self,
        state: ServingState<'_>,
        call_id: &str,
        channel: &str,
        mut try_write: impl FnMut(&[u8]) -> std::io::Result<usize>,
    ) -> Result<bool> {
        let ServingState { identity, head, time } = state;
        if let Err(error) = self.check_ready(identity, head, time) {
            self.calls.remove(call_id);
            return Err(error);
        }
        let result = (|| {
            let call =
                self.calls.get_mut(call_id).ok_or(CheckpointError::Refused("call_missing"))?;
            require(
                call.identity == *identity && call.head == *head && call.channel == channel,
                "call_mismatch",
            )?;
            let bytes = call.bytes.as_ref().ok_or(CheckpointError::Refused("candidate_missing"))?;
            let remaining =
                bytes.get(call.written..).ok_or(CheckpointError::Refused("candidate_offset"))?;
            match try_write(remaining) {
                Ok(0) => Err(CheckpointError::Refused("transport_closed")),
                Ok(count) if count <= remaining.len() => {
                    call.written += count;
                    Ok(call.written == bytes.len())
                }
                Ok(_) => Err(CheckpointError::Refused("transport_count")),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error.into()),
            }
        })();
        if !matches!(result, Ok(false)) {
            self.calls.remove(call_id);
        }
        result
    }

    pub fn cancel(&mut self, call_id: &str) {
        self.calls.remove(call_id);
    }

    pub(crate) fn call(&self, call_id: &str) -> Result<&ServingCall> {
        self.calls
            .get(call_id)
            .and_then(|call| call.owner.as_ref())
            .ok_or(CheckpointError::Refused("call_missing"))
    }
}

pub(super) fn random_id() -> Result<String> {
    Ok(ramflux_protocol::encode_base64url(
        ramflux_crypto::random_32().map_err(|_| CheckpointError::Refused("randomness"))?,
    ))
}

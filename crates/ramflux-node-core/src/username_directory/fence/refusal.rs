// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Anonymous contexts can emit only their fixed non-name refusal through the ordinary fence.
use super::{CALL_MILLIS, Call, ServingFence, ServingState, random_id};
use crate::username_directory::{CheckpointError, Result, fixed, require};
use ramflux_protocol::username_directory::DirectoryCode as Code;

impl ServingFence {
    pub(crate) fn admit_anonymous(
        &mut self,
        state: ServingState<'_>,
        channel: &str,
        code: Code,
    ) -> Result<String> {
        let ServingState { identity, head, time } = state;
        self.check_ready(identity, head, time)?;
        fixed(channel)?;
        require(
            matches!(
                code,
                Code::AuthenticationRequired
                    | Code::RateLimited
                    | Code::Capacity
                    | Code::DirectoryUnavailable
                    | Code::UnsupportedVersion
            ),
            "anonymous_name_fact",
        )?;
        require(
            self.calls.len() < 64
                && self.calls.values().filter(|call| call.owner.is_none()).count() < 16,
            "serving_capacity",
        )?;
        let id = random_id()?;
        require(!self.calls.contains_key(&id), "call_collision")?;
        let deadline =
            time.monotonic.checked_add(CALL_MILLIS).ok_or(CheckpointError::Refused("clock"))?;
        self.calls.insert(
            id.clone(),
            Call {
                owner: None,
                channel: channel.into(),
                refusal: Some(code),
                deadline,
                head: head.clone(),
                identity: identity.clone(),
                bytes: None,
                written: 0,
            },
        );
        Ok(id)
    }

    pub(crate) fn anonymous(&self, id: &str) -> bool {
        self.calls.get(id).is_some_and(|call| call.owner.is_none())
    }

    pub(crate) fn queue_anonymous(
        &mut self,
        state: ServingState<'_>,
        id: &str,
        channel: &str,
        code: Code,
        bytes: Vec<u8>,
    ) -> Result<()> {
        require(
            self.calls
                .get(id)
                .is_some_and(|call| call.owner.is_none() && call.refusal == Some(code)),
            "anonymous_response",
        )?;
        self.queue_inner(state, id, channel, bytes)
    }
}

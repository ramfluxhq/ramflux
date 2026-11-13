// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account runtime bounds and individually injectable deadline origins.

use std::time::Duration;

pub(crate) const NETWORK_WAIT: Duration = Duration::from_secs(5);
pub(crate) const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const COMMAND_DEADLINE: Duration = Duration::from_secs(25);
pub(crate) const CALL_QUEUE: usize = 32;
pub(crate) const SUBSCRIBER_QUEUE: usize = 256;
pub(crate) const LIFECYCLE_QUEUE: usize = 4;
pub(crate) const SESSION_BUFFER: usize = 256;
pub(crate) const SESSION_BUFFER_BYTES: usize = 8 * ramflux_transport::MAX_GATEWAY_FRAME_BYTES;
pub(crate) const TRANSFER_SLOTS: usize = 2;
pub(crate) const TRANSFER_QUEUE: usize = 16;
pub(crate) const KEEPALIVE_IDLE: Duration = Duration::from_secs(25);
pub(crate) const KEEPALIVE_CALL: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub(crate) struct RuntimeTimeouts {
    pub network_wait: Duration,
    pub attempt: Duration,
    pub call: Duration,
    pub receipt: Duration,
    pub task_approval: Duration,
    pub task_submit: Duration,
    pub http: Duration,

    pub command: Duration,
    pub post_claim: Duration,
    pub frame: Duration,
    pub transport_open: Duration,
    #[cfg(test)]
    pub retry_budget: Duration,
    pub receive_min: Duration,
    pub receive_max: Duration,
    pub sync: Duration,
    pub fetch: Duration,
    pub keepalive_idle: Duration,
    pub keepalive_call: Duration,
}

impl Default for RuntimeTimeouts {
    fn default() -> Self {
        Self {
            network_wait: NETWORK_WAIT,
            attempt: ATTEMPT_TIMEOUT,
            call: CALL_TIMEOUT,
            receipt: Duration::from_secs(3),
            task_approval: Duration::from_secs(1),
            task_submit: Duration::from_secs(15),
            http: crate::prekey::SDK_HTTP_TIMEOUT,

            command: COMMAND_DEADLINE,
            post_claim: COMMAND_DEADLINE,
            frame: crate::constants::GATEWAY_SESSION_NETWORK_TIMEOUT,
            transport_open: crate::constants::GATEWAY_SESSION_NETWORK_TIMEOUT,
            #[cfg(test)]
            retry_budget: Duration::from_secs(90),
            receive_min: Duration::from_millis(250),
            receive_max: Duration::from_secs(5),
            sync: Duration::from_secs(20),
            fetch: Duration::from_secs(20),
            keepalive_idle: KEEPALIVE_IDLE,
            keepalive_call: KEEPALIVE_CALL,
        }
    }
}

impl RuntimeTimeouts {
    pub(super) fn configured() -> Result<Self, crate::SdkError> {
        let schedule = super::sync_driver::Schedule::new()?;
        Ok(Self { receive_min: schedule.min, receive_max: schedule.max, ..Self::default() })
    }
}

impl RuntimeTimeouts {
    #[cfg(test)]
    pub(crate) fn held_for_test() -> Self {
        let held = Duration::from_secs(600);
        Self {
            network_wait: held,
            attempt: held,
            call: held,
            receipt: held,
            task_approval: held,
            task_submit: held,
            http: held,
            command: held,
            post_claim: held,
            frame: held,
            transport_open: held,
            retry_budget: held,
            receive_min: held,
            receive_max: held,
            sync: held,
            fetch: held,
            keepalive_idle: held,
            keepalive_call: held,
        }
    }
}

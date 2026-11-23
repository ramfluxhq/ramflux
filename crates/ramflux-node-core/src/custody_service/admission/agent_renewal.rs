// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Renewal consults this hook before extending a native grant.
//! `RouterCore::require_agent_operable` is not in this tree, so the hook admits.
//! It does not read retirement rows or reimplement that fence.

use ramflux_protocol::custody::DeviceRef;

/// What this build can say about an agent's retirement.
/// A linked fence adds a refusal variant. This build does not invent that check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentRenewalFence {
    /// The agent-custody fence is not linked. Renewal does not invent one.
    NotLinked,
}

/// Account anchor is the value `require_agent_operable` takes once that method is linked.
#[must_use]
pub(crate) fn admit_agent_renewal(device: &DeviceRef) -> AgentRenewalFence {
    let _anchor = device.account_anchor.as_str();
    AgentRenewalFence::NotLinked
}

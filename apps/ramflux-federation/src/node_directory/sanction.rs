// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sanction checks applied by the node at its two peer boundaries: outbound forwarding and inbound
//! envelopes. `s` (suspended) and `r` (revoked) refuse under `refuse` mode and log under `observe`.
//! `l` (limited) and `a` (active) never change behaviour. A sanction never removes an existing pin.

use ramflux_node_core::{NodeCoreError, NodeDirectorySanctionMode};

use super::{State, sanction_mode, sanction_of};

const LOG_TARGET: &str = "ramflux_federation_directory";

/// Returns `Err` when the peer must be refused. Cheap: a single map lookup on the held snapshot.
pub(crate) fn check_peer(domain: &str, direction: &str) -> Result<(), NodeCoreError> {
    let Some(state) = sanction_of(domain)? else { return Ok(()) };
    if state == State::Limited {
        tracing::debug!(target: LOG_TARGET, %domain, direction, "peer limited by directory");
        return Ok(());
    }
    if !state.sanctioned() {
        return Ok(());
    }
    match sanction_mode() {
        Some(NodeDirectorySanctionMode::Refuse) => {
            tracing::warn!(target: LOG_TARGET, %domain, direction, state = state.code(), "peer sanctioned; refused");
            Err(NodeCoreError::Unauthorized("peer_sanctioned".to_owned()))
        }
        Some(NodeDirectorySanctionMode::Observe) => {
            tracing::info!(target: LOG_TARGET, %domain, direction, state = state.code(), "peer sanctioned; observed only");
            Ok(())
        }
        None => Ok(()),
    }
}

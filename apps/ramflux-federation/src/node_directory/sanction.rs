// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sanction checks at the node's peer boundaries: outbound pin/forward, inbound envelopes and
//! installation of a pin. The decision reads sticky state (section 3a point 4), so an expired
//! snapshot keeps applying what it taught. Under `refuse` a sanctioned peer or a peer that breaks
//! the domain binding is refused; under `observe` it is only logged. A sanction never removes a pin.

use ramflux_node_core::{NodeCoreError, NodeDirectorySanctionMode};

use super::{decide, sanction_mode};

const LOG_TARGET: &str = "ramflux_federation_directory";

/// `Err` when the peer must be refused. `key` is the node key when it is known.
pub(crate) fn check_peer(
    domain: &str,
    key: Option<&str>,
    direction: &str,
) -> Result<(), NodeCoreError> {
    let Err(reason) = decide(domain, key) else { return Ok(()) };
    match sanction_mode() {
        Some(NodeDirectorySanctionMode::Observe) => {
            tracing::info!(target: LOG_TARGET, %domain, direction, reason, "peer sanctioned; observed only");
            Ok(())
        }
        Some(NodeDirectorySanctionMode::Refuse) | None => {
            tracing::warn!(target: LOG_TARGET, %domain, direction, reason, "peer refused by directory");
            Err(match reason {
                "domain_binding" => NodeCoreError::ItestHttp("directory_key_mismatch".to_owned()),
                _ => NodeCoreError::Unauthorized("peer_sanctioned".to_owned()),
            })
        }
    }
}

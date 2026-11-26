// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sanction checks at the node's peer boundaries: outbound pin/forward, inbound envelopes and
//! installation of a pin. The decision reads sticky state (section 3a point 4), so an expired
//! snapshot keeps applying what it taught. Under `refuse` a sanctioned peer or a peer that breaks
//! the domain binding is refused; under `observe` it is only logged. A suspension keeps the pin. A
//! pin whose key the directory revoked is dropped (`release_revoked_pin`); the revoked key stays
//! refused for good and the domain can pin again only a key equal to the directory's live key.

use ramflux_node_core::{NodeCoreError, NodeDirectorySanctionMode};

use super::{decide, sanction_mode};

const LOG_TARGET: &str = "ramflux_federation_directory";

/// Operator pin (admin path). A revoked key is refused; any other sanction is logged and the pin
/// proceeds, as does every pin while the directory is off. An unavailable directory state refuses.
pub(crate) fn operator_pin(domain: &str, key: &str) -> Result<(), NodeCoreError> {
    let Err(reason) = decide(domain, Some(key)) else { return Ok(()) };
    if reason == "unavailable" || super::key_revoked(key) {
        tracing::warn!(target: LOG_TARGET, %domain, reason, "operator pin refused by directory");
        return Err(NodeCoreError::Unauthorized("peer_revoked".to_owned()));
    }
    tracing::warn!(target: LOG_TARGET, %domain, reason, "operator pinned a sanctioned peer");
    Ok(())
}

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

/// Drops the pin of `domain` when it holds a key the directory has revoked (section 3: revoked
/// drops the pin). Does nothing under `observe`, for suspended keys or when no pin exists.
pub(crate) fn release_revoked_pin(
    domain: &str,
    state: &crate::state::SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
) -> Result<(), NodeCoreError> {
    if !matches!(sanction_mode(), Some(NodeDirectorySanctionMode::Refuse)) {
        return Ok(());
    }
    let Some(key) = state.snapshot()?.pinned_node_public_key(domain) else { return Ok(()) };
    if !super::key_revoked(&key) {
        return Ok(());
    }
    let dropped =
        state.update_and_save(store, |trust| Ok(trust.drop_discovery_pin(domain, &key)))?;
    if dropped {
        tracing::warn!(target: LOG_TARGET, %domain, "pin dropped: pinned key revoked by directory");
    }
    Ok(())
}

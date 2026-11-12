// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Service dependency builds never inherit the unit-test fixture key exemption.
use ramflux_node_core::{GatewayPreAuthPolicy, GatewayState, NodeCoreError};

#[test]
fn enabled_service_requires_a_separate_mounted_cookie_key() -> Result<(), Box<dyn std::error::Error>>
{
    let mut state = GatewayState::new();
    state.set_pre_auth_policy(GatewayPreAuthPolicy {
        enabled: true,
        per_source_ip_handshake_rate: 1,
        ..Default::default()
    })?;
    assert!(matches!(
        state.validate_pre_auth_configuration(),
        Err(NodeCoreError::PreAuthConfigInvalid)
    ));
    assert!(matches!(
        state.check_pre_auth("fixture-source", None, 100),
        Err(NodeCoreError::PreAuthConfigInvalid)
    ));
    assert!(
        state
            .check_pre_auth(
                "fixture-source",
                Some(ramflux_node_core::DEFAULT_PRE_AUTH_COOKIE_SECRET),
                100
            )
            .is_err()
    );
    Ok(())
}

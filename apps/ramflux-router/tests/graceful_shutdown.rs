// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[path = "../../../tests/configured_shutdown.rs"]
mod configured_shutdown;

#[cfg(feature = "itest-http")]
#[path = "../../../tests/shutdown_identity.rs"]
mod shutdown_identity;

#[cfg(unix)]
#[test]
fn configured_service_drains_and_closes_redb_on_sigterm() -> Result<(), Box<dyn std::error::Error>>
{
    #[cfg(feature = "itest-http")]
    let seed = Some(
        shutdown_identity::seed as fn(&std::path::Path) -> Result<(), Box<dyn std::error::Error>>,
    );
    #[cfg(not(feature = "itest-http"))]
    let seed = None;
    configured_shutdown::configured_shutdown_with_registration(
        env!("CARGO_BIN_EXE_ramflux-router"),
        "ramflux-router",
        seed,
    )
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[path = "../../../tests/configured_shutdown.rs"]
mod configured_shutdown;

#[cfg(unix)]
#[test]
fn configured_service_drains_and_closes_redb_on_sigterm() -> Result<(), Box<dyn std::error::Error>>
{
    configured_shutdown::configured_shutdown_is_clean(
        env!("CARGO_BIN_EXE_ramflux-gateway"),
        "ramflux-gateway",
    )
}

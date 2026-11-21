// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process entrypoint for the configured relay service.
fn main() {
    if let Err(error) = ramflux_relay::run() {
        eprintln!("ramflux-relay: {error}");
        std::process::exit(2);
    }
}

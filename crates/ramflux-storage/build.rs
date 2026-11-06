// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ramflux_production)");
    println!("cargo:rerun-if-env-changed=RAMFLUX_PRODUCTION_BUILD");
    if std::env::var("RAMFLUX_PRODUCTION_BUILD").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=ramflux_production");
    }
}

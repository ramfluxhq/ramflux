// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ramflux_release_profile)");
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo:rustc-cfg=ramflux_release_profile");
    }
    println!("cargo:rustc-check-cfg=cfg(ramflux_itest)");
    println!("cargo:rerun-if-env-changed=RAMFLUX_ITEST_BUILD");
    if std::env::var("RAMFLUX_ITEST_BUILD").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=ramflux_itest");
    }
    println!("cargo:rustc-check-cfg=cfg(ramflux_production)");
    println!("cargo:rerun-if-env-changed=RAMFLUX_PRODUCTION_BUILD");
    if std::env::var("RAMFLUX_PRODUCTION_BUILD").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=ramflux_production");
    }

    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    println!("cargo:rerun-if-changed=src/c_abi");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    if std::env::var_os("CARGO_FEATURE_C_ABI").is_none() {
        return;
    }

    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(value) => value,
        Err(error) => {
            println!("cargo:warning=failed to locate manifest dir for cbindgen: {error}");
            return;
        }
    };
    let target_root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || std::path::Path::new(&manifest_dir).join("target"),
        std::path::PathBuf::from,
    );
    let target_dir = target_root.join("include");
    if let Err(error) = std::fs::create_dir_all(&target_dir) {
        println!("cargo:warning=failed to create cbindgen output dir: {error}");
        return;
    }
    let config_path = std::path::Path::new(&manifest_dir).join("cbindgen.toml");
    let output_path = target_dir.join("ramflux_sdk.h");
    let config = match cbindgen::Config::from_file(&config_path) {
        Ok(config) => config,
        Err(error) => {
            println!("cargo:warning=failed to read cbindgen config: {error}");
            return;
        }
    };
    match cbindgen::Builder::new().with_crate(&manifest_dir).with_config(config).generate() {
        Ok(bindings) => {
            let _written = bindings.write_to_file(output_path);
        }
        Err(error) => println!("cargo:warning=failed to generate cbindgen header: {error}"),
    }
}

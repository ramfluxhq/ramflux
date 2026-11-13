// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[path = "src/c_abi/v2/method_policy.rs"]
mod method_policy;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        return Ok(());
    }

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = manifest_dir.join("../..");
    let target_root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || workspace_root.join("target"),
        |value| {
            let path = std::path::PathBuf::from(value);
            if path.is_absolute() { path } else { workspace_root.join(path) }
        },
    );
    let target_dir = target_root.join("include");
    std::fs::create_dir_all(&target_dir)?;
    let config = cbindgen::Config::from_file(manifest_dir.join("cbindgen.toml"))?;
    let bindings =
        cbindgen::Builder::new().with_crate(&manifest_dir).with_config(config).generate()?;
    let mut header = Vec::new();
    bindings.write(&mut header);
    std::fs::write(target_dir.join("ramflux_sdk.h"), header)?;
    let mut policy = serde_json::to_vec_pretty(&method_policy::manifest())?;
    policy.push(b'\n');
    std::fs::write(target_dir.join("ramflux_sdk_methods.json"), policy)?;
    Ok(())
}

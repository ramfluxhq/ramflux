// SPDX-License-Identifier: BSD-3-Clause
#[path = "src/engine_compiler.rs"]
mod engine_compiler;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=src/bootstrap.js");
    println!("cargo:rerun-if-changed=src/engine_compiler.rs");
    let out = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or("missing build output directory")?,
    );
    std::fs::write(
        out.join("bootstrap.qjb"),
        engine_compiler::compile(include_bytes!("src/bootstrap.js"), "rf-host-bootstrap")?,
    )?;
    Ok(())
}

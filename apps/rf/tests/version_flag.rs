// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf --version` reports the shared product version and the build commit.

use std::process::Command;

#[test]
fn version_flag_prints_product_version_and_commit() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_rf")).arg("--version").output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    let expected = format!("ramflux {} (", env!("CARGO_PKG_VERSION"));
    assert!(text.starts_with(&expected), "unexpected --version output: {text}");
    assert!(text.trim_end().ends_with(')'));
    Ok(())
}

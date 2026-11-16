// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Embeds the 12-character git commit of the build as `RAMFLUX_GIT_SHA`.
//!
//! `RAMFLUX_GIT_SHA` in the build environment wins (it must be lowercase hex, at least 12
//! characters, else the build fails), so a source copy without `.git` (QA sync, release
//! tarball) can still carry the real commit. Without either the value is `unknown`.

mod build_sha;

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RAMFLUX_GIT_SHA");
    let override_value = std::env::var("RAMFLUX_GIT_SHA").ok();
    let head = git(&["rev-parse", "HEAD"]);
    // A bad override stops the build; its text is never printed or published.
    let sha = match build_sha::resolve(override_value.as_deref(), head.as_deref()) {
        Ok(sha) => sha,
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    };
    println!("cargo:rustc-env=RAMFLUX_GIT_SHA={sha}");
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"])
            && let Some(common) = git(&["rev-parse", "--git-common-dir"])
        {
            println!("cargo:rerun-if-changed={common}/{head_ref}");
        }
    }
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Embeds the 12-character git commit of the build as `RAMFLUX_GIT_SHA`.
//!
//! `RAMFLUX_GIT_SHA` in the build environment wins, so a source copy without `.git`
//! (QA sync, release tarball) can still carry the real commit. Without either the
//! value is `unknown`.

use std::process::Command;

const SHA_LEN: usize = 12;

fn main() {
    println!("cargo:rerun-if-env-changed=RAMFLUX_GIT_SHA");
    let sha = std::env::var("RAMFLUX_GIT_SHA")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(git_sha)
        .map_or_else(|| "unknown".to_owned(), |value| value.chars().take(SHA_LEN).collect());
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

fn git_sha() -> Option<String> {
    git(&["rev-parse", "HEAD"])
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

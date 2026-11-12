// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-tree guards for the message schema v1 activation. An attested precondition that the
//! tree contradicts fails here; the compile-time guard in the protocol crate then keeps the
//! generation from flipping without the attestation.
use ramflux_protocol::schema_activation as activation;
use ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION;
use std::path::Path;

const PENDING_CONTROL: &str = concat!("generated native control executor is not yet ", "activated");
const SELECTION_BRANCHES: [&str; 2] =
    [concat!("schema_v1_", "selected()"), concat!("schema_v1_", "live()")];

fn collect(dir: &Path, found: &mut Vec<(String, String)>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, found)?;
            continue;
        }
        let name = path.to_string_lossy().into_owned();
        let test_file = name.ends_with("tests.rs")
            || name.contains("/tests/")
            || name.contains("/runtime_tests/")
            || name.ends_with("/testing.rs");
        // The selector definition itself is deleted by the removal, not scanned as a caller.
        if !name.ends_with(".rs") || test_file || name.ends_with("client/target_selection.rs") {
            continue;
        }
        found.push((name, std::fs::read_to_string(&path)?));
    }
    Ok(())
}

fn offenders(markers: &[&str]) -> std::io::Result<Vec<String>> {
    let mut sources = Vec::new();
    collect(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut sources)?;
    Ok(sources
        .into_iter()
        .filter(|(_, source)| {
            // Inline test modules may keep the thread-local test gate.
            let production = source.split("#[cfg(test)]").next().unwrap_or_default();
            markers.iter().any(|marker| production.contains(marker))
        })
        .map(|(name, _)| name)
        .collect())
}

#[test]
fn attested_native_controls_leave_no_pending_fallthrough() -> std::io::Result<()> {
    if activation::is_met(activation::NATIVE_CONTROLS_COMPLETE) {
        assert_eq!(offenders(&[PENDING_CONTROL])?, Vec::<String>::new());
    }
    Ok(())
}

#[test]
fn attested_codec_removal_leaves_no_generation_branch() -> std::io::Result<()> {
    if activation::is_met(activation::LEGACY_CODEC_REMOVED) {
        assert_eq!(offenders(&SELECTION_BRANCHES)?, Vec::<String>::new());
    }
    Ok(())
}

#[test]
fn scanner_finds_the_generation_branches_of_the_dormant_tree() -> std::io::Result<()> {
    // Calibration: while the old codec is present the scanner must see its selection branches.
    if !activation::is_met(activation::LEGACY_CODEC_REMOVED) {
        assert!(!offenders(&SELECTION_BRANCHES)?.is_empty(), "scanner matched nothing");
    }
    Ok(())
}

#[test]
fn generation_flip_requires_every_attested_precondition() {
    assert!(activation::activation_allowed(ACTIVE_STORAGE_GENERATION, &activation::PRECONDITIONS));
    if ACTIVE_STORAGE_GENERATION != 0 {
        for row in activation::PRECONDITIONS {
            assert!(row.met, "{} is unmet on a live generation", row.name);
        }
    }
}

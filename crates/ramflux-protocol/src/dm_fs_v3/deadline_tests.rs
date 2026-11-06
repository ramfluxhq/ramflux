// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::deadline::deadline_ceiling;
use super::{BootstrapMode, DeadlineError, DeadlineInputs, validate_bootstrap_deadline};
use serde_json::Value;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
const WIRE: &str = include_str!("../../fixtures/dm_fs_v3/wire_vectors.json");
fn value(v: &Value, name: &str) -> std::result::Result<u64, Box<dyn std::error::Error>> {
    v[name].as_u64().ok_or_else(|| "integer".into())
}
fn ordinary(mode: BootstrapMode) -> DeadlineInputs {
    DeadlineInputs {
        mode,
        now: 1_001_009,
        deadline: 1_001_010,
        ttl: 1000,
        spk_validity_seconds: 1_209_600,
        leased_at: 1_000_010,
        issued_at: 1_000_010,
        spk_expires_at: 2_209_600,
        envelope_created_at: 1_000_010,
    }
}
#[test]
fn dm_fs_v3_deadline_boundaries() -> Result {
    let w: Value = serde_json::from_str(WIRE)?;
    let cases = w["deadlines"].as_array().ok_or("deadlines")?;
    assert_eq!(cases.len(), 28);
    for v in cases {
        let i = &v["input"];
        let mode = match i["mode"].as_str() {
            Some("opk") => BootstrapMode::Opk,
            Some("spk_only") => BootstrapMode::SpkOnly,
            _ => return Err("mode".into()),
        };
        let input = DeadlineInputs {
            mode,
            now: value(i, "now")?,
            deadline: value(i, "deadline")?,
            ttl: value(i, "ttl")?,
            spk_validity_seconds: value(i, "validity")?,
            leased_at: value(i, "leased_at")?,
            issued_at: value(i, "issued_at")?,
            spk_expires_at: value(i, "spk_expires_at")?,
            envelope_created_at: value(i, "created_at")?,
        };
        let name = v["name"].as_str().ok_or("case name")?;
        let suffix = name
            .strip_prefix("opk_")
            .or_else(|| name.strip_prefix("spk_only_"))
            .ok_or("mode prefix")?;
        let expected = match suffix {
            "D-1" | "ttl_T" | "future_S" | "other_start_does_not_limit" => Ok(()),
            "D" | "D+1" => Err(DeadlineError::Expired),
            "ttl_T+1" | "validity_2T+1" => Err(DeadlineError::Policy),
            "future_S+1" => Err(DeadlineError::FutureLease),
            "overflow" => Err(DeadlineError::Overflow),
            "envelope_min" | "spk_min" | "start_min" | "start_limit_different_times" => {
                Err(DeadlineError::ExceedsBound)
            }
            _ => return Err("unowned deadline vector outcome".into()),
        };
        assert_eq!(expected.is_ok(), v["accepted"].as_bool().ok_or("expected")?);
        assert_eq!(validate_bootstrap_deadline(&input), expected, "{name}");
    }
    // Every bound term overflows independently; no min or skew can hide overflow.
    for mode in [BootstrapMode::Opk, BootstrapMode::SpkOnly] {
        let base = ordinary(mode);
        assert_eq!(deadline_ceiling(&base)?, base.deadline);
        let mut bad = base;
        bad.spk_expires_at = u64::MAX;
        assert_eq!(validate_bootstrap_deadline(&bad), Err(DeadlineError::Overflow));
        bad = base;
        bad.envelope_created_at = u64::MAX;
        assert_eq!(validate_bootstrap_deadline(&bad), Err(DeadlineError::Overflow));
        bad = base;
        bad.now = u64::MAX;
        assert_eq!(validate_bootstrap_deadline(&bad), Err(DeadlineError::Overflow));
        bad = base;
        bad.issued_at = u64::MAX;
        bad.leased_at = u64::MAX - 100;
        bad.now = u64::MAX - 300;
        assert_eq!(validate_bootstrap_deadline(&bad), Err(DeadlineError::Overflow));
        // One second of skew never grants a second of deadline validity.
        bad = base;
        bad.now = base.deadline;
        assert_eq!(validate_bootstrap_deadline(&bad), Err(DeadlineError::Expired));
        assert!(
            validate_bootstrap_deadline(&DeadlineInputs { now: base.deadline + 1, ..base })
                .is_err()
        );
    }
    Ok(())
}

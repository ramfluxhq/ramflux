// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Strict settings parsing, removed-key diagnostics and complete bootstrap tuples.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn pools(values: &[(&str, &str)]) -> Result<CustodyPoolSettings, NodeCoreError> {
    CustodyPoolSettings::from_values(|key| {
        Ok(values.iter().find(|(name, _)| *name == key).map_or("", |(_, value)| *value).to_owned())
    })
}
#[test]
fn default_pools_have_no_authenticated_ceiling() -> TestResult {
    let settings = pools(&[])?;
    assert_eq!(settings.authenticated, None);
    assert_eq!(settings.handshakes, 256);
    assert_eq!(settings.preauth_per_source, 4);
    assert!(settings.limiter().authenticated_limit.is_none());
    Ok(())
}
#[test]
fn invalid_pool_settings_are_refused() {
    for (name, max) in [
        ("RAMFLUX_CUSTODY_HANDSHAKE_POOL", 65_536),
        ("RAMFLUX_CUSTODY_AUTHENTICATED_POOL", 1_048_576),
        ("RAMFLUX_CUSTODY_PREAUTH_HANDSHAKES_PER_SOURCE", 4096),
        ("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS", 10_000),
    ] {
        for invalid in
            ["0".to_owned(), (max + 1).to_string(), "-1".into(), "abc".into(), " ".into()]
        {
            let error = pools(&[(name, &invalid)]).err().map(|error| error.to_string());
            assert!(error.is_some_and(|error| error.contains(name)), "{name}={invalid}");
        }
        assert!(pools(&[(name, &max.to_string())]).is_ok());
    }
}
#[test]
fn settings_old_names_start_and_warn_once() -> TestResult {
    if crate::custody_budget_log::tests::run_isolated()? {
        return Ok(());
    }
    let (result, lines) =
        crate::custody_budget_log::tests::capture_warnings(|| -> Result<_, NodeCoreError> {
            let values = [
                ("RAMFLUX_CUSTODY_AUTHENTICATED_POOL", "512"),
                ("RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL", "4"),
            ];
            let settings = pools(&values)?;
            pools(&values)?;
            Ok(settings)
        });
    assert_eq!(result?.authenticated, Some(512));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("ignored: authenticated sessions are not capped per principal"));
    assert!(lines[0].contains("RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL"));
    Ok(())
}
#[test]
fn settings_issuance_ranges_and_ordering_are_strict() {
    for name in [
        "RAMFLUX_CUSTODY_CHALLENGES_PER_IP_PER_MINUTE",
        "RAMFLUX_CUSTODY_CHALLENGES_PER_PREFIX_PER_MINUTE",
        "RAMFLUX_CUSTODY_CHALLENGES_PER_NODE_PER_MINUTE",
    ] {
        for invalid in ["0", "65537", "-1", "abc", " "] {
            let result = CustodyIssuanceSettings::from_values(|key| {
                Ok(if key == name { invalid } else { "" }.to_owned())
            });
            assert!(result.err().is_some_and(|error| error.to_string().contains(name)));
        }
    }
    assert!(CustodyIssuanceSettings::new(1, 1, 1).is_ok());
    assert!(CustodyIssuanceSettings::new(65_536, 65_536, 65_536).is_ok());
    assert!(CustodyIssuanceSettings::new(16, 32, 31).is_err());
}
#[test]
fn issuance_tuple_ordering_and_fast_bootstrap() -> TestResult {
    let invalid = CustodyIssuanceSettings::new(128, 32, 1024)
        .err()
        .ok_or("accepted unordered tuple")?
        .to_string();
    assert!(invalid.contains("RAMFLUX_CUSTODY_CHALLENGES_PER_PREFIX_PER_MINUTE"));
    let settings = CustodyIssuanceSettings::new(128, 128, 1024)?;
    for ip in ["192.0.2.1", "2001:db8:1:2::1"] {
        let tick = std::time::Instant::now();
        let mut source = crate::custody_ingress::CustodySourceBudget::with_settings(settings);
        for _ in 0..20 * 3 {
            source.admit(ip.parse()?, tick)?;
        }
    }
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Service environment input: only explicitly optional tuning may ignore Compose expressions.
use std::{
    collections::BTreeSet,
    env::VarError,
    ffi::OsString,
    str::FromStr,
    sync::{Mutex, OnceLock},
};

/// Optional non-security tuning whose unexpanded Compose values may select defaults.
/// Every other unexpanded service setting is a startup error, including optional secret paths.
pub const OPTIONAL_EXPRESSION_KEYS: &[&str] = &[
    "RAMFLUX_FEDERATION_SPOOL_TTL_SECONDS",
    "RAMFLUX_GATEWAY_RESUME_WINDOW_SECONDS",
    "RAMFLUX_ITEST_GATEWAY_FRAME_DELAY_MS",
    "RAMFLUX_ITEST_PERF",
    "RAMFLUX_MESH_HTTP_MAX_IDLE_PER_PEER",
    "RAMFLUX_NOTIFY_BENCH",
    "RAMFLUX_NOTIFY_RUNTIME",
    "RAMFLUX_FEDERATION_MESH_RUNTIME",
    "RAMFLUX_NOTIFY_MESH_INGRESS_RUNTIME",
    "RAMFLUX_RELAY_GC_SWEEP_INTERVAL_SECONDS",
    "RAMFLUX_RELAY_INGRESS_THREADS",
    "RAMFLUX_RELAY_METADATA_MAX_BYTES",
    "RAMFLUX_RELAY_REDB_CACHE_BYTES",
    "RAMFLUX_RETENTION_GC_SWEEP_INTERVAL_SECONDS",
    "RAMFLUX_ROUTER_INGRESS_THREADS",
    "RAMFLUX_ROUTER_WAL_BENCH",
];

/// Reject unresolved non-optional input without exposing its value.
/// # Errors
/// Returns only the setting name for an unresolved value outside the optional allowlist.
pub fn validate_input(name: &str, value: &std::ffi::OsStr) -> Result<(), String> {
    if value.as_encoded_bytes().windows(2).any(|pair| pair == b"${")
        && !OPTIONAL_EXPRESSION_KEYS.contains(&name)
    {
        return Err(format!("unexpanded environment setting: {name}"));
    }
    Ok(())
}

/// Validate the startup environment before optional adapters can hide security inputs.
/// # Errors
/// Rejects unresolved service settings outside the explicit non-security allowlist.
pub fn validate_service_environment() -> Result<(), String> {
    for (name, value) in std::env::vars_os() {
        if let Some(name) = name.to_str()
            && name.starts_with("RAMFLUX_")
        {
            validate_input(name, &value)?;
        }
    }
    Ok(())
}

/// Read an environment variable, ignoring unresolved expressions only for optional tuning.
/// Empty strings retain their meaning, including explicitly disabling an optional listener.
/// # Errors
/// Returns standard absent/non-Unicode errors; an optional expression is treated as absent.
pub fn var(name: &str) -> Result<String, VarError> {
    var_os(name).ok_or(VarError::NotPresent)?.into_string().map_err(|value| {
        warn_invalid(name);
        VarError::NotUnicode(value)
    })
}

/// Read an OS value; non-optional expressions are retained for fail-closed startup validation.
#[must_use]
pub fn var_os(name: &str) -> Option<OsString> {
    configured_os_value(name, std::env::var_os(name))
}

fn configured_os_value(name: &str, value: Option<OsString>) -> Option<OsString> {
    let value = value?;
    if OPTIONAL_EXPRESSION_KEYS.contains(&name)
        && value.as_encoded_bytes().windows(2).any(|pair| pair == b"${")
    {
        warn_invalid(name);
        None
    } else {
        Some(value)
    }
}

/// Apply the optional tuning allowlist to a configuration adapter value.
#[must_use]
pub fn configured_value<'a>(name: &str, value: Option<&'a str>) -> Option<&'a str> {
    let value = value?;
    if OPTIONAL_EXPRESSION_KEYS.contains(&name) && value.contains("${") {
        warn_invalid(name);
        None
    } else {
        Some(value)
    }
}

/// Parse an optional setting. Missing, empty and malformed values select the caller's default.
#[must_use]
pub fn parsed<T: FromStr>(name: &str) -> Option<T> {
    parse_value(name, var(name).ok().as_deref())
}

/// Parse configuration input without changing valid values or returning invalid input in an error.
#[must_use]
pub fn parse_value<T: FromStr>(name: &str, value: Option<&str>) -> Option<T> {
    let value = configured_value(name, value)?;
    if value.is_empty() {
        return None;
    }
    value.parse().map_or_else(
        |_| {
            warn_invalid(name);
            None
        },
        Some,
    )
}

/// Choose a supported runtime or mode; absent, empty and unsupported settings use the default.
#[must_use]
pub fn choice<'a>(
    name: &str,
    value: Option<&str>,
    allowed: &[&'a str],
    default: &'a str,
) -> &'a str {
    let Some(value) = configured_value(name, value).filter(|value| !value.is_empty()) else {
        return default;
    };
    if let Some(selected) = allowed.iter().find(|candidate| **candidate == value) {
        return selected;
    }
    warn_invalid(name);
    default
}

/// Warn once per setting, never including its value (which may be a secret).
pub fn warn_invalid(name: &str) {
    static WARNED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let warn = WARNED
        .get_or_init(Mutex::default)
        .lock()
        .is_ok_and(|mut names| names.len() < 128 && names.insert(name.to_owned()));
    if warn {
        tracing::warn!(
            setting = name,
            "invalid or unexpanded environment setting; treating it as not configured"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expressions_are_absent_even_inside_paths_and_values_are_never_interpolated() {
        for value in
            ["${SETTING:-}", "${SETTING:-default}", "/run/${SETTING}/key", "prefix${SETTING}"]
        {
            assert_eq!(configured_value("RAMFLUX_RELAY_METADATA_MAX_BYTES", Some(value)), None);
            assert_eq!(
                configured_os_value(
                    "RAMFLUX_RELAY_METADATA_MAX_BYTES",
                    Some(OsString::from(value))
                ),
                None
            );
        }
        assert_eq!(configured_value("RAMFLUX_RELAY_METADATA_MAX_BYTES", None), None);
        assert_eq!(configured_os_value("RAMFLUX_RELAY_METADATA_MAX_BYTES", None), None);
    }

    #[test]
    fn unresolved_security_paths_and_unknown_settings_are_rejected_without_the_value() {
        for key in [
            "RAMFLUX_NODE_PRIVACY_KEY_FILE",
            "RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE",
            "RAMFLUX_GATEWAY_V3_ISSUER_CERT_FILE",
            "RAMFLUX_FEDERATION_TRUST_SNAPSHOT_FILE",
            "RAMFLUX_NEW_SECRET_FILE",
        ] {
            let value = "/private/${DO_NOT_LOG}/key";
            let error = validate_input(key, value.as_ref()).err();
            assert_eq!(error, Some(format!("unexpanded environment setting: {key}")));
            assert_eq!(configured_value(key, Some(value)), Some(value));
        }
        for key in OPTIONAL_EXPRESSION_KEYS {
            assert!(validate_input(key, "${OPTIONAL}".as_ref()).is_ok());
            assert_eq!(configured_value(key, Some("${OPTIONAL}")), None);
        }
    }

    #[test]
    fn empty_disabled_and_concrete_configuration_keep_their_original_values() {
        for value in ["", "0", "off", "example.test:443", "/run/secrets/key", " value ", "$literal"]
        {
            assert_eq!(
                configured_value("RAMFLUX_RELAY_METADATA_MAX_BYTES", Some(value)),
                Some(value)
            );
            assert_eq!(
                configured_os_value("RAMFLUX_RELAY_METADATA_MAX_BYTES", Some(value.into())),
                Some(value.into())
            );
        }
    }

    #[test]
    fn malformed_numeric_configuration_selects_no_override_but_zero_remains_valid() {
        for value in
            [None, Some(""), Some("${SETTING:-12}"), Some("invalid"), Some("18446744073709551616")]
        {
            assert_eq!(parse_value::<u64>("RAMFLUX_RELAY_METADATA_MAX_BYTES", value), None);
        }
        assert_eq!(parse_value::<u64>("RAMFLUX_RELAY_METADATA_MAX_BYTES", Some("0")), Some(0));
        assert_eq!(parse_value::<u64>("RAMFLUX_RELAY_METADATA_MAX_BYTES", Some("12")), Some(12));
    }

    #[test]
    fn unexpanded_and_unsupported_runtime_settings_keep_the_default_without_hiding_valid_modes() {
        for value in [None, Some(""), Some("${RUNTIME:-compio}"), Some("unsupported")] {
            assert_eq!(
                choice("RAMFLUX_NOTIFY_RUNTIME", value, &["tokio", "compio"], "tokio"),
                "tokio"
            );
        }
        assert_eq!(
            choice("RAMFLUX_NOTIFY_RUNTIME", Some("compio"), &["tokio", "compio"], "tokio"),
            "compio"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_paths_are_preserved_but_cannot_hide_an_expression() {
        use std::os::unix::ffi::OsStringExt;
        let path = OsString::from_vec(b"/run/\xff/key".to_vec());
        assert_eq!(
            configured_os_value("RAMFLUX_RELAY_METADATA_MAX_BYTES", Some(path.clone())),
            Some(path)
        );
        assert_eq!(
            configured_os_value(
                "RAMFLUX_RELAY_METADATA_MAX_BYTES",
                Some(OsString::from_vec(b"\xff/${SETTING}/key".to_vec()))
            ),
            None
        );
    }
}

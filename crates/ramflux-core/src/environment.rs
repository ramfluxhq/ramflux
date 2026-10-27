// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Service environment input, with unexpanded Compose expressions treated as absent.
use std::{
    collections::BTreeSet,
    env::VarError,
    ffi::OsString,
    str::FromStr,
    sync::{Mutex, OnceLock},
};

/// Read an environment variable without accepting an unexpanded Compose expression.
/// Empty strings retain their meaning, including explicitly disabling an optional listener.
/// # Errors
/// Returns the standard absent/non-Unicode errors, including absence for an expression.
pub fn var(name: &str) -> Result<String, VarError> {
    var_os(name).ok_or(VarError::NotPresent)?.into_string().map_err(|value| {
        warn_invalid(name);
        VarError::NotUnicode(value)
    })
}

/// Read a path or other OS value; valid non-Unicode paths are preserved.
#[must_use]
pub fn var_os(name: &str) -> Option<OsString> {
    configured_os_value(name, std::env::var_os(name))
}

fn configured_os_value(name: &str, value: Option<OsString>) -> Option<OsString> {
    let value = value?;
    if value.as_encoded_bytes().windows(2).any(|pair| pair == b"${") {
        warn_invalid(name);
        None
    } else {
        Some(value)
    }
}

/// Apply the same expression check to a value supplied by a configuration adapter.
#[must_use]
pub fn configured_value<'a>(name: &str, value: Option<&'a str>) -> Option<&'a str> {
    let value = value?;
    if value.contains("${") {
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
            assert_eq!(configured_value("SETTING", Some(value)), None);
            assert_eq!(configured_os_value("SETTING", Some(OsString::from(value))), None);
        }
        assert_eq!(configured_value("SETTING", None), None);
        assert_eq!(configured_os_value("SETTING", None), None);
    }

    #[test]
    fn empty_disabled_and_concrete_configuration_keep_their_original_values() {
        for value in ["", "0", "off", "example.test:443", "/run/secrets/key", " value ", "$literal"]
        {
            assert_eq!(configured_value("SETTING", Some(value)), Some(value));
            assert_eq!(configured_os_value("SETTING", Some(value.into())), Some(value.into()));
        }
    }

    #[test]
    fn malformed_numeric_configuration_selects_no_override_but_zero_remains_valid() {
        for value in
            [None, Some(""), Some("${SETTING:-12}"), Some("invalid"), Some("18446744073709551616")]
        {
            assert_eq!(parse_value::<u64>("SETTING", value), None);
        }
        assert_eq!(parse_value::<u64>("SETTING", Some("0")), Some(0));
        assert_eq!(parse_value::<u64>("SETTING", Some("12")), Some(12));
    }

    #[test]
    fn unexpanded_and_unsupported_runtime_settings_keep_the_default_without_hiding_valid_modes() {
        for value in [None, Some(""), Some("${RUNTIME:-compio}"), Some("unsupported")] {
            assert_eq!(choice("RUNTIME", value, &["tokio", "compio"], "tokio"), "tokio");
        }
        assert_eq!(choice("RUNTIME", Some("compio"), &["tokio", "compio"], "tokio"), "compio");
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_paths_are_preserved_but_cannot_hide_an_expression() {
        use std::os::unix::ffi::OsStringExt;
        let path = OsString::from_vec(b"/run/\xff/key".to_vec());
        assert_eq!(configured_os_value("SETTING", Some(path.clone())), Some(path));
        assert_eq!(
            configured_os_value(
                "SETTING",
                Some(OsString::from_vec(b"\xff/${SETTING}/key".to_vec()))
            ),
            None
        );
    }
}

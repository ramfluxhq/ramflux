// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private device label normalization. The public device chain does not carry these fields.
use serde::{Deserialize, Serialize};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use crate::ProtocolError;
use crate::text_safety::is_bidi_control;

/// UTF-8 byte cap after NFC. Controls and bidi overrides are stripped before the check.
pub const MAX_LABEL_BYTES: usize = 64;
/// Canonical signed record carried inside `OwnDeviceLabel`.
pub const SIGNED_SCHEMA: &str = "ramflux.device_label.signed.v1";
/// Body schema covered by the setting device's branch signature.
pub const BODY_SCHEMA: &str = "ramflux.device_label.v1";
/// Largest canonical signed record, in bytes.
pub const MAX_SIGNED_RECORD_BYTES: usize = 1024;
/// Branch `not_before` is unix seconds. The bus reports milliseconds.
#[must_use]
pub fn linked_at_ms(not_before_unix_seconds: u64) -> Option<u64> {
    if not_before_unix_seconds == 0 { None } else { not_before_unix_seconds.checked_mul(1_000) }
}

/// Closed platform set supplied by the client at enrolment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    Ios,
    Android,
    Macos,
    Linux,
    Windows,
    Cli,
}

impl DevicePlatform {
    /// Wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Cli => "cli",
        }
    }

    /// # Errors
    /// Rejects any spelling other than [`Self::as_str`].
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        match value {
            "ios" => Ok(Self::Ios),
            "android" => Ok(Self::Android),
            "macos" => Ok(Self::Macos),
            "linux" => Ok(Self::Linux),
            "windows" => Ok(Self::Windows),
            "cli" => Ok(Self::Cli),
            _ => Err(ProtocolError::InvalidDeviceLabel),
        }
    }
}

/// Strip controls and bidi overrides, then NFC. The result is the only signable form.
/// # Errors
/// Empty after stripping, or longer than [`MAX_LABEL_BYTES`] UTF-8 bytes.
pub fn normalize_label(value: &str) -> Result<String, ProtocolError> {
    let stripped: String = value
        .chars()
        .filter(|ch| get_general_category(*ch) != GeneralCategory::Control && !is_bidi_control(*ch))
        .collect();
    let name: String = stripped.nfc().collect();
    if name.is_empty() || name.len() > MAX_LABEL_BYTES {
        return Err(ProtocolError::InvalidDeviceLabel);
    }
    Ok(name)
}

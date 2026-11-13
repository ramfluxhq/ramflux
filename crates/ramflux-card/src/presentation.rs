// SPDX-License-Identifier: BSD-3-Clause
//! Host-owned locale and theme configuration, separate from peer card JSON.
use crate::CardError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const MAX_PRESENTATION: usize = 16 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub locale: String,
    pub direction: Direction,
    pub strings: BTreeMap<String, String>,
    pub tokens: BTreeMap<String, serde_json::Value>,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    Ltr,
    Rtl,
}
impl Presentation {
    /// Load the app-bundled launch catalogs; additional locales/themes use `parse`.
    /// # Errors
    /// Rejects unsupported bundled locale/theme names.
    pub fn bundled(locale: &str, dark: bool) -> Result<Self, CardError> {
        let strings = match locale {
            "en" => include_str!("../locales/en.json"),
            "zh-CN" => include_str!("../locales/zh-CN.json"),
            _ => return Err(CardError::Invalid("host locale")),
        };
        let tokens = if dark {
            include_str!("../themes/dark.json")
        } else {
            include_str!("../themes/light.json")
        };
        Ok(Self {
            locale: locale.into(),
            direction: Direction::Ltr,
            strings: serde_json::from_str(strings)?,
            tokens: serde_json::from_str(tokens)?,
        })
    }
    /// Parse independently supplied host configuration before allocating a VM.
    /// # Errors
    /// Rejects incomplete or oversized catalogs and invalid token values.
    pub fn parse(bytes: &[u8]) -> Result<Self, CardError> {
        crate::spec::preflight(bytes, MAX_PRESENTATION)?;
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<(), CardError> {
        let reference = Self::bundled("en", false)?;
        if self.locale.is_empty()
            || self.locale.len() > 35
            || !self.locale.bytes().all(|v| v.is_ascii_alphanumeric() || v == b'-')
            || self.strings.keys().ne(reference.strings.keys())
            || self.tokens.keys().ne(reference.tokens.keys())
            || self.strings.values().any(|v| v.is_empty() || v.len() > 1024)
            || serde_json::to_vec(&self.strings)?.len() > 8192
            || serde_json::to_vec(self)?.len() > MAX_PRESENTATION
        {
            return Err(CardError::Limit("host presentation"));
        }
        if self.tokens.get("gap").and_then(serde_json::Value::as_u64).is_none_or(|value| value > 64)
        {
            return Err(CardError::Invalid("theme geometry"));
        }
        for (key, value) in &self.tokens {
            let expected = reference.tokens.get(key).ok_or(CardError::Invalid("theme token"))?;
            let valid = if expected.is_number() {
                value.as_f64().is_some_and(|n| n.is_finite() && (0.0..=2048.0).contains(&n))
            } else if expected.as_str().is_some_and(|s| s.starts_with('#')) {
                value.as_str().is_some_and(color)
            } else {
                value.as_str().is_some_and(|s| {
                    !s.is_empty() && s.len() <= 256 && !s.contains([';', '{', '}', '(', ')'])
                })
            };
            if !valid {
                return Err(CardError::Invalid("theme token"));
            }
        }
        Ok(())
    }
    #[must_use]
    pub fn text(&self, key: &str) -> &str {
        self.strings.get(key).map_or("", String::as_str)
    }
    pub(crate) fn format(&self, key: &str, values: &[(&str, &str)]) -> String {
        let mut result = String::new();
        let mut rest = self.text(key);
        while let Some((prefix, tail)) = rest.split_once('{') {
            result.push_str(prefix);
            let Some((name, tail)) = tail.split_once('}') else {
                result.push('{');
                rest = tail;
                break;
            };
            if let Some((_, value)) = values.iter().find(|(key, _)| *key == name) {
                result.push_str(value);
            }
            rest = tail;
        }
        result.push_str(rest);
        result
    }
    pub(crate) fn owns_color(&self, value: &str) -> bool {
        self.tokens.values().any(|token| token.as_str() == Some(value))
    }
}
fn color(value: &str) -> bool {
    matches!(value.len(), 7 | 9)
        && value.starts_with('#')
        && value.bytes().skip(1).all(|v| v.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalogs_are_complete_bounded_and_peer_values_are_opaque() {
        for locale in ["en", "zh-CN"] {
            let value = Presentation::bundled(locale, false).expect("test: bundled locale");
            let encoded = serde_json::to_vec(&value).expect("test: configuration");
            Presentation::parse(&encoded).expect("test: complete validated configuration");
            assert!(
                value
                    .format("task_people", &[("requester", "{owner}"), ("owner", "Alice")])
                    .contains("{owner}"),
                "peer text cannot become a placeholder"
            );
            let mut invalid = value.clone();
            invalid.strings.remove("form_submit");
            assert!(
                matches!(invalid.validate(), Err(CardError::Limit("host presentation"))),
                "missing locale keys must be rejected"
            );
            let mut invalid = value;
            invalid.tokens.insert("text".into(), "red;display:none".into());
            assert!(
                matches!(invalid.validate(), Err(CardError::Invalid("theme token"))),
                "invalid token values must be rejected"
            );
        }
    }
    #[test]
    fn peer_json_cannot_select_host_presentation_or_legacy_form() {
        let input = include_str!("../fixtures/form.json");
        for property in ["\"theme\":\"dark\",", "\"host\":{},"] {
            assert!(
                crate::CardSpec::parse(input.replacen('{', &format!("{{{property}"), 1).as_bytes())
                    .is_err(),
                "peer JSON cannot select host presentation"
            );
        }
        let mut json: serde_json::Value = serde_json::from_str(input).expect("test: fixture");
        let form = json
            .get_mut("components")
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|v| v.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .expect("test: form object");
        form.insert("fields".into(), serde_json::json!([]));
        assert!(
            crate::CardSpec::parse(&serde_json::to_vec(&json).expect("test: empty form")).is_err(),
            "explicit fields must be nonempty"
        );
        let form = json
            .get_mut("components")
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|v| v.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .expect("test: form object");
        form.remove("fields");
        form.insert("label".into(), "Name".into());
        form.insert("binding".into(), "/name".into());
        assert!(
            crate::CardSpec::parse(&serde_json::to_vec(&json).expect("test: legacy specimen"))
                .is_err(),
            "single-field legacy spelling is rejected"
        );
    }
}

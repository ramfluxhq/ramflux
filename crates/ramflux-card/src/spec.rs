// SPDX-License-Identifier: BSD-3-Clause
use crate::CardError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_INPUT: usize = 16 * 1024;
pub(crate) const MAX_MODEL: usize = 4096;
pub(crate) const MAX_JSON_DEPTH: usize = 16;
pub(crate) const MAX_COMPONENTS: usize = 32;
const MAX_MODEL_FIELDS: usize = 32;

/// The first closed declarative catalog. No scripts, URLs or authority fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardSpec {
    pub catalog: String,
    pub components: Vec<Form>,
    #[serde(deserialize_with = "unique_model")]
    pub model: BTreeMap<String, String>,
}
/// A form owns exactly one local text binding and a declarative submit action.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Form {
    pub id: String,
    pub component: String,
    pub title: String,
    pub label: String,
    pub binding: String,
    pub submit: String,
}

/// Check raw byte/depth limits before deserialization allocates any values.
pub(crate) fn preflight(bytes: &[u8], max: usize) -> Result<(), CardError> {
    if bytes.len() > max {
        return Err(CardError::Limit("JSON bytes"));
    }
    let (mut depth, mut quoted, mut escaped) = (0_usize, false, false);
    for b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *b == b'\\' {
                escaped = true;
            } else if *b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_JSON_DEPTH {
                        return Err(CardError::Limit("JSON depth"));
                    }
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or(CardError::Invalid("JSON depth"))?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}
pub(crate) fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        && !matches!(s, "__proto__" | "prototype" | "constructor")
}
fn unique_model<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique string model keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if result.len() >= MAX_MODEL_FIELDS || result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate or excessive model keys"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Visitor)
}
impl CardSpec {
    /// Parse a bounded closed card, before constructing a VM.
    /// # Errors
    /// Rejects unknown fields, invalid bindings and all catalog/resource violations.
    pub fn parse(bytes: &[u8]) -> Result<Self, CardError> {
        preflight(bytes, MAX_INPUT)?;
        let spec: Self = serde_json::from_slice(bytes)?;
        spec.validate()?;
        Ok(spec)
    }
    pub(crate) fn validate(&self) -> Result<(), CardError> {
        if self.catalog != "rf-card/v1" {
            return Err(CardError::Invalid("catalog"));
        }
        if self.components.is_empty() || self.components.len() > MAX_COMPONENTS {
            return Err(CardError::Limit("components"));
        }
        if self.model.len() > MAX_MODEL_FIELDS
            || self.model.iter().any(|(k, v)| k.len() > 64 || v.len() > MAX_MODEL)
        {
            return Err(CardError::Limit("model fields"));
        }
        if serde_json::to_vec(&self.model)?.len() > MAX_MODEL {
            return Err(CardError::Limit("model"));
        }
        if self.model.keys().any(|s| !identifier(s)) {
            return Err(CardError::Invalid("model key"));
        }
        let (mut ids, mut bindings) = (BTreeSet::new(), BTreeSet::new());
        for form in &self.components {
            if form.component != "rf.form"
                || !identifier(&form.id)
                || !identifier(&form.submit)
                || form.title.len() > 256
                || form.label.len() > 256
                || !ids.insert(&form.id)
            {
                return Err(CardError::Invalid("form properties"));
            }
            let key = form.binding.strip_prefix('/').ok_or(CardError::Invalid("local binding"))?;
            if !identifier(key) || !self.model.contains_key(key) || !bindings.insert(key) {
                return Err(CardError::Invalid("binding ownership"));
            }
        }
        Ok(())
    }
    pub(crate) fn render_input(&self) -> Result<String, CardError> {
        let rows: Vec<_> = self.components.iter().map(|f| {
            let key = f.binding.strip_prefix('/').ok_or(CardError::Invalid("binding"))?;
            let value = self.model.get(key).ok_or(CardError::Invalid("binding value"))?;
            Ok(serde_json::json!({"id":f.id,"title":f.title,"label":f.label,"value":value,"submit":f.submit}))
        }).collect::<Result<_, CardError>>()?;
        Ok(serde_json::to_string(&rows)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_closed_props_and_limits() {
        let input = include_str!("../fixtures/form.json");
        assert!(
            CardSpec::parse(
                input.replace("\"name\":\"Ada\"", "\"name\":\"Ada\",\"name\":\"Eve\"").as_bytes()
            )
            .is_err(),
            "duplicate model keys must not have parser-dependent semantics"
        );
        assert!(
            CardSpec::parse(input.replace("rf.form", "rf.approval").as_bytes()).is_err(),
            "security chrome must not enter the catalog"
        );
        assert!(
            CardSpec::parse(input.replace("\"title\":", "\"script\":0,\"title\":").as_bytes())
                .is_err(),
            "unknown props must fail closed"
        );
        assert!(
            CardSpec::parse(input.replace("/name", "https://example.invalid/name").as_bytes())
                .is_err(),
            "bindings must stay local"
        );
        let mut spec = CardSpec::parse(input.as_bytes()).expect("test: valid fixture");
        spec.components = vec![spec.components[0].clone(); MAX_COMPONENTS + 1];
        assert!(spec.validate().is_err(), "component limit must reject before VM allocation");
        spec = CardSpec::parse(input.as_bytes()).expect("test: fixture");
        spec.model.insert("name".into(), "x".repeat(MAX_MODEL));
        assert!(spec.validate().is_err(), "model serialization must fit 4 KiB");
        assert!(
            preflight(&[b'['; MAX_JSON_DEPTH + 1], MAX_INPUT).is_err(),
            "depth preflight must stop recursive parsing"
        );
    }
}

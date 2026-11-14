// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonically escaped RFC 6901 pointers; streaming additionally forbids array traversal.
use super::Reject;
use serde_json::Value;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonPointer {
    segments: Vec<String>,
}
impl JsonPointer {
    /// Parse an absolute RFC 6901 pointer without accepting alternate escaping.
    /// # Errors
    /// Refuses malformed escapes and prototype property names.
    pub fn parse(path: &str) -> Result<Self, Reject> {
        if path.is_empty() {
            return Ok(Self { segments: Vec::new() });
        }
        let tail = path.strip_prefix('/').ok_or(Reject::Expression)?;
        let mut segments = Vec::new();
        for part in tail.split('/') {
            let mut chars = part.chars();
            let mut decoded = String::new();
            while let Some(c) = chars.next() {
                if c == '~' {
                    decoded.push(match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err(Reject::Expression),
                    });
                } else {
                    decoded.push(c);
                }
            }
            if matches!(decoded.as_str(), "__proto__" | "prototype" | "constructor") {
                return Err(Reject::Expression);
            }
            segments.push(decoded);
        }
        Ok(Self { segments })
    }
    #[must_use]
    pub fn canonical(&self) -> String {
        self.segments
            .iter()
            .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
            .collect()
    }
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.segments.starts_with(&other.segments) || other.segments.starts_with(&self.segments)
    }
    #[must_use]
    pub fn get<'a>(&self, value: &'a Value) -> Option<&'a Value> {
        let mut current = value;
        for part in &self.segments {
            current = match current {
                Value::Object(map) => map.get(part)?,
                Value::Array(array) => array.get(index(part).ok()?)?,
                _ => return None,
            };
        }
        Some(current)
    }
    /// An append/finality target must traverse only existing object members.
    /// # Errors
    /// Refuses arrays, the append marker, missing targets and non-string leaves.
    pub fn text<'a>(&self, model: &'a Value) -> Result<&'a str, Reject> {
        let mut current = model;
        if self.segments.is_empty()
            || self.segments.len() == 1 && self.segments.first().is_some_and(String::is_empty)
        {
            return Err(Reject::Expression);
        }
        for part in &self.segments {
            if part == "-" {
                return Err(Reject::Expression);
            }
            current = current.as_object().and_then(|m| m.get(part)).ok_or(Reject::Expression)?;
        }
        current.as_str().ok_or(Reject::Expression)
    }
    /// Pointer upsert with null deletion. Root `/` is the upstream root operation.
    /// # Errors
    /// Refuses invalid parents or array indices; never shifts a finalized stream.
    pub fn update(&self, model: &mut Value, value: Value) -> Result<(), Reject> {
        let Some((last, parents)) = self.segments.split_last() else {
            *model = value;
            return Ok(());
        };
        let mut current = model;
        for part in parents {
            current = match current {
                Value::Object(map) => {
                    map.entry(part).or_insert_with(|| Value::Object(Default::default()))
                }
                Value::Array(array) => array.get_mut(index(part)?).ok_or(Reject::Expression)?,
                _ => return Err(Reject::Expression),
            };
        }
        match current {
            Value::Object(map) => {
                if value.is_null() {
                    map.remove(last);
                } else {
                    map.insert(last.clone(), value);
                }
            }
            Value::Array(array) => {
                let i = index(last)?;
                if value.is_null() {
                    if i >= array.len() {
                        return Err(Reject::Expression);
                    }
                    array.remove(i);
                } else if i == array.len() {
                    array.push(value);
                } else {
                    *array.get_mut(i).ok_or(Reject::Expression)? = value;
                }
            }
            _ => return Err(Reject::Expression),
        }
        Ok(())
    }
}
fn index(part: &str) -> Result<usize, Reject> {
    if part.is_empty()
        || part.len() > 1 && part.starts_with('0')
        || !part.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Reject::Expression);
    }
    part.parse().map_err(|_| Reject::Expression)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn stream_targets_are_canonical_object_members_and_never_root_array_or_append_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let model = json!({"":"root alias","items":[{"text":"array member"}],"object":{"0":"object member","a/b":"slash","a~b":"tilde","-":"append marker"}});
        for path in ["", "/", "/items/0/text", "/object/-"] {
            assert!(
                JsonPointer::parse(path)?.text(&model).is_err(),
                "streaming must refuse ambiguous or non-object-only target {path:?}"
            );
        }
        for (path, text) in
            [("/object/0", "object member"), ("/object/a~1b", "slash"), ("/object/a~0b", "tilde")]
        {
            let pointer = JsonPointer::parse(path)?;
            assert_eq!(pointer.canonical(), path, "a finality key has one canonical escaping");
            assert_eq!(pointer.text(&model)?, text, "object-only pointers may have numeric keys");
        }
        for path in ["/object/a~2b", "/object/a~", "/constructor/x"] {
            assert!(
                JsonPointer::parse(path).is_err(),
                "invalid/prototype pointers must fail closed: {path}"
            );
        }
        assert!(
            !JsonPointer::parse("/a")?.overlaps(&JsonPointer::parse("/ab")?),
            "overlap is by decoded segments, not string prefix"
        );
        Ok(())
    }
}

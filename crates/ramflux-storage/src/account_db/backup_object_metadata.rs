// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read object identities while skipping key slots, prepared keys and payload buffers.
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

pub(super) fn references(bytes: &[u8]) -> Result<Vec<(String, Option<String>)>, serde_json::Error> {
    let mut found = Vec::new();
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Scan(&mut found).deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(found)
}
struct Scan<'a>(&'a mut Vec<(String, Option<String>)>);
impl<'de> DeserializeSeed<'de> for Scan<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Scan<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("object reference metadata")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        let mut wire = None;
        let mut manifest = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "object_id" | "manifest_hash" => {
                    let value = map.next_value::<Option<String>>()?;
                    if key == "object_id" {
                        wire = value;
                    } else {
                        manifest = value;
                    }
                }
                "object_key" | "prepared_slot" | "key_slot" | "ciphertext" | "nonce"
                | "access_grant" | "plaintext_base64" | "body_base64" | "encrypted_body" => {
                    map.next_value::<IgnoredAny>()?;
                }
                _ => map.next_value_seed(Scan(&mut *self.0))?,
            }
        }
        if let Some(wire) = wire {
            self.0.push((wire, manifest));
        }
        Ok(())
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<(), S::Error> {
        while sequence.next_element_seed(Scan(&mut *self.0))?.is_some() {}
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}

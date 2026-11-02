// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Discover history-container ownership without allocating copies of encoded payload buffers.
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct HistoryOwners {
    pub messages: BTreeSet<String>,
    pub objects: BTreeSet<(String, String)>,
}

pub(super) fn from_bytes(bytes: &[u8]) -> Result<HistoryOwners, serde_json::Error> {
    let mut owners = HistoryOwners::default();
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Scan(&mut owners).deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(owners)
}
struct Scan<'a>(&'a mut HistoryOwners);
impl<'de> DeserializeSeed<'de> for Scan<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Scan<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("history metadata")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        let mut wire = None;
        let mut manifest = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "message_id" | "own_copy_message_id" | "object_id" | "manifest_hash" => {
                    let value = map.next_value::<serde_json::Value>()?;
                    if let Some(value) = value.as_str() {
                        match key.as_str() {
                            "object_id" => wire = Some(value.to_owned()),
                            "manifest_hash" => manifest = Some(value.to_owned()),
                            _ => {
                                self.0.messages.insert(value.to_owned());
                            }
                        }
                    }
                }
                "encrypted_body"
                | "ciphertext"
                | "plaintext_base64"
                | "body_base64"
                | "contents"
                | "nonce"
                | "sender_key_distributions_base64" => {
                    map.next_value::<IgnoredAny>()?;
                }
                _ => map.next_value_seed(Scan(&mut *self.0))?,
            }
        }
        if let (Some(wire), Some(manifest)) = (wire, manifest) {
            self.0.objects.insert((wire, manifest));
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

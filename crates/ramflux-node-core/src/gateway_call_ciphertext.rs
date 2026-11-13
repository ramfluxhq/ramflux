// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded opaque invitation storage. The public ciphertext bytes do not change.

use serde::{
    Deserializer, Serializer,
    de::{Error, SeqAccess, Visitor},
};
const MAX_BYTES: usize = 32768;
const MAX_ENCODED: usize = 43691;

pub(super) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if value.len() > MAX_BYTES {
        return Err(serde::ser::Error::custom("call invitation exceeds 32KiB"));
    }
    serializer.serialize_str(&ramflux_protocol::encode_base64url(value))
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    struct Ciphertext;
    impl<'de> Visitor<'de> for Ciphertext {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded invitation bytes")
        }
        fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > MAX_ENCODED {
                return Err(E::custom("call invitation exceeds 32KiB"));
            }
            let bytes = ramflux_protocol::decode_base64url(value).map_err(E::custom)?;
            if bytes.len() > MAX_BYTES || ramflux_protocol::encode_base64url(&bytes) != value {
                return Err(E::custom("invalid invitation bytes"));
            }
            Ok(bytes)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut bytes = Vec::new();
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() >= MAX_BYTES {
                    return Err(A::Error::custom("call invitation exceeds 32KiB"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    decoder.deserialize_any(Ciphertext)
}

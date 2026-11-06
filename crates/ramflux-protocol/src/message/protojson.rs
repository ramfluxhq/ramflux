// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Strict `ProtoJSON` input through the generated serde implementations.

/// Decode a generated local request, preserving exact integers and field presence.
///
/// # Errors
/// Returns an error for malformed JSON, duplicate/alias fields, unknown fields or invalid values.
pub fn from_protojson<T: serde::de::DeserializeOwned>(input: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(input)
}

// Protobuf stores enum fields as i32 so future numeric values survive decoding.
// pbjson's default enum adapter converts to the closed Rust enum too early.
pub(crate) struct EnumValue<E> {
    pub(crate) value: i32,
    marker: std::marker::PhantomData<E>,
}

impl<E> EnumValue<E> {
    pub(crate) fn new(value: i32) -> Self {
        Self { value, marker: std::marker::PhantomData }
    }
}

impl<E: TryFrom<i32> + serde::Serialize> serde::Serialize for EnumValue<E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match E::try_from(self.value) {
            Ok(known) => known.serialize(serializer),
            Err(_) => serializer.serialize_i32(self.value),
        }
    }
}

impl<'de, E: serde::de::DeserializeOwned + Into<i32>> serde::Deserialize<'de> for EnumValue<E> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnumVisitor<E>(std::marker::PhantomData<E>);
        impl<E: serde::de::DeserializeOwned + Into<i32>> serde::de::Visitor<'_> for EnumVisitor<E> {
            type Value = EnumValue<E>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a protobuf enum name or i32 number")
            }
            fn visit_i64<Error: serde::de::Error>(self, value: i64) -> Result<Self::Value, Error> {
                i32::try_from(value).map(EnumValue::new).map_err(Error::custom)
            }
            fn visit_u64<Error: serde::de::Error>(self, value: u64) -> Result<Self::Value, Error> {
                i32::try_from(value).map(EnumValue::new).map_err(Error::custom)
            }
            fn visit_str<Error: serde::de::Error>(self, value: &str) -> Result<Self::Value, Error> {
                let known = E::deserialize(serde::de::value::StrDeserializer::<Error>::new(value))?;
                Ok(EnumValue::new(known.into()))
            }
        }
        deserializer.deserialize_any(EnumVisitor(std::marker::PhantomData))
    }
}

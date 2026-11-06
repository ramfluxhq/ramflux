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

/// Generated map deserialization must preserve duplicate detection before collect.
pub(crate) struct StrictMap<K, V>(std::collections::BTreeMap<K, V>);

impl<'de, K, V> serde::Deserialize<'de> for StrictMap<K, V>
where
    K: serde::Deserialize<'de> + Ord,
    V: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor<K, V>(std::marker::PhantomData<(K, V)>);
        impl<'de, K, V> serde::de::Visitor<'de> for MapVisitor<K, V>
        where
            K: serde::Deserialize<'de> + Ord,
            V: serde::Deserialize<'de>,
        {
            type Value = StrictMap<K, V>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a protobuf JSON map with unique keys")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut values = std::collections::BTreeMap::new();
                while let Some(key) = map.next_key::<K>()? {
                    match values.entry(key) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(map.next_value::<V>()?);
                        }
                        std::collections::btree_map::Entry::Occupied(_) => {
                            return Err(serde::de::Error::custom("duplicate ProtoJSON map key"));
                        }
                    }
                }
                Ok(StrictMap(values))
            }
        }
        deserializer.deserialize_map(MapVisitor(std::marker::PhantomData))
    }
}

impl<K, V> IntoIterator for StrictMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::collections::btree_map::IntoIter<K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

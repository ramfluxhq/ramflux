// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct CallActionRekey {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
    #[prost(string, tag = "2")]
    pub base_key: ::prost::alloc::string::String,
}
impl serde::Serialize for CallActionRekey {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.generation != 0 {
            len += 1;
        }
        if !self.base_key.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.CallActionRekey", len)?;
        if self.generation != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("generation", ToString::to_string(&self.generation).as_str())?;
        }
        if !self.base_key.is_empty() {
            struct_ser.serialize_field("baseKey", &self.base_key)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for CallActionRekey {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["generation", "base_key", "baseKey"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Generation,
            BaseKey,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;
                impl serde::de::Visitor<'_> for GeneratedVisitor {
                    type Value = GeneratedField;
                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }
                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "generation" => Ok(GeneratedField::Generation),
                            "baseKey" | "base_key" => Ok(GeneratedField::BaseKey),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = CallActionRekey;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.CallActionRekey")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<CallActionRekey, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut generation__ = None;
                let mut base_key__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Generation => {
                            if generation__.is_some() {
                                return Err(serde::de::Error::duplicate_field("generation"));
                            }
                            generation__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::BaseKey => {
                            if base_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("baseKey"));
                            }
                            base_key__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(CallActionRekey {
                    generation: generation__.unwrap_or_default(),
                    base_key: base_key__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.CallActionRekey",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

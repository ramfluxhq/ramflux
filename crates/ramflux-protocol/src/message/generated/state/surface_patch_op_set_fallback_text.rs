// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct SurfacePatchOpSetFallbackText {
    #[prost(string, tag = "1")]
    pub fallback_text: ::prost::alloc::string::String,
}
impl serde::Serialize for SurfacePatchOpSetFallbackText {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.fallback_text.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.SurfacePatchOpSetFallbackText", len)?;
        if !self.fallback_text.is_empty() {
            struct_ser.serialize_field("fallbackText", &self.fallback_text)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SurfacePatchOpSetFallbackText {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["fallback_text", "fallbackText"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            FallbackText,
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
                            "fallbackText" | "fallback_text" => Ok(GeneratedField::FallbackText),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SurfacePatchOpSetFallbackText;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SurfacePatchOpSetFallbackText")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<SurfacePatchOpSetFallbackText, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut fallback_text__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::FallbackText => {
                            if fallback_text__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fallbackText"));
                            }
                            fallback_text__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(SurfacePatchOpSetFallbackText {
                    fallback_text: fallback_text__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.SurfacePatchOpSetFallbackText",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

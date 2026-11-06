// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct StreamAppendCommand {
    #[prost(string, tag = "1")]
    pub surface_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub component_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub text_delta: ::prost::alloc::string::String,
    #[prost(bool, tag = "4")]
    pub r#final: bool,
}
impl serde::Serialize for StreamAppendCommand {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.surface_id.is_empty() {
            len += 1;
        }
        if !self.component_id.is_empty() {
            len += 1;
        }
        if !self.text_delta.is_empty() {
            len += 1;
        }
        if self.r#final {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.StreamAppendCommand", len)?;
        if !self.surface_id.is_empty() {
            struct_ser.serialize_field("surfaceId", &self.surface_id)?;
        }
        if !self.component_id.is_empty() {
            struct_ser.serialize_field("componentId", &self.component_id)?;
        }
        if !self.text_delta.is_empty() {
            struct_ser.serialize_field("textDelta", &self.text_delta)?;
        }
        if self.r#final {
            struct_ser.serialize_field("final", &self.r#final)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for StreamAppendCommand {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "surface_id",
            "surfaceId",
            "component_id",
            "componentId",
            "text_delta",
            "textDelta",
            "final_",
            "final",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            SurfaceId,
            ComponentId,
            TextDelta,
            Final,
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
                            "surfaceId" | "surface_id" => Ok(GeneratedField::SurfaceId),
                            "componentId" | "component_id" => Ok(GeneratedField::ComponentId),
                            "textDelta" | "text_delta" => Ok(GeneratedField::TextDelta),
                            "final" | "final_" => Ok(GeneratedField::Final),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = StreamAppendCommand;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.StreamAppendCommand")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<StreamAppendCommand, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut surface_id__ = None;
                let mut component_id__ = None;
                let mut text_delta__ = None;
                let mut r#final__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::SurfaceId => {
                            if surface_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("surfaceId"));
                            }
                            surface_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ComponentId => {
                            if component_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("componentId"));
                            }
                            component_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::TextDelta => {
                            if text_delta__.is_some() {
                                return Err(serde::de::Error::duplicate_field("textDelta"));
                            }
                            text_delta__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Final => {
                            if r#final__.is_some() {
                                return Err(serde::de::Error::duplicate_field("final"));
                            }
                            r#final__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(StreamAppendCommand {
                    surface_id: surface_id__.unwrap_or_default(),
                    component_id: component_id__.unwrap_or_default(),
                    text_delta: text_delta__.unwrap_or_default(),
                    r#final: r#final__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.StreamAppendCommand",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SurfaceHistoryExport {
    #[prost(message, repeated, tag = "1")]
    pub controls: ::prost::alloc::vec::Vec<SurfaceDelivery>,
    #[prost(message, repeated, tag = "2")]
    pub checkpoints: ::prost::alloc::vec::Vec<OwnedSurfaceCheckpoint>,
    #[prost(message, optional, tag = "3")]
    pub metadata: ::core::option::Option<SurfaceExportMetadata>,
}
impl serde::Serialize for SurfaceHistoryExport {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.controls.is_empty() {
            len += 1;
        }
        if !self.checkpoints.is_empty() {
            len += 1;
        }
        if self.metadata.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.SurfaceHistoryExport", len)?;
        if !self.controls.is_empty() {
            struct_ser.serialize_field("controls", &self.controls)?;
        }
        if !self.checkpoints.is_empty() {
            struct_ser.serialize_field("checkpoints", &self.checkpoints)?;
        }
        if let Some(v) = self.metadata.as_ref() {
            struct_ser.serialize_field("metadata", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SurfaceHistoryExport {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["controls", "checkpoints", "metadata"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Controls,
            Checkpoints,
            Metadata,
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
                            "controls" => Ok(GeneratedField::Controls),
                            "checkpoints" => Ok(GeneratedField::Checkpoints),
                            "metadata" => Ok(GeneratedField::Metadata),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SurfaceHistoryExport;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SurfaceHistoryExport")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<SurfaceHistoryExport, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut controls__ = None;
                let mut checkpoints__ = None;
                let mut metadata__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Controls => {
                            if controls__.is_some() {
                                return Err(serde::de::Error::duplicate_field("controls"));
                            }
                            controls__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Checkpoints => {
                            if checkpoints__.is_some() {
                                return Err(serde::de::Error::duplicate_field("checkpoints"));
                            }
                            checkpoints__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Metadata => {
                            if metadata__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            metadata__ = map_.next_value()?;
                        }
                    }
                }
                Ok(SurfaceHistoryExport {
                    controls: controls__.unwrap_or_default(),
                    checkpoints: checkpoints__.unwrap_or_default(),
                    metadata: metadata__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.SurfaceHistoryExport",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SurfaceSnapshotProof {
    #[prost(message, optional, tag = "1")]
    pub event: ::core::option::Option<SurfaceEvent>,
    #[prost(message, optional, tag = "2")]
    pub checkpoint: ::core::option::Option<SurfaceCheckpoint>,
    #[prost(string, optional, tag = "3")]
    pub surface_hash: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "4")]
    pub metadata: ::core::option::Option<SurfaceResyncMetadata>,
    #[prost(string, tag = "5")]
    pub author_device_id: ::prost::alloc::string::String,
}
impl serde::Serialize for SurfaceSnapshotProof {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.event.is_some() {
            len += 1;
        }
        if self.checkpoint.is_some() {
            len += 1;
        }
        if self.surface_hash.is_some() {
            len += 1;
        }
        if self.metadata.is_some() {
            len += 1;
        }
        if !self.author_device_id.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.SurfaceSnapshotProof", len)?;
        if let Some(v) = self.event.as_ref() {
            struct_ser.serialize_field("event", v)?;
        }
        if let Some(v) = self.checkpoint.as_ref() {
            struct_ser.serialize_field("checkpoint", v)?;
        }
        if let Some(v) = self.surface_hash.as_ref() {
            struct_ser.serialize_field("surfaceHash", v)?;
        }
        if let Some(v) = self.metadata.as_ref() {
            struct_ser.serialize_field("metadata", v)?;
        }
        if !self.author_device_id.is_empty() {
            struct_ser.serialize_field("authorDeviceId", &self.author_device_id)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SurfaceSnapshotProof {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "event",
            "checkpoint",
            "surface_hash",
            "surfaceHash",
            "metadata",
            "author_device_id",
            "authorDeviceId",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Event,
            Checkpoint,
            SurfaceHash,
            Metadata,
            AuthorDeviceId,
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
                            "event" => Ok(GeneratedField::Event),
                            "checkpoint" => Ok(GeneratedField::Checkpoint),
                            "surfaceHash" | "surface_hash" => Ok(GeneratedField::SurfaceHash),
                            "metadata" => Ok(GeneratedField::Metadata),
                            "authorDeviceId" | "author_device_id" => {
                                Ok(GeneratedField::AuthorDeviceId)
                            }
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SurfaceSnapshotProof;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SurfaceSnapshotProof")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<SurfaceSnapshotProof, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut event__ = None;
                let mut checkpoint__ = None;
                let mut surface_hash__ = None;
                let mut metadata__ = None;
                let mut author_device_id__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Event => {
                            if event__.is_some() {
                                return Err(serde::de::Error::duplicate_field("event"));
                            }
                            event__ = map_.next_value()?;
                        }
                        GeneratedField::Checkpoint => {
                            if checkpoint__.is_some() {
                                return Err(serde::de::Error::duplicate_field("checkpoint"));
                            }
                            checkpoint__ = map_.next_value()?;
                        }
                        GeneratedField::SurfaceHash => {
                            if surface_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("surfaceHash"));
                            }
                            surface_hash__ = map_.next_value()?;
                        }
                        GeneratedField::Metadata => {
                            if metadata__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            metadata__ = map_.next_value()?;
                        }
                        GeneratedField::AuthorDeviceId => {
                            if author_device_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("authorDeviceId"));
                            }
                            author_device_id__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(SurfaceSnapshotProof {
                    event: event__,
                    checkpoint: checkpoint__,
                    surface_hash: surface_hash__,
                    metadata: metadata__,
                    author_device_id: author_device_id__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.SurfaceSnapshotProof",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

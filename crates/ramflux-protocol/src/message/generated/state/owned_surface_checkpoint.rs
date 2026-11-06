// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OwnedSurfaceCheckpoint {
    #[prost(message, optional, tag = "1")]
    pub record: ::core::option::Option<StoredSurface>,
    #[prost(message, optional, tag = "2")]
    pub snapshot_event: ::core::option::Option<SurfaceEvent>,
    #[prost(uint64, tag = "3")]
    pub version: u64,
    #[prost(string, tag = "4")]
    pub surface_hash: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "5")]
    pub conversation: ::core::option::Option<JsonValue>,
    #[prost(uint64, optional, tag = "6")]
    pub group_epoch: ::core::option::Option<u64>,
}
impl serde::Serialize for OwnedSurfaceCheckpoint {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.record.is_some() {
            len += 1;
        }
        if self.snapshot_event.is_some() {
            len += 1;
        }
        if self.version != 0 {
            len += 1;
        }
        if !self.surface_hash.is_empty() {
            len += 1;
        }
        if self.conversation.is_some() {
            len += 1;
        }
        if self.group_epoch.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.OwnedSurfaceCheckpoint", len)?;
        if let Some(v) = self.record.as_ref() {
            struct_ser.serialize_field("record", v)?;
        }
        if let Some(v) = self.snapshot_event.as_ref() {
            struct_ser.serialize_field("snapshotEvent", v)?;
        }
        if self.version != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("version", ToString::to_string(&self.version).as_str())?;
        }
        if !self.surface_hash.is_empty() {
            struct_ser.serialize_field("surfaceHash", &self.surface_hash)?;
        }
        if let Some(v) = self.conversation.as_ref() {
            struct_ser.serialize_field("conversation", v)?;
        }
        if let Some(v) = self.group_epoch.as_ref() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("groupEpoch", ToString::to_string(&v).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for OwnedSurfaceCheckpoint {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "record",
            "snapshot_event",
            "snapshotEvent",
            "version",
            "surface_hash",
            "surfaceHash",
            "conversation",
            "group_epoch",
            "groupEpoch",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Record,
            SnapshotEvent,
            Version,
            SurfaceHash,
            Conversation,
            GroupEpoch,
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
                            "record" => Ok(GeneratedField::Record),
                            "snapshotEvent" | "snapshot_event" => Ok(GeneratedField::SnapshotEvent),
                            "version" => Ok(GeneratedField::Version),
                            "surfaceHash" | "surface_hash" => Ok(GeneratedField::SurfaceHash),
                            "conversation" => Ok(GeneratedField::Conversation),
                            "groupEpoch" | "group_epoch" => Ok(GeneratedField::GroupEpoch),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = OwnedSurfaceCheckpoint;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.OwnedSurfaceCheckpoint")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<OwnedSurfaceCheckpoint, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut record__ = None;
                let mut snapshot_event__ = None;
                let mut version__ = None;
                let mut surface_hash__ = None;
                let mut conversation__ = None;
                let mut group_epoch__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Record => {
                            if record__.is_some() {
                                return Err(serde::de::Error::duplicate_field("record"));
                            }
                            record__ = map_.next_value()?;
                        }
                        GeneratedField::SnapshotEvent => {
                            if snapshot_event__.is_some() {
                                return Err(serde::de::Error::duplicate_field("snapshotEvent"));
                            }
                            snapshot_event__ = map_.next_value()?;
                        }
                        GeneratedField::Version => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::SurfaceHash => {
                            if surface_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("surfaceHash"));
                            }
                            surface_hash__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Conversation => {
                            if conversation__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversation"));
                            }
                            conversation__ = map_.next_value()?;
                        }
                        GeneratedField::GroupEpoch => {
                            if group_epoch__.is_some() {
                                return Err(serde::de::Error::duplicate_field("groupEpoch"));
                            }
                            group_epoch__ = map_
                                .next_value::<
                                    ::std::option::Option<
                                        ::pbjson::private::NumberDeserialize<_>,
                                    >,
                                >()?
                                .map(|x| x.0);
                        }
                    }
                }
                Ok(OwnedSurfaceCheckpoint {
                    record: record__,
                    snapshot_event: snapshot_event__,
                    version: version__.unwrap_or_default(),
                    surface_hash: surface_hash__.unwrap_or_default(),
                    conversation: conversation__,
                    group_epoch: group_epoch__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.OwnedSurfaceCheckpoint",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

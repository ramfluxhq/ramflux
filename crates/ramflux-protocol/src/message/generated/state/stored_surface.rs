// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StoredSurface {
    #[prost(string, tag = "1")]
    pub surface_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub conversation_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub author_principal_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub author_device_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "5")]
    pub checkpoint: ::core::option::Option<SurfaceCheckpoint>,
    #[prost(int64, optional, tag = "6")]
    pub created_at: ::core::option::Option<i64>,
    #[prost(int64, optional, tag = "7")]
    pub updated_at: ::core::option::Option<i64>,
}
impl serde::Serialize for StoredSurface {
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
        if !self.conversation_id.is_empty() {
            len += 1;
        }
        if !self.author_principal_id.is_empty() {
            len += 1;
        }
        if !self.author_device_id.is_empty() {
            len += 1;
        }
        if self.checkpoint.is_some() {
            len += 1;
        }
        if self.created_at.is_some() {
            len += 1;
        }
        if self.updated_at.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.StoredSurface", len)?;
        if !self.surface_id.is_empty() {
            struct_ser.serialize_field("surfaceId", &self.surface_id)?;
        }
        if !self.conversation_id.is_empty() {
            struct_ser.serialize_field("conversationId", &self.conversation_id)?;
        }
        if !self.author_principal_id.is_empty() {
            struct_ser.serialize_field("authorPrincipalId", &self.author_principal_id)?;
        }
        if !self.author_device_id.is_empty() {
            struct_ser.serialize_field("authorDeviceId", &self.author_device_id)?;
        }
        if let Some(v) = self.checkpoint.as_ref() {
            struct_ser.serialize_field("checkpoint", v)?;
        }
        if let Some(v) = self.created_at.as_ref() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("createdAt", ToString::to_string(&v).as_str())?;
        }
        if let Some(v) = self.updated_at.as_ref() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("updatedAt", ToString::to_string(&v).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for StoredSurface {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "surface_id",
            "surfaceId",
            "conversation_id",
            "conversationId",
            "author_principal_id",
            "authorPrincipalId",
            "author_device_id",
            "authorDeviceId",
            "checkpoint",
            "created_at",
            "createdAt",
            "updated_at",
            "updatedAt",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            SurfaceId,
            ConversationId,
            AuthorPrincipalId,
            AuthorDeviceId,
            Checkpoint,
            CreatedAt,
            UpdatedAt,
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
                            "conversationId" | "conversation_id" => {
                                Ok(GeneratedField::ConversationId)
                            }
                            "authorPrincipalId" | "author_principal_id" => {
                                Ok(GeneratedField::AuthorPrincipalId)
                            }
                            "authorDeviceId" | "author_device_id" => {
                                Ok(GeneratedField::AuthorDeviceId)
                            }
                            "checkpoint" => Ok(GeneratedField::Checkpoint),
                            "createdAt" | "created_at" => Ok(GeneratedField::CreatedAt),
                            "updatedAt" | "updated_at" => Ok(GeneratedField::UpdatedAt),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = StoredSurface;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.StoredSurface")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<StoredSurface, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut surface_id__ = None;
                let mut conversation_id__ = None;
                let mut author_principal_id__ = None;
                let mut author_device_id__ = None;
                let mut checkpoint__ = None;
                let mut created_at__ = None;
                let mut updated_at__ = None;
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
                        GeneratedField::ConversationId => {
                            if conversation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversationId"));
                            }
                            conversation_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::AuthorPrincipalId => {
                            if author_principal_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("authorPrincipalId"));
                            }
                            author_principal_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::AuthorDeviceId => {
                            if author_device_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("authorDeviceId"));
                            }
                            author_device_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Checkpoint => {
                            if checkpoint__.is_some() {
                                return Err(serde::de::Error::duplicate_field("checkpoint"));
                            }
                            checkpoint__ = map_.next_value()?;
                        }
                        GeneratedField::CreatedAt => {
                            if created_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("createdAt"));
                            }
                            created_at__ = map_
                                .next_value::<
                                    ::std::option::Option<
                                        ::pbjson::private::NumberDeserialize<_>,
                                    >,
                                >()?
                                .map(|x| x.0);
                        }
                        GeneratedField::UpdatedAt => {
                            if updated_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("updatedAt"));
                            }
                            updated_at__ = map_
                                .next_value::<
                                    ::std::option::Option<
                                        ::pbjson::private::NumberDeserialize<_>,
                                    >,
                                >()?
                                .map(|x| x.0);
                        }
                    }
                }
                Ok(StoredSurface {
                    surface_id: surface_id__.unwrap_or_default(),
                    conversation_id: conversation_id__.unwrap_or_default(),
                    author_principal_id: author_principal_id__.unwrap_or_default(),
                    author_device_id: author_device_id__.unwrap_or_default(),
                    checkpoint: checkpoint__,
                    created_at: created_at__,
                    updated_at: updated_at__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.StoredSurface",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

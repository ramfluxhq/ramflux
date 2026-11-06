// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SurfaceCheckpoint {
    #[prost(string, tag = "1")]
    pub schema: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub content: ::core::option::Option<CreateSurfaceCommand>,
    #[prost(string, optional, tag = "3")]
    pub conversation_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint64, tag = "4")]
    pub version: u64,
    #[prost(bool, tag = "5")]
    pub closed: bool,
    #[prost(message, repeated, tag = "6")]
    pub final_text: ::prost::alloc::vec::Vec<SurfaceFinalEntry>,
}
impl serde::Serialize for SurfaceCheckpoint {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.schema.is_empty() {
            len += 1;
        }
        if self.content.is_some() {
            len += 1;
        }
        if self.conversation_id.is_some() {
            len += 1;
        }
        if self.version != 0 {
            len += 1;
        }
        if self.closed {
            len += 1;
        }
        if !self.final_text.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.SurfaceCheckpoint", len)?;
        if !self.schema.is_empty() {
            struct_ser.serialize_field("schema", &self.schema)?;
        }
        if let Some(v) = self.content.as_ref() {
            struct_ser.serialize_field("content", v)?;
        }
        if let Some(v) = self.conversation_id.as_ref() {
            struct_ser.serialize_field("conversationId", v)?;
        }
        if self.version != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("version", ToString::to_string(&self.version).as_str())?;
        }
        if self.closed {
            struct_ser.serialize_field("closed", &self.closed)?;
        }
        if !self.final_text.is_empty() {
            struct_ser.serialize_field("finalText", &self.final_text)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SurfaceCheckpoint {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "schema",
            "content",
            "conversation_id",
            "conversationId",
            "version",
            "closed",
            "final_text",
            "finalText",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Schema,
            Content,
            ConversationId,
            Version,
            Closed,
            FinalText,
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
                            "schema" => Ok(GeneratedField::Schema),
                            "content" => Ok(GeneratedField::Content),
                            "conversationId" | "conversation_id" => {
                                Ok(GeneratedField::ConversationId)
                            }
                            "version" => Ok(GeneratedField::Version),
                            "closed" => Ok(GeneratedField::Closed),
                            "finalText" | "final_text" => Ok(GeneratedField::FinalText),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SurfaceCheckpoint;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SurfaceCheckpoint")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SurfaceCheckpoint, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut schema__ = None;
                let mut content__ = None;
                let mut conversation_id__ = None;
                let mut version__ = None;
                let mut closed__ = None;
                let mut final_text__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Schema => {
                            if schema__.is_some() {
                                return Err(serde::de::Error::duplicate_field("schema"));
                            }
                            schema__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Content => {
                            if content__.is_some() {
                                return Err(serde::de::Error::duplicate_field("content"));
                            }
                            content__ = map_.next_value()?;
                        }
                        GeneratedField::ConversationId => {
                            if conversation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversationId"));
                            }
                            conversation_id__ = map_.next_value()?;
                        }
                        GeneratedField::Version => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Closed => {
                            if closed__.is_some() {
                                return Err(serde::de::Error::duplicate_field("closed"));
                            }
                            closed__ = Some(map_.next_value()?);
                        }
                        GeneratedField::FinalText => {
                            if final_text__.is_some() {
                                return Err(serde::de::Error::duplicate_field("finalText"));
                            }
                            final_text__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(SurfaceCheckpoint {
                    schema: schema__.unwrap_or_default(),
                    content: content__,
                    conversation_id: conversation_id__,
                    version: version__.unwrap_or_default(),
                    closed: closed__.unwrap_or_default(),
                    final_text: final_text__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.SurfaceCheckpoint",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

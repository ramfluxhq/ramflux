// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(string, tag = "1")]
    pub text: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "2")]
    pub entities: ::prost::alloc::vec::Vec<Entity>,
    #[prost(message, optional, tag = "3")]
    pub reply_to: ::core::option::Option<MessageRef>,
    #[prost(message, optional, tag = "4")]
    pub forward: ::core::option::Option<Forward>,
    #[prost(message, repeated, tag = "5")]
    pub media: ::prost::alloc::vec::Vec<MediaRef>,
    #[prost(message, optional, tag = "16")]
    pub sealed_group: ::core::option::Option<GroupSealedContent>,
}
impl serde::Serialize for Message {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.text.is_empty() {
            len += 1;
        }
        if !self.entities.is_empty() {
            len += 1;
        }
        if self.reply_to.is_some() {
            len += 1;
        }
        if self.forward.is_some() {
            len += 1;
        }
        if !self.media.is_empty() {
            len += 1;
        }
        if self.sealed_group.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.Message", len)?;
        if !self.text.is_empty() {
            struct_ser.serialize_field("text", &self.text)?;
        }
        if !self.entities.is_empty() {
            struct_ser.serialize_field("entities", &self.entities)?;
        }
        if let Some(v) = self.reply_to.as_ref() {
            struct_ser.serialize_field("replyTo", v)?;
        }
        if let Some(v) = self.forward.as_ref() {
            struct_ser.serialize_field("forward", v)?;
        }
        if !self.media.is_empty() {
            struct_ser.serialize_field("media", &self.media)?;
        }
        if let Some(v) = self.sealed_group.as_ref() {
            struct_ser.serialize_field("sealedGroup", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Message {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "text",
            "entities",
            "reply_to",
            "replyTo",
            "forward",
            "media",
            "sealed_group",
            "sealedGroup",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Text,
            Entities,
            ReplyTo,
            Forward,
            Media,
            SealedGroup,
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
                            "text" => Ok(GeneratedField::Text),
                            "entities" => Ok(GeneratedField::Entities),
                            "replyTo" | "reply_to" => Ok(GeneratedField::ReplyTo),
                            "forward" => Ok(GeneratedField::Forward),
                            "media" => Ok(GeneratedField::Media),
                            "sealedGroup" | "sealed_group" => Ok(GeneratedField::SealedGroup),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Message;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.Message")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Message, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut text__ = None;
                let mut entities__ = None;
                let mut reply_to__ = None;
                let mut forward__ = None;
                let mut media__ = None;
                let mut sealed_group__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Text => {
                            if text__.is_some() {
                                return Err(serde::de::Error::duplicate_field("text"));
                            }
                            text__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Entities => {
                            if entities__.is_some() {
                                return Err(serde::de::Error::duplicate_field("entities"));
                            }
                            entities__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ReplyTo => {
                            if reply_to__.is_some() {
                                return Err(serde::de::Error::duplicate_field("replyTo"));
                            }
                            reply_to__ = map_.next_value()?;
                        }
                        GeneratedField::Forward => {
                            if forward__.is_some() {
                                return Err(serde::de::Error::duplicate_field("forward"));
                            }
                            forward__ = map_.next_value()?;
                        }
                        GeneratedField::Media => {
                            if media__.is_some() {
                                return Err(serde::de::Error::duplicate_field("media"));
                            }
                            media__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SealedGroup => {
                            if sealed_group__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sealedGroup"));
                            }
                            sealed_group__ = map_.next_value()?;
                        }
                    }
                }
                Ok(Message {
                    text: text__.unwrap_or_default(),
                    entities: entities__.unwrap_or_default(),
                    reply_to: reply_to__,
                    forward: forward__,
                    media: media__.unwrap_or_default(),
                    sealed_group: sealed_group__,
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.Message", FIELDS, GeneratedVisitor)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendMessage {
    #[prost(string, tag = "1")]
    pub conversation_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub content: ::core::option::Option<Content>,
    #[prost(bytes = "vec", tag = "3")]
    pub operation_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub reply_to: ::core::option::Option<MessageRef>,
}
impl serde::Serialize for SendMessage {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.conversation_id.is_empty() {
            len += 1;
        }
        if self.content.is_some() {
            len += 1;
        }
        if !self.operation_id.is_empty() {
            len += 1;
        }
        if self.reply_to.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.SendMessage", len)?;
        if !self.conversation_id.is_empty() {
            struct_ser.serialize_field("conversationId", &self.conversation_id)?;
        }
        if let Some(v) = self.content.as_ref() {
            struct_ser.serialize_field("content", v)?;
        }
        if !self.operation_id.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "operationId",
                pbjson::private::base64::encode(&self.operation_id).as_str(),
            )?;
        }
        if let Some(v) = self.reply_to.as_ref() {
            struct_ser.serialize_field("replyTo", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SendMessage {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "conversation_id",
            "conversationId",
            "content",
            "operation_id",
            "operationId",
            "reply_to",
            "replyTo",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            ConversationId,
            Content,
            OperationId,
            ReplyTo,
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
                            "conversationId" | "conversation_id" => {
                                Ok(GeneratedField::ConversationId)
                            }
                            "content" => Ok(GeneratedField::Content),
                            "operationId" | "operation_id" => Ok(GeneratedField::OperationId),
                            "replyTo" | "reply_to" => Ok(GeneratedField::ReplyTo),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SendMessage;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SendMessage")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SendMessage, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut conversation_id__ = None;
                let mut content__ = None;
                let mut operation_id__ = None;
                let mut reply_to__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::ConversationId => {
                            if conversation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversationId"));
                            }
                            conversation_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Content => {
                            if content__.is_some() {
                                return Err(serde::de::Error::duplicate_field("content"));
                            }
                            content__ = map_.next_value()?;
                        }
                        GeneratedField::OperationId => {
                            if operation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("operationId"));
                            }
                            operation_id__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::ReplyTo => {
                            if reply_to__.is_some() {
                                return Err(serde::de::Error::duplicate_field("replyTo"));
                            }
                            reply_to__ = map_.next_value()?;
                        }
                    }
                }
                Ok(SendMessage {
                    conversation_id: conversation_id__.unwrap_or_default(),
                    content: content__,
                    operation_id: operation_id__.unwrap_or_default(),
                    reply_to: reply_to__,
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.SendMessage", FIELDS, GeneratedVisitor)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageRequest {
    #[prost(string, tag = "1")]
    pub request_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub account_id: ::prost::alloc::string::String,
    #[prost(oneof = "message_request::Action", tags = "3, 4, 5, 6, 7")]
    pub action: ::core::option::Option<message_request::Action>,
}
/// Nested message and enum types in `MessageRequest`.
pub mod message_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Action {
        #[prost(message, tag = "3")]
        Send(super::SendMessage),
        #[prost(message, tag = "4")]
        Edit(super::Edit),
        #[prost(message, tag = "5")]
        Delete(super::Delete),
        #[prost(message, tag = "6")]
        Reaction(super::Reaction),
        #[prost(message, tag = "7")]
        Typing(super::Typing),
    }
}
impl serde::Serialize for MessageRequest {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.request_id.is_empty() {
            len += 1;
        }
        if !self.account_id.is_empty() {
            len += 1;
        }
        if self.action.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.MessageRequest", len)?;
        if !self.request_id.is_empty() {
            struct_ser.serialize_field("requestId", &self.request_id)?;
        }
        if !self.account_id.is_empty() {
            struct_ser.serialize_field("accountId", &self.account_id)?;
        }
        if let Some(v) = self.action.as_ref() {
            match v {
                message_request::Action::Send(v) => {
                    struct_ser.serialize_field("send", v)?;
                }
                message_request::Action::Edit(v) => {
                    struct_ser.serialize_field("edit", v)?;
                }
                message_request::Action::Delete(v) => {
                    struct_ser.serialize_field("delete", v)?;
                }
                message_request::Action::Reaction(v) => {
                    struct_ser.serialize_field("reaction", v)?;
                }
                message_request::Action::Typing(v) => {
                    struct_ser.serialize_field("typing", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MessageRequest {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "request_id",
            "requestId",
            "account_id",
            "accountId",
            "send",
            "edit",
            "delete",
            "reaction",
            "typing",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            RequestId,
            AccountId,
            Send,
            Edit,
            Delete,
            Reaction,
            Typing,
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
                            "requestId" | "request_id" => Ok(GeneratedField::RequestId),
                            "accountId" | "account_id" => Ok(GeneratedField::AccountId),
                            "send" => Ok(GeneratedField::Send),
                            "edit" => Ok(GeneratedField::Edit),
                            "delete" => Ok(GeneratedField::Delete),
                            "reaction" => Ok(GeneratedField::Reaction),
                            "typing" => Ok(GeneratedField::Typing),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MessageRequest;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.MessageRequest")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<MessageRequest, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut request_id__ = None;
                let mut account_id__ = None;
                let mut action__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::RequestId => {
                            if request_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("requestId"));
                            }
                            request_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::AccountId => {
                            if account_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("accountId"));
                            }
                            account_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Send => {
                            if action__.is_some() {
                                return Err(serde::de::Error::duplicate_field("send"));
                            }
                            action__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(message_request::Action::Send);
                        }
                        GeneratedField::Edit => {
                            if action__.is_some() {
                                return Err(serde::de::Error::duplicate_field("edit"));
                            }
                            action__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(message_request::Action::Edit);
                        }
                        GeneratedField::Delete => {
                            if action__.is_some() {
                                return Err(serde::de::Error::duplicate_field("delete"));
                            }
                            action__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(message_request::Action::Delete);
                        }
                        GeneratedField::Reaction => {
                            if action__.is_some() {
                                return Err(serde::de::Error::duplicate_field("reaction"));
                            }
                            action__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(message_request::Action::Reaction);
                        }
                        GeneratedField::Typing => {
                            if action__.is_some() {
                                return Err(serde::de::Error::duplicate_field("typing"));
                            }
                            action__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(message_request::Action::Typing);
                        }
                    }
                }
                Ok(MessageRequest {
                    request_id: request_id__.unwrap_or_default(),
                    account_id: account_id__.unwrap_or_default(),
                    action: action__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.MessageRequest",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

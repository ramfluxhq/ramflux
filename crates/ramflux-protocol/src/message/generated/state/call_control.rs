// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct CallControl {
    #[prost(string, tag = "1")]
    pub schema: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub call_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub conversation_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub caller: ::core::option::Option<CallEndpoint>,
    #[prost(message, optional, tag = "5")]
    pub callee: ::core::option::Option<CallEndpoint>,
    #[prost(message, optional, tag = "6")]
    pub sender: ::core::option::Option<CallEndpoint>,
    #[prost(uint64, tag = "7")]
    pub seq: u64,
    #[prost(int64, tag = "8")]
    pub created_at: i64,
    #[prost(message, optional, tag = "9")]
    pub body: ::core::option::Option<CallAction>,
    #[prost(string, tag = "10")]
    pub signature: ::prost::alloc::string::String,
}
impl serde::Serialize for CallControl {
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
        if !self.call_id.is_empty() {
            len += 1;
        }
        if !self.conversation_id.is_empty() {
            len += 1;
        }
        if self.caller.is_some() {
            len += 1;
        }
        if self.callee.is_some() {
            len += 1;
        }
        if self.sender.is_some() {
            len += 1;
        }
        if self.seq != 0 {
            len += 1;
        }
        if self.created_at != 0 {
            len += 1;
        }
        if self.body.is_some() {
            len += 1;
        }
        if !self.signature.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.CallControl", len)?;
        if !self.schema.is_empty() {
            struct_ser.serialize_field("schema", &self.schema)?;
        }
        if !self.call_id.is_empty() {
            struct_ser.serialize_field("callId", &self.call_id)?;
        }
        if !self.conversation_id.is_empty() {
            struct_ser.serialize_field("conversationId", &self.conversation_id)?;
        }
        if let Some(v) = self.caller.as_ref() {
            struct_ser.serialize_field("caller", v)?;
        }
        if let Some(v) = self.callee.as_ref() {
            struct_ser.serialize_field("callee", v)?;
        }
        if let Some(v) = self.sender.as_ref() {
            struct_ser.serialize_field("sender", v)?;
        }
        if self.seq != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("seq", ToString::to_string(&self.seq).as_str())?;
        }
        if self.created_at != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("createdAt", ToString::to_string(&self.created_at).as_str())?;
        }
        if let Some(v) = self.body.as_ref() {
            struct_ser.serialize_field("body", v)?;
        }
        if !self.signature.is_empty() {
            struct_ser.serialize_field("signature", &self.signature)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for CallControl {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "schema",
            "call_id",
            "callId",
            "conversation_id",
            "conversationId",
            "caller",
            "callee",
            "sender",
            "seq",
            "created_at",
            "createdAt",
            "body",
            "signature",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Schema,
            CallId,
            ConversationId,
            Caller,
            Callee,
            Sender,
            Seq,
            CreatedAt,
            Body,
            Signature,
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
                            "callId" | "call_id" => Ok(GeneratedField::CallId),
                            "conversationId" | "conversation_id" => {
                                Ok(GeneratedField::ConversationId)
                            }
                            "caller" => Ok(GeneratedField::Caller),
                            "callee" => Ok(GeneratedField::Callee),
                            "sender" => Ok(GeneratedField::Sender),
                            "seq" => Ok(GeneratedField::Seq),
                            "createdAt" | "created_at" => Ok(GeneratedField::CreatedAt),
                            "body" => Ok(GeneratedField::Body),
                            "signature" => Ok(GeneratedField::Signature),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = CallControl;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.CallControl")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<CallControl, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut schema__ = None;
                let mut call_id__ = None;
                let mut conversation_id__ = None;
                let mut caller__ = None;
                let mut callee__ = None;
                let mut sender__ = None;
                let mut seq__ = None;
                let mut created_at__ = None;
                let mut body__ = None;
                let mut signature__ = None;
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
                        GeneratedField::CallId => {
                            if call_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("callId"));
                            }
                            call_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ConversationId => {
                            if conversation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversationId"));
                            }
                            conversation_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Caller => {
                            if caller__.is_some() {
                                return Err(serde::de::Error::duplicate_field("caller"));
                            }
                            caller__ = map_.next_value()?;
                        }
                        GeneratedField::Callee => {
                            if callee__.is_some() {
                                return Err(serde::de::Error::duplicate_field("callee"));
                            }
                            callee__ = map_.next_value()?;
                        }
                        GeneratedField::Sender => {
                            if sender__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sender"));
                            }
                            sender__ = map_.next_value()?;
                        }
                        GeneratedField::Seq => {
                            if seq__.is_some() {
                                return Err(serde::de::Error::duplicate_field("seq"));
                            }
                            seq__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::CreatedAt => {
                            if created_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("createdAt"));
                            }
                            created_at__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Body => {
                            if body__.is_some() {
                                return Err(serde::de::Error::duplicate_field("body"));
                            }
                            body__ = map_.next_value()?;
                        }
                        GeneratedField::Signature => {
                            if signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(CallControl {
                    schema: schema__.unwrap_or_default(),
                    call_id: call_id__.unwrap_or_default(),
                    conversation_id: conversation_id__.unwrap_or_default(),
                    caller: caller__,
                    callee: callee__,
                    sender: sender__,
                    seq: seq__.unwrap_or_default(),
                    created_at: created_at__.unwrap_or_default(),
                    body: body__,
                    signature: signature__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.CallControl", FIELDS, GeneratedVisitor)
    }
}

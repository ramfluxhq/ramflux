// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferProbe {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub actor: ::core::option::Option<NativeGroupActor>,
    #[prost(message, optional, tag = "3")]
    pub creator: ::core::option::Option<NativeGroupActor>,
    #[prost(message, optional, tag = "4")]
    pub base: ::core::option::Option<NativeGroupSnapshot>,
    #[prost(message, repeated, tag = "5")]
    pub required: ::prost::alloc::vec::Vec<TransferDevice>,
    #[prost(int64, tag = "6")]
    pub issued_at: i64,
    #[prost(int64, tag = "7")]
    pub expires_at: i64,
}
impl serde::Serialize for TransferProbe {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.id.is_empty() {
            len += 1;
        }
        if self.actor.is_some() {
            len += 1;
        }
        if self.creator.is_some() {
            len += 1;
        }
        if self.base.is_some() {
            len += 1;
        }
        if !self.required.is_empty() {
            len += 1;
        }
        if self.issued_at != 0 {
            len += 1;
        }
        if self.expires_at != 0 {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.TransferProbe", len)?;
        if !self.id.is_empty() {
            struct_ser.serialize_field("id", &self.id)?;
        }
        if let Some(v) = self.actor.as_ref() {
            struct_ser.serialize_field("actor", v)?;
        }
        if let Some(v) = self.creator.as_ref() {
            struct_ser.serialize_field("creator", v)?;
        }
        if let Some(v) = self.base.as_ref() {
            struct_ser.serialize_field("base", v)?;
        }
        if !self.required.is_empty() {
            struct_ser.serialize_field("required", &self.required)?;
        }
        if self.issued_at != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("issuedAt", ToString::to_string(&self.issued_at).as_str())?;
        }
        if self.expires_at != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("expiresAt", ToString::to_string(&self.expires_at).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TransferProbe {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "id",
            "actor",
            "creator",
            "base",
            "required",
            "issued_at",
            "issuedAt",
            "expires_at",
            "expiresAt",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Id,
            Actor,
            Creator,
            Base,
            Required,
            IssuedAt,
            ExpiresAt,
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
                            "id" => Ok(GeneratedField::Id),
                            "actor" => Ok(GeneratedField::Actor),
                            "creator" => Ok(GeneratedField::Creator),
                            "base" => Ok(GeneratedField::Base),
                            "required" => Ok(GeneratedField::Required),
                            "issuedAt" | "issued_at" => Ok(GeneratedField::IssuedAt),
                            "expiresAt" | "expires_at" => Ok(GeneratedField::ExpiresAt),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TransferProbe;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TransferProbe")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TransferProbe, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut id__ = None;
                let mut actor__ = None;
                let mut creator__ = None;
                let mut base__ = None;
                let mut required__ = None;
                let mut issued_at__ = None;
                let mut expires_at__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Id => {
                            if id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("id"));
                            }
                            id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Actor => {
                            if actor__.is_some() {
                                return Err(serde::de::Error::duplicate_field("actor"));
                            }
                            actor__ = map_.next_value()?;
                        }
                        GeneratedField::Creator => {
                            if creator__.is_some() {
                                return Err(serde::de::Error::duplicate_field("creator"));
                            }
                            creator__ = map_.next_value()?;
                        }
                        GeneratedField::Base => {
                            if base__.is_some() {
                                return Err(serde::de::Error::duplicate_field("base"));
                            }
                            base__ = map_.next_value()?;
                        }
                        GeneratedField::Required => {
                            if required__.is_some() {
                                return Err(serde::de::Error::duplicate_field("required"));
                            }
                            required__ = Some(map_.next_value()?);
                        }
                        GeneratedField::IssuedAt => {
                            if issued_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("issuedAt"));
                            }
                            issued_at__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::ExpiresAt => {
                            if expires_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("expiresAt"));
                            }
                            expires_at__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(TransferProbe {
                    id: id__.unwrap_or_default(),
                    actor: actor__,
                    creator: creator__,
                    base: base__,
                    required: required__.unwrap_or_default(),
                    issued_at: issued_at__.unwrap_or_default(),
                    expires_at: expires_at__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.TransferProbe",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct OwnGroupConsent {
    #[prost(string, tag = "1")]
    pub schema: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub actor: ::core::option::Option<NativeGroupActor>,
    #[prost(message, optional, tag = "3")]
    pub snapshot: ::core::option::Option<NativeGroupSnapshot>,
    #[prost(bool, tag = "4")]
    pub accepted: bool,
    #[prost(int64, tag = "5")]
    pub issued_at: i64,
    #[prost(int64, tag = "6")]
    pub expires_at: i64,
    #[prost(string, tag = "7")]
    pub signature: ::prost::alloc::string::String,
}
impl serde::Serialize for OwnGroupConsent {
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
        if self.actor.is_some() {
            len += 1;
        }
        if self.snapshot.is_some() {
            len += 1;
        }
        if self.accepted {
            len += 1;
        }
        if self.issued_at != 0 {
            len += 1;
        }
        if self.expires_at != 0 {
            len += 1;
        }
        if !self.signature.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.OwnGroupConsent", len)?;
        if !self.schema.is_empty() {
            struct_ser.serialize_field("schema", &self.schema)?;
        }
        if let Some(v) = self.actor.as_ref() {
            struct_ser.serialize_field("actor", v)?;
        }
        if let Some(v) = self.snapshot.as_ref() {
            struct_ser.serialize_field("snapshot", v)?;
        }
        if self.accepted {
            struct_ser.serialize_field("accepted", &self.accepted)?;
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
        if !self.signature.is_empty() {
            struct_ser.serialize_field("signature", &self.signature)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for OwnGroupConsent {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "schema",
            "actor",
            "snapshot",
            "accepted",
            "issued_at",
            "issuedAt",
            "expires_at",
            "expiresAt",
            "signature",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Schema,
            Actor,
            Snapshot,
            Accepted,
            IssuedAt,
            ExpiresAt,
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
                            "actor" => Ok(GeneratedField::Actor),
                            "snapshot" => Ok(GeneratedField::Snapshot),
                            "accepted" => Ok(GeneratedField::Accepted),
                            "issuedAt" | "issued_at" => Ok(GeneratedField::IssuedAt),
                            "expiresAt" | "expires_at" => Ok(GeneratedField::ExpiresAt),
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
            type Value = OwnGroupConsent;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.OwnGroupConsent")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<OwnGroupConsent, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut schema__ = None;
                let mut actor__ = None;
                let mut snapshot__ = None;
                let mut accepted__ = None;
                let mut issued_at__ = None;
                let mut expires_at__ = None;
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
                        GeneratedField::Actor => {
                            if actor__.is_some() {
                                return Err(serde::de::Error::duplicate_field("actor"));
                            }
                            actor__ = map_.next_value()?;
                        }
                        GeneratedField::Snapshot => {
                            if snapshot__.is_some() {
                                return Err(serde::de::Error::duplicate_field("snapshot"));
                            }
                            snapshot__ = map_.next_value()?;
                        }
                        GeneratedField::Accepted => {
                            if accepted__.is_some() {
                                return Err(serde::de::Error::duplicate_field("accepted"));
                            }
                            accepted__ = Some(map_.next_value()?);
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
                        GeneratedField::Signature => {
                            if signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(OwnGroupConsent {
                    schema: schema__.unwrap_or_default(),
                    actor: actor__,
                    snapshot: snapshot__,
                    accepted: accepted__.unwrap_or_default(),
                    issued_at: issued_at__.unwrap_or_default(),
                    expires_at: expires_at__.unwrap_or_default(),
                    signature: signature__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.OwnGroupConsent",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

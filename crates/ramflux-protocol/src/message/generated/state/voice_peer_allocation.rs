// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct VoicePeerAllocation {
    #[prost(string, tag = "1")]
    pub lease_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub endpoint: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub expires_at: u64,
    #[prost(uint64, tag = "4")]
    pub hard_expires_at: u64,
}
impl serde::Serialize for VoicePeerAllocation {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.lease_id.is_empty() {
            len += 1;
        }
        if !self.endpoint.is_empty() {
            len += 1;
        }
        if self.expires_at != 0 {
            len += 1;
        }
        if self.hard_expires_at != 0 {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.VoicePeerAllocation", len)?;
        if !self.lease_id.is_empty() {
            struct_ser.serialize_field("leaseId", &self.lease_id)?;
        }
        if !self.endpoint.is_empty() {
            struct_ser.serialize_field("endpoint", &self.endpoint)?;
        }
        if self.expires_at != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("expiresAt", ToString::to_string(&self.expires_at).as_str())?;
        }
        if self.hard_expires_at != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "hardExpiresAt",
                ToString::to_string(&self.hard_expires_at).as_str(),
            )?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for VoicePeerAllocation {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "lease_id",
            "leaseId",
            "endpoint",
            "expires_at",
            "expiresAt",
            "hard_expires_at",
            "hardExpiresAt",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            LeaseId,
            Endpoint,
            ExpiresAt,
            HardExpiresAt,
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
                            "leaseId" | "lease_id" => Ok(GeneratedField::LeaseId),
                            "endpoint" => Ok(GeneratedField::Endpoint),
                            "expiresAt" | "expires_at" => Ok(GeneratedField::ExpiresAt),
                            "hardExpiresAt" | "hard_expires_at" => {
                                Ok(GeneratedField::HardExpiresAt)
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
            type Value = VoicePeerAllocation;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.VoicePeerAllocation")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<VoicePeerAllocation, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut lease_id__ = None;
                let mut endpoint__ = None;
                let mut expires_at__ = None;
                let mut hard_expires_at__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::LeaseId => {
                            if lease_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("leaseId"));
                            }
                            lease_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Endpoint => {
                            if endpoint__.is_some() {
                                return Err(serde::de::Error::duplicate_field("endpoint"));
                            }
                            endpoint__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ExpiresAt => {
                            if expires_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("expiresAt"));
                            }
                            expires_at__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::HardExpiresAt => {
                            if hard_expires_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("hardExpiresAt"));
                            }
                            hard_expires_at__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(VoicePeerAllocation {
                    lease_id: lease_id__.unwrap_or_default(),
                    endpoint: endpoint__.unwrap_or_default(),
                    expires_at: expires_at__.unwrap_or_default(),
                    hard_expires_at: hard_expires_at__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.VoicePeerAllocation",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct VoiceLeaseConsent {
    #[prost(message, optional, tag = "1")]
    pub scope: ::core::option::Option<VoiceAllocationRequest>,
    #[prost(string, tag = "2")]
    pub lease_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub expires_at: u64,
    #[prost(string, tag = "4")]
    pub signature: ::prost::alloc::string::String,
}
impl serde::Serialize for VoiceLeaseConsent {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.scope.is_some() {
            len += 1;
        }
        if !self.lease_id.is_empty() {
            len += 1;
        }
        if self.expires_at != 0 {
            len += 1;
        }
        if !self.signature.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.VoiceLeaseConsent", len)?;
        if let Some(v) = self.scope.as_ref() {
            struct_ser.serialize_field("scope", v)?;
        }
        if !self.lease_id.is_empty() {
            struct_ser.serialize_field("leaseId", &self.lease_id)?;
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
impl<'de> serde::Deserialize<'de> for VoiceLeaseConsent {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["scope", "lease_id", "leaseId", "expires_at", "expiresAt", "signature"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Scope,
            LeaseId,
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
                            "scope" => Ok(GeneratedField::Scope),
                            "leaseId" | "lease_id" => Ok(GeneratedField::LeaseId),
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
            type Value = VoiceLeaseConsent;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.VoiceLeaseConsent")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<VoiceLeaseConsent, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut scope__ = None;
                let mut lease_id__ = None;
                let mut expires_at__ = None;
                let mut signature__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Scope => {
                            if scope__.is_some() {
                                return Err(serde::de::Error::duplicate_field("scope"));
                            }
                            scope__ = map_.next_value()?;
                        }
                        GeneratedField::LeaseId => {
                            if lease_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("leaseId"));
                            }
                            lease_id__ = Some(map_.next_value()?);
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
                Ok(VoiceLeaseConsent {
                    scope: scope__,
                    lease_id: lease_id__.unwrap_or_default(),
                    expires_at: expires_at__.unwrap_or_default(),
                    signature: signature__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.VoiceLeaseConsent",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

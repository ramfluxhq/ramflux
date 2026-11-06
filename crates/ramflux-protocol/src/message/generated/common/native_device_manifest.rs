// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NativeDeviceManifest {
    #[prost(message, optional, tag = "1")]
    pub custody: ::core::option::Option<NativeCustodyManifest>,
    #[prost(message, optional, tag = "2")]
    pub signed_device_set: ::core::option::Option<NativeSignedDeviceSet>,
    #[prost(string, tag = "3")]
    pub principal_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub principal_commitment: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub root_public_key: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "6")]
    pub devices: ::prost::alloc::vec::Vec<ManifestDevice>,
}
impl serde::Serialize for NativeDeviceManifest {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.custody.is_some() {
            len += 1;
        }
        if self.signed_device_set.is_some() {
            len += 1;
        }
        if !self.principal_id.is_empty() {
            len += 1;
        }
        if !self.principal_commitment.is_empty() {
            len += 1;
        }
        if !self.root_public_key.is_empty() {
            len += 1;
        }
        if !self.devices.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.NativeDeviceManifest", len)?;
        if let Some(v) = self.custody.as_ref() {
            struct_ser.serialize_field("custody", v)?;
        }
        if let Some(v) = self.signed_device_set.as_ref() {
            struct_ser.serialize_field("signedDeviceSet", v)?;
        }
        if !self.principal_id.is_empty() {
            struct_ser.serialize_field("principalId", &self.principal_id)?;
        }
        if !self.principal_commitment.is_empty() {
            struct_ser.serialize_field("principalCommitment", &self.principal_commitment)?;
        }
        if !self.root_public_key.is_empty() {
            struct_ser.serialize_field("rootPublicKey", &self.root_public_key)?;
        }
        if !self.devices.is_empty() {
            struct_ser.serialize_field("devices", &self.devices)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for NativeDeviceManifest {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "custody",
            "signed_device_set",
            "signedDeviceSet",
            "principal_id",
            "principalId",
            "principal_commitment",
            "principalCommitment",
            "root_public_key",
            "rootPublicKey",
            "devices",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Custody,
            SignedDeviceSet,
            PrincipalId,
            PrincipalCommitment,
            RootPublicKey,
            Devices,
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
                            "custody" => Ok(GeneratedField::Custody),
                            "signedDeviceSet" | "signed_device_set" => {
                                Ok(GeneratedField::SignedDeviceSet)
                            }
                            "principalId" | "principal_id" => Ok(GeneratedField::PrincipalId),
                            "principalCommitment" | "principal_commitment" => {
                                Ok(GeneratedField::PrincipalCommitment)
                            }
                            "rootPublicKey" | "root_public_key" => {
                                Ok(GeneratedField::RootPublicKey)
                            }
                            "devices" => Ok(GeneratedField::Devices),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = NativeDeviceManifest;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.NativeDeviceManifest")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<NativeDeviceManifest, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut custody__ = None;
                let mut signed_device_set__ = None;
                let mut principal_id__ = None;
                let mut principal_commitment__ = None;
                let mut root_public_key__ = None;
                let mut devices__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Custody => {
                            if custody__.is_some() {
                                return Err(serde::de::Error::duplicate_field("custody"));
                            }
                            custody__ = map_.next_value()?;
                        }
                        GeneratedField::SignedDeviceSet => {
                            if signed_device_set__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signedDeviceSet"));
                            }
                            signed_device_set__ = map_.next_value()?;
                        }
                        GeneratedField::PrincipalId => {
                            if principal_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("principalId"));
                            }
                            principal_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::PrincipalCommitment => {
                            if principal_commitment__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "principalCommitment",
                                ));
                            }
                            principal_commitment__ = Some(map_.next_value()?);
                        }
                        GeneratedField::RootPublicKey => {
                            if root_public_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("rootPublicKey"));
                            }
                            root_public_key__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Devices => {
                            if devices__.is_some() {
                                return Err(serde::de::Error::duplicate_field("devices"));
                            }
                            devices__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(NativeDeviceManifest {
                    custody: custody__,
                    signed_device_set: signed_device_set__,
                    principal_id: principal_id__.unwrap_or_default(),
                    principal_commitment: principal_commitment__.unwrap_or_default(),
                    root_public_key: root_public_key__.unwrap_or_default(),
                    devices: devices__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.NativeDeviceManifest",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

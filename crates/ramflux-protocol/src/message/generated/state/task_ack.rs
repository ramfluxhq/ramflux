// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaskAck {
    #[prost(message, optional, tag = "1")]
    pub carrier: ::core::option::Option<TaskCarrier>,
    #[prost(message, optional, tag = "2")]
    pub certificate: ::core::option::Option<TaskCertificate>,
    #[prost(message, repeated, tag = "3")]
    pub manifests: ::prost::alloc::vec::Vec<NativeDeviceManifest>,
    #[prost(string, tag = "4")]
    pub signer_principal: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub signer_device: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub signature: ::prost::alloc::string::String,
}
impl serde::Serialize for TaskAck {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.carrier.is_some() {
            len += 1;
        }
        if self.certificate.is_some() {
            len += 1;
        }
        if !self.manifests.is_empty() {
            len += 1;
        }
        if !self.signer_principal.is_empty() {
            len += 1;
        }
        if !self.signer_device.is_empty() {
            len += 1;
        }
        if !self.signature.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.TaskAck", len)?;
        if let Some(v) = self.carrier.as_ref() {
            struct_ser.serialize_field("carrier", v)?;
        }
        if let Some(v) = self.certificate.as_ref() {
            struct_ser.serialize_field("certificate", v)?;
        }
        if !self.manifests.is_empty() {
            struct_ser.serialize_field("manifests", &self.manifests)?;
        }
        if !self.signer_principal.is_empty() {
            struct_ser.serialize_field("signerPrincipal", &self.signer_principal)?;
        }
        if !self.signer_device.is_empty() {
            struct_ser.serialize_field("signerDevice", &self.signer_device)?;
        }
        if !self.signature.is_empty() {
            struct_ser.serialize_field("signature", &self.signature)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskAck {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "carrier",
            "certificate",
            "manifests",
            "signer_principal",
            "signerPrincipal",
            "signer_device",
            "signerDevice",
            "signature",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Carrier,
            Certificate,
            Manifests,
            SignerPrincipal,
            SignerDevice,
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
                            "carrier" => Ok(GeneratedField::Carrier),
                            "certificate" => Ok(GeneratedField::Certificate),
                            "manifests" => Ok(GeneratedField::Manifests),
                            "signerPrincipal" | "signer_principal" => {
                                Ok(GeneratedField::SignerPrincipal)
                            }
                            "signerDevice" | "signer_device" => Ok(GeneratedField::SignerDevice),
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
            type Value = TaskAck;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskAck")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskAck, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut carrier__ = None;
                let mut certificate__ = None;
                let mut manifests__ = None;
                let mut signer_principal__ = None;
                let mut signer_device__ = None;
                let mut signature__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Carrier => {
                            if carrier__.is_some() {
                                return Err(serde::de::Error::duplicate_field("carrier"));
                            }
                            carrier__ = map_.next_value()?;
                        }
                        GeneratedField::Certificate => {
                            if certificate__.is_some() {
                                return Err(serde::de::Error::duplicate_field("certificate"));
                            }
                            certificate__ = map_.next_value()?;
                        }
                        GeneratedField::Manifests => {
                            if manifests__.is_some() {
                                return Err(serde::de::Error::duplicate_field("manifests"));
                            }
                            manifests__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SignerPrincipal => {
                            if signer_principal__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signerPrincipal"));
                            }
                            signer_principal__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SignerDevice => {
                            if signer_device__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signerDevice"));
                            }
                            signer_device__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Signature => {
                            if signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(TaskAck {
                    carrier: carrier__,
                    certificate: certificate__,
                    manifests: manifests__.unwrap_or_default(),
                    signer_principal: signer_principal__.unwrap_or_default(),
                    signer_device: signer_device__.unwrap_or_default(),
                    signature: signature__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.TaskAck", FIELDS, GeneratedVisitor)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct LocalBusFederationRoute {
    #[prost(string, tag = "1")]
    pub federation_url: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub source_node_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub target_node_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub required_capability: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "5")]
    pub admin_token: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "6")]
    pub recipient_prekey_url: ::core::option::Option<::prost::alloc::string::String>,
}
impl serde::Serialize for LocalBusFederationRoute {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.federation_url.is_empty() {
            len += 1;
        }
        if !self.source_node_id.is_empty() {
            len += 1;
        }
        if !self.target_node_id.is_empty() {
            len += 1;
        }
        if !self.required_capability.is_empty() {
            len += 1;
        }
        if self.admin_token.is_some() {
            len += 1;
        }
        if self.recipient_prekey_url.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.LocalBusFederationRoute", len)?;
        if !self.federation_url.is_empty() {
            struct_ser.serialize_field("federationUrl", &self.federation_url)?;
        }
        if !self.source_node_id.is_empty() {
            struct_ser.serialize_field("sourceNodeId", &self.source_node_id)?;
        }
        if !self.target_node_id.is_empty() {
            struct_ser.serialize_field("targetNodeId", &self.target_node_id)?;
        }
        if !self.required_capability.is_empty() {
            struct_ser.serialize_field("requiredCapability", &self.required_capability)?;
        }
        if let Some(v) = self.admin_token.as_ref() {
            struct_ser.serialize_field("adminToken", v)?;
        }
        if let Some(v) = self.recipient_prekey_url.as_ref() {
            struct_ser.serialize_field("recipientPrekeyUrl", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LocalBusFederationRoute {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "federation_url",
            "federationUrl",
            "source_node_id",
            "sourceNodeId",
            "target_node_id",
            "targetNodeId",
            "required_capability",
            "requiredCapability",
            "admin_token",
            "adminToken",
            "recipient_prekey_url",
            "recipientPrekeyUrl",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            FederationUrl,
            SourceNodeId,
            TargetNodeId,
            RequiredCapability,
            AdminToken,
            RecipientPrekeyUrl,
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
                            "federationUrl" | "federation_url" => Ok(GeneratedField::FederationUrl),
                            "sourceNodeId" | "source_node_id" => Ok(GeneratedField::SourceNodeId),
                            "targetNodeId" | "target_node_id" => Ok(GeneratedField::TargetNodeId),
                            "requiredCapability" | "required_capability" => {
                                Ok(GeneratedField::RequiredCapability)
                            }
                            "adminToken" | "admin_token" => Ok(GeneratedField::AdminToken),
                            "recipientPrekeyUrl" | "recipient_prekey_url" => {
                                Ok(GeneratedField::RecipientPrekeyUrl)
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
            type Value = LocalBusFederationRoute;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.LocalBusFederationRoute")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<LocalBusFederationRoute, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut federation_url__ = None;
                let mut source_node_id__ = None;
                let mut target_node_id__ = None;
                let mut required_capability__ = None;
                let mut admin_token__ = None;
                let mut recipient_prekey_url__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::FederationUrl => {
                            if federation_url__.is_some() {
                                return Err(serde::de::Error::duplicate_field("federationUrl"));
                            }
                            federation_url__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SourceNodeId => {
                            if source_node_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sourceNodeId"));
                            }
                            source_node_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::TargetNodeId => {
                            if target_node_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("targetNodeId"));
                            }
                            target_node_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::RequiredCapability => {
                            if required_capability__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "requiredCapability",
                                ));
                            }
                            required_capability__ = Some(map_.next_value()?);
                        }
                        GeneratedField::AdminToken => {
                            if admin_token__.is_some() {
                                return Err(serde::de::Error::duplicate_field("adminToken"));
                            }
                            admin_token__ = map_.next_value()?;
                        }
                        GeneratedField::RecipientPrekeyUrl => {
                            if recipient_prekey_url__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "recipientPrekeyUrl",
                                ));
                            }
                            recipient_prekey_url__ = map_.next_value()?;
                        }
                    }
                }
                Ok(LocalBusFederationRoute {
                    federation_url: federation_url__.unwrap_or_default(),
                    source_node_id: source_node_id__.unwrap_or_default(),
                    target_node_id: target_node_id__.unwrap_or_default(),
                    required_capability: required_capability__.unwrap_or_default(),
                    admin_token: admin_token__,
                    recipient_prekey_url: recipient_prekey_url__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.LocalBusFederationRoute",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

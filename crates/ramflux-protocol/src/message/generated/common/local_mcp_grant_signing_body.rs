// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct LocalMcpGrantSigningBody {
    #[prost(message, optional, tag = "1")]
    pub task_binding: ::core::option::Option<TaskApprovalBinding>,
    #[prost(string, tag = "2")]
    pub approval_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub grant_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub server_id: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub tool_name: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "6")]
    pub tool_scope: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "7")]
    pub capability: ::core::option::Option<McpCapability>,
    #[prost(string, tag = "8")]
    pub registry_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "9")]
    pub tool_manifest_set_hash: ::prost::alloc::string::String,
    #[prost(bool, tag = "10")]
    pub full_delegation: bool,
    #[prost(bool, tag = "11")]
    pub single_use: bool,
    #[prost(string, optional, tag = "12")]
    pub arguments_hash: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, tag = "13")]
    pub expires_at: i64,
}
impl serde::Serialize for LocalMcpGrantSigningBody {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.task_binding.is_some() {
            len += 1;
        }
        if !self.approval_id.is_empty() {
            len += 1;
        }
        if !self.grant_id.is_empty() {
            len += 1;
        }
        if !self.server_id.is_empty() {
            len += 1;
        }
        if !self.tool_name.is_empty() {
            len += 1;
        }
        if self.tool_scope.is_some() {
            len += 1;
        }
        if self.capability.is_some() {
            len += 1;
        }
        if !self.registry_hash.is_empty() {
            len += 1;
        }
        if !self.tool_manifest_set_hash.is_empty() {
            len += 1;
        }
        if self.full_delegation {
            len += 1;
        }
        if self.single_use {
            len += 1;
        }
        if self.arguments_hash.is_some() {
            len += 1;
        }
        if self.expires_at != 0 {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.LocalMcpGrantSigningBody", len)?;
        if let Some(v) = self.task_binding.as_ref() {
            struct_ser.serialize_field("taskBinding", v)?;
        }
        if !self.approval_id.is_empty() {
            struct_ser.serialize_field("approvalId", &self.approval_id)?;
        }
        if !self.grant_id.is_empty() {
            struct_ser.serialize_field("grantId", &self.grant_id)?;
        }
        if !self.server_id.is_empty() {
            struct_ser.serialize_field("serverId", &self.server_id)?;
        }
        if !self.tool_name.is_empty() {
            struct_ser.serialize_field("toolName", &self.tool_name)?;
        }
        if let Some(v) = self.tool_scope.as_ref() {
            struct_ser.serialize_field("toolScope", v)?;
        }
        if let Some(v) = self.capability.as_ref() {
            struct_ser.serialize_field("capability", v)?;
        }
        if !self.registry_hash.is_empty() {
            struct_ser.serialize_field("registryHash", &self.registry_hash)?;
        }
        if !self.tool_manifest_set_hash.is_empty() {
            struct_ser.serialize_field("toolManifestSetHash", &self.tool_manifest_set_hash)?;
        }
        if self.full_delegation {
            struct_ser.serialize_field("fullDelegation", &self.full_delegation)?;
        }
        if self.single_use {
            struct_ser.serialize_field("singleUse", &self.single_use)?;
        }
        if let Some(v) = self.arguments_hash.as_ref() {
            struct_ser.serialize_field("argumentsHash", v)?;
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
impl<'de> serde::Deserialize<'de> for LocalMcpGrantSigningBody {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "task_binding",
            "taskBinding",
            "approval_id",
            "approvalId",
            "grant_id",
            "grantId",
            "server_id",
            "serverId",
            "tool_name",
            "toolName",
            "tool_scope",
            "toolScope",
            "capability",
            "registry_hash",
            "registryHash",
            "tool_manifest_set_hash",
            "toolManifestSetHash",
            "full_delegation",
            "fullDelegation",
            "single_use",
            "singleUse",
            "arguments_hash",
            "argumentsHash",
            "expires_at",
            "expiresAt",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            TaskBinding,
            ApprovalId,
            GrantId,
            ServerId,
            ToolName,
            ToolScope,
            Capability,
            RegistryHash,
            ToolManifestSetHash,
            FullDelegation,
            SingleUse,
            ArgumentsHash,
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
                            "taskBinding" | "task_binding" => Ok(GeneratedField::TaskBinding),
                            "approvalId" | "approval_id" => Ok(GeneratedField::ApprovalId),
                            "grantId" | "grant_id" => Ok(GeneratedField::GrantId),
                            "serverId" | "server_id" => Ok(GeneratedField::ServerId),
                            "toolName" | "tool_name" => Ok(GeneratedField::ToolName),
                            "toolScope" | "tool_scope" => Ok(GeneratedField::ToolScope),
                            "capability" => Ok(GeneratedField::Capability),
                            "registryHash" | "registry_hash" => Ok(GeneratedField::RegistryHash),
                            "toolManifestSetHash" | "tool_manifest_set_hash" => {
                                Ok(GeneratedField::ToolManifestSetHash)
                            }
                            "fullDelegation" | "full_delegation" => {
                                Ok(GeneratedField::FullDelegation)
                            }
                            "singleUse" | "single_use" => Ok(GeneratedField::SingleUse),
                            "argumentsHash" | "arguments_hash" => Ok(GeneratedField::ArgumentsHash),
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
            type Value = LocalMcpGrantSigningBody;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.LocalMcpGrantSigningBody")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<LocalMcpGrantSigningBody, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut task_binding__ = None;
                let mut approval_id__ = None;
                let mut grant_id__ = None;
                let mut server_id__ = None;
                let mut tool_name__ = None;
                let mut tool_scope__ = None;
                let mut capability__ = None;
                let mut registry_hash__ = None;
                let mut tool_manifest_set_hash__ = None;
                let mut full_delegation__ = None;
                let mut single_use__ = None;
                let mut arguments_hash__ = None;
                let mut expires_at__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::TaskBinding => {
                            if task_binding__.is_some() {
                                return Err(serde::de::Error::duplicate_field("taskBinding"));
                            }
                            task_binding__ = map_.next_value()?;
                        }
                        GeneratedField::ApprovalId => {
                            if approval_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("approvalId"));
                            }
                            approval_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::GrantId => {
                            if grant_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("grantId"));
                            }
                            grant_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ServerId => {
                            if server_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("serverId"));
                            }
                            server_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ToolName => {
                            if tool_name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("toolName"));
                            }
                            tool_name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ToolScope => {
                            if tool_scope__.is_some() {
                                return Err(serde::de::Error::duplicate_field("toolScope"));
                            }
                            tool_scope__ = map_.next_value()?;
                        }
                        GeneratedField::Capability => {
                            if capability__.is_some() {
                                return Err(serde::de::Error::duplicate_field("capability"));
                            }
                            capability__ = map_.next_value()?;
                        }
                        GeneratedField::RegistryHash => {
                            if registry_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("registryHash"));
                            }
                            registry_hash__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ToolManifestSetHash => {
                            if tool_manifest_set_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "toolManifestSetHash",
                                ));
                            }
                            tool_manifest_set_hash__ = Some(map_.next_value()?);
                        }
                        GeneratedField::FullDelegation => {
                            if full_delegation__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fullDelegation"));
                            }
                            full_delegation__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SingleUse => {
                            if single_use__.is_some() {
                                return Err(serde::de::Error::duplicate_field("singleUse"));
                            }
                            single_use__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ArgumentsHash => {
                            if arguments_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("argumentsHash"));
                            }
                            arguments_hash__ = map_.next_value()?;
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
                Ok(LocalMcpGrantSigningBody {
                    task_binding: task_binding__,
                    approval_id: approval_id__.unwrap_or_default(),
                    grant_id: grant_id__.unwrap_or_default(),
                    server_id: server_id__.unwrap_or_default(),
                    tool_name: tool_name__.unwrap_or_default(),
                    tool_scope: tool_scope__,
                    capability: capability__,
                    registry_hash: registry_hash__.unwrap_or_default(),
                    tool_manifest_set_hash: tool_manifest_set_hash__.unwrap_or_default(),
                    full_delegation: full_delegation__.unwrap_or_default(),
                    single_use: single_use__.unwrap_or_default(),
                    arguments_hash: arguments_hash__,
                    expires_at: expires_at__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.LocalMcpGrantSigningBody",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

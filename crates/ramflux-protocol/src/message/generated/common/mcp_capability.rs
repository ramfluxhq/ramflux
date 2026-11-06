// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Message)]
pub struct McpCapability {
    #[prost(oneof = "mcp_capability::Value", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11")]
    pub value: ::core::option::Option<mcp_capability::Value>,
}
/// Nested message and enum types in `McpCapability`.
pub mod mcp_capability {
    #[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "1")]
        ReadConversation(super::McpCapabilityReadConversation),
        #[prost(message, tag = "2")]
        DraftMessage(super::McpCapabilityDraftMessage),
        #[prost(message, tag = "3")]
        SendMessage(super::McpCapabilitySendMessage),
        #[prost(message, tag = "4")]
        ReadLocalFiles(super::McpCapabilityReadLocalFiles),
        #[prost(message, tag = "5")]
        WriteLocalFiles(super::McpCapabilityWriteLocalFiles),
        #[prost(message, tag = "6")]
        RunShell(super::McpCapabilityRunShell),
        #[prost(message, tag = "7")]
        ManageContacts(super::McpCapabilityManageContacts),
        #[prost(message, tag = "8")]
        ManageGroup(super::McpCapabilityManageGroup),
        #[prost(message, tag = "9")]
        ManageMedia(super::McpCapabilityManageMedia),
        #[prost(message, tag = "10")]
        ManageNode(super::McpCapabilityManageNode),
        #[prost(message, tag = "11")]
        ExternalToolInvoke(super::McpCapabilityExternalToolInvoke),
    }
}
impl serde::Serialize for McpCapability {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.value.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.McpCapability", len)?;
        if let Some(v) = self.value.as_ref() {
            match v {
                mcp_capability::Value::ReadConversation(v) => {
                    struct_ser.serialize_field("readConversation", v)?;
                }
                mcp_capability::Value::DraftMessage(v) => {
                    struct_ser.serialize_field("draftMessage", v)?;
                }
                mcp_capability::Value::SendMessage(v) => {
                    struct_ser.serialize_field("sendMessage", v)?;
                }
                mcp_capability::Value::ReadLocalFiles(v) => {
                    struct_ser.serialize_field("readLocalFiles", v)?;
                }
                mcp_capability::Value::WriteLocalFiles(v) => {
                    struct_ser.serialize_field("writeLocalFiles", v)?;
                }
                mcp_capability::Value::RunShell(v) => {
                    struct_ser.serialize_field("runShell", v)?;
                }
                mcp_capability::Value::ManageContacts(v) => {
                    struct_ser.serialize_field("manageContacts", v)?;
                }
                mcp_capability::Value::ManageGroup(v) => {
                    struct_ser.serialize_field("manageGroup", v)?;
                }
                mcp_capability::Value::ManageMedia(v) => {
                    struct_ser.serialize_field("manageMedia", v)?;
                }
                mcp_capability::Value::ManageNode(v) => {
                    struct_ser.serialize_field("manageNode", v)?;
                }
                mcp_capability::Value::ExternalToolInvoke(v) => {
                    struct_ser.serialize_field("externalToolInvoke", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for McpCapability {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "read_conversation",
            "readConversation",
            "draft_message",
            "draftMessage",
            "send_message",
            "sendMessage",
            "read_local_files",
            "readLocalFiles",
            "write_local_files",
            "writeLocalFiles",
            "run_shell",
            "runShell",
            "manage_contacts",
            "manageContacts",
            "manage_group",
            "manageGroup",
            "manage_media",
            "manageMedia",
            "manage_node",
            "manageNode",
            "external_tool_invoke",
            "externalToolInvoke",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            ReadConversation,
            DraftMessage,
            SendMessage,
            ReadLocalFiles,
            WriteLocalFiles,
            RunShell,
            ManageContacts,
            ManageGroup,
            ManageMedia,
            ManageNode,
            ExternalToolInvoke,
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
                            "readConversation" | "read_conversation" => {
                                Ok(GeneratedField::ReadConversation)
                            }
                            "draftMessage" | "draft_message" => Ok(GeneratedField::DraftMessage),
                            "sendMessage" | "send_message" => Ok(GeneratedField::SendMessage),
                            "readLocalFiles" | "read_local_files" => {
                                Ok(GeneratedField::ReadLocalFiles)
                            }
                            "writeLocalFiles" | "write_local_files" => {
                                Ok(GeneratedField::WriteLocalFiles)
                            }
                            "runShell" | "run_shell" => Ok(GeneratedField::RunShell),
                            "manageContacts" | "manage_contacts" => {
                                Ok(GeneratedField::ManageContacts)
                            }
                            "manageGroup" | "manage_group" => Ok(GeneratedField::ManageGroup),
                            "manageMedia" | "manage_media" => Ok(GeneratedField::ManageMedia),
                            "manageNode" | "manage_node" => Ok(GeneratedField::ManageNode),
                            "externalToolInvoke" | "external_tool_invoke" => {
                                Ok(GeneratedField::ExternalToolInvoke)
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
            type Value = McpCapability;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.McpCapability")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<McpCapability, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut value__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::ReadConversation => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("readConversation"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::ReadConversation);
                        }
                        GeneratedField::DraftMessage => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("draftMessage"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::DraftMessage);
                        }
                        GeneratedField::SendMessage => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sendMessage"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::SendMessage);
                        }
                        GeneratedField::ReadLocalFiles => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("readLocalFiles"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::ReadLocalFiles);
                        }
                        GeneratedField::WriteLocalFiles => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("writeLocalFiles"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::WriteLocalFiles);
                        }
                        GeneratedField::RunShell => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("runShell"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::RunShell);
                        }
                        GeneratedField::ManageContacts => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("manageContacts"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::ManageContacts);
                        }
                        GeneratedField::ManageGroup => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("manageGroup"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::ManageGroup);
                        }
                        GeneratedField::ManageMedia => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("manageMedia"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::ManageMedia);
                        }
                        GeneratedField::ManageNode => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("manageNode"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::ManageNode);
                        }
                        GeneratedField::ExternalToolInvoke => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "externalToolInvoke",
                                ));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(mcp_capability::Value::ExternalToolInvoke);
                        }
                    }
                }
                Ok(McpCapability { value: value__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.McpCapability",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

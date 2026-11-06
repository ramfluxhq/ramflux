// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SurfaceAction {
    #[prost(string, tag = "1")]
    pub schema: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub conversation_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub surface_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub version: u64,
    #[prost(string, tag = "5")]
    pub surface_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub action_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "7")]
    pub values: ::core::option::Option<JsonValue>,
    #[prost(string, tag = "8")]
    pub args_hash: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "9")]
    pub task_binding: ::core::option::Option<SurfaceTaskBinding>,
}
impl serde::Serialize for SurfaceAction {
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
        if !self.conversation_id.is_empty() {
            len += 1;
        }
        if !self.surface_id.is_empty() {
            len += 1;
        }
        if self.version != 0 {
            len += 1;
        }
        if !self.surface_hash.is_empty() {
            len += 1;
        }
        if !self.action_id.is_empty() {
            len += 1;
        }
        if self.values.is_some() {
            len += 1;
        }
        if !self.args_hash.is_empty() {
            len += 1;
        }
        if self.task_binding.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.SurfaceAction", len)?;
        if !self.schema.is_empty() {
            struct_ser.serialize_field("schema", &self.schema)?;
        }
        if !self.conversation_id.is_empty() {
            struct_ser.serialize_field("conversationId", &self.conversation_id)?;
        }
        if !self.surface_id.is_empty() {
            struct_ser.serialize_field("surfaceId", &self.surface_id)?;
        }
        if self.version != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("version", ToString::to_string(&self.version).as_str())?;
        }
        if !self.surface_hash.is_empty() {
            struct_ser.serialize_field("surfaceHash", &self.surface_hash)?;
        }
        if !self.action_id.is_empty() {
            struct_ser.serialize_field("actionId", &self.action_id)?;
        }
        if let Some(v) = self.values.as_ref() {
            struct_ser.serialize_field("values", v)?;
        }
        if !self.args_hash.is_empty() {
            struct_ser.serialize_field("argsHash", &self.args_hash)?;
        }
        if let Some(v) = self.task_binding.as_ref() {
            struct_ser.serialize_field("taskBinding", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SurfaceAction {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "schema",
            "conversation_id",
            "conversationId",
            "surface_id",
            "surfaceId",
            "version",
            "surface_hash",
            "surfaceHash",
            "action_id",
            "actionId",
            "values",
            "args_hash",
            "argsHash",
            "task_binding",
            "taskBinding",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Schema,
            ConversationId,
            SurfaceId,
            Version,
            SurfaceHash,
            ActionId,
            Values,
            ArgsHash,
            TaskBinding,
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
                            "conversationId" | "conversation_id" => {
                                Ok(GeneratedField::ConversationId)
                            }
                            "surfaceId" | "surface_id" => Ok(GeneratedField::SurfaceId),
                            "version" => Ok(GeneratedField::Version),
                            "surfaceHash" | "surface_hash" => Ok(GeneratedField::SurfaceHash),
                            "actionId" | "action_id" => Ok(GeneratedField::ActionId),
                            "values" => Ok(GeneratedField::Values),
                            "argsHash" | "args_hash" => Ok(GeneratedField::ArgsHash),
                            "taskBinding" | "task_binding" => Ok(GeneratedField::TaskBinding),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SurfaceAction;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SurfaceAction")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SurfaceAction, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut schema__ = None;
                let mut conversation_id__ = None;
                let mut surface_id__ = None;
                let mut version__ = None;
                let mut surface_hash__ = None;
                let mut action_id__ = None;
                let mut values__ = None;
                let mut args_hash__ = None;
                let mut task_binding__ = None;
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
                        GeneratedField::ConversationId => {
                            if conversation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversationId"));
                            }
                            conversation_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SurfaceId => {
                            if surface_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("surfaceId"));
                            }
                            surface_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Version => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::SurfaceHash => {
                            if surface_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("surfaceHash"));
                            }
                            surface_hash__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ActionId => {
                            if action_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("actionId"));
                            }
                            action_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Values => {
                            if values__.is_some() {
                                return Err(serde::de::Error::duplicate_field("values"));
                            }
                            values__ = map_.next_value()?;
                        }
                        GeneratedField::ArgsHash => {
                            if args_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("argsHash"));
                            }
                            args_hash__ = Some(map_.next_value()?);
                        }
                        GeneratedField::TaskBinding => {
                            if task_binding__.is_some() {
                                return Err(serde::de::Error::duplicate_field("taskBinding"));
                            }
                            task_binding__ = map_.next_value()?;
                        }
                    }
                }
                Ok(SurfaceAction {
                    schema: schema__.unwrap_or_default(),
                    conversation_id: conversation_id__.unwrap_or_default(),
                    surface_id: surface_id__.unwrap_or_default(),
                    version: version__.unwrap_or_default(),
                    surface_hash: surface_hash__.unwrap_or_default(),
                    action_id: action_id__.unwrap_or_default(),
                    values: values__,
                    args_hash: args_hash__.unwrap_or_default(),
                    task_binding: task_binding__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.SurfaceAction",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

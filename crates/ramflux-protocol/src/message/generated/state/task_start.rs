// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct TaskStart {
    #[prost(string, tag = "1")]
    pub task_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub conversation_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub requester: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub assignee: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub text: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "6")]
    pub constraints: ::core::option::Option<::prost::alloc::string::String>,
}
impl serde::Serialize for TaskStart {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.task_id.is_empty() {
            len += 1;
        }
        if !self.conversation_id.is_empty() {
            len += 1;
        }
        if !self.requester.is_empty() {
            len += 1;
        }
        if !self.assignee.is_empty() {
            len += 1;
        }
        if !self.text.is_empty() {
            len += 1;
        }
        if self.constraints.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.TaskStart", len)?;
        if !self.task_id.is_empty() {
            struct_ser.serialize_field("taskId", &self.task_id)?;
        }
        if !self.conversation_id.is_empty() {
            struct_ser.serialize_field("conversationId", &self.conversation_id)?;
        }
        if !self.requester.is_empty() {
            struct_ser.serialize_field("requester", &self.requester)?;
        }
        if !self.assignee.is_empty() {
            struct_ser.serialize_field("assignee", &self.assignee)?;
        }
        if !self.text.is_empty() {
            struct_ser.serialize_field("text", &self.text)?;
        }
        if let Some(v) = self.constraints.as_ref() {
            struct_ser.serialize_field("constraints", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskStart {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "task_id",
            "taskId",
            "conversation_id",
            "conversationId",
            "requester",
            "assignee",
            "text",
            "constraints",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            TaskId,
            ConversationId,
            Requester,
            Assignee,
            Text,
            Constraints,
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
                            "taskId" | "task_id" => Ok(GeneratedField::TaskId),
                            "conversationId" | "conversation_id" => {
                                Ok(GeneratedField::ConversationId)
                            }
                            "requester" => Ok(GeneratedField::Requester),
                            "assignee" => Ok(GeneratedField::Assignee),
                            "text" => Ok(GeneratedField::Text),
                            "constraints" => Ok(GeneratedField::Constraints),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskStart;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskStart")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskStart, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut task_id__ = None;
                let mut conversation_id__ = None;
                let mut requester__ = None;
                let mut assignee__ = None;
                let mut text__ = None;
                let mut constraints__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::TaskId => {
                            if task_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("taskId"));
                            }
                            task_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ConversationId => {
                            if conversation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversationId"));
                            }
                            conversation_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Requester => {
                            if requester__.is_some() {
                                return Err(serde::de::Error::duplicate_field("requester"));
                            }
                            requester__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Assignee => {
                            if assignee__.is_some() {
                                return Err(serde::de::Error::duplicate_field("assignee"));
                            }
                            assignee__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Text => {
                            if text__.is_some() {
                                return Err(serde::de::Error::duplicate_field("text"));
                            }
                            text__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Constraints => {
                            if constraints__.is_some() {
                                return Err(serde::de::Error::duplicate_field("constraints"));
                            }
                            constraints__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TaskStart {
                    task_id: task_id__.unwrap_or_default(),
                    conversation_id: conversation_id__.unwrap_or_default(),
                    requester: requester__.unwrap_or_default(),
                    assignee: assignee__.unwrap_or_default(),
                    text: text__.unwrap_or_default(),
                    constraints: constraints__,
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.TaskStart", FIELDS, GeneratedVisitor)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaskProposal {
    #[prost(string, tag = "1")]
    pub task_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub conversation_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub proposer: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub assignee: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub title: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "6")]
    pub steps: ::prost::alloc::vec::Vec<TaskStep>,
}
impl serde::Serialize for TaskProposal {
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
        if !self.proposer.is_empty() {
            len += 1;
        }
        if !self.assignee.is_empty() {
            len += 1;
        }
        if !self.title.is_empty() {
            len += 1;
        }
        if !self.steps.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.TaskProposal", len)?;
        if !self.task_id.is_empty() {
            struct_ser.serialize_field("taskId", &self.task_id)?;
        }
        if !self.conversation_id.is_empty() {
            struct_ser.serialize_field("conversationId", &self.conversation_id)?;
        }
        if !self.proposer.is_empty() {
            struct_ser.serialize_field("proposer", &self.proposer)?;
        }
        if !self.assignee.is_empty() {
            struct_ser.serialize_field("assignee", &self.assignee)?;
        }
        if !self.title.is_empty() {
            struct_ser.serialize_field("title", &self.title)?;
        }
        if !self.steps.is_empty() {
            struct_ser.serialize_field("steps", &self.steps)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskProposal {
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
            "proposer",
            "assignee",
            "title",
            "steps",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            TaskId,
            ConversationId,
            Proposer,
            Assignee,
            Title,
            Steps,
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
                            "proposer" => Ok(GeneratedField::Proposer),
                            "assignee" => Ok(GeneratedField::Assignee),
                            "title" => Ok(GeneratedField::Title),
                            "steps" => Ok(GeneratedField::Steps),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskProposal;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskProposal")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskProposal, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut task_id__ = None;
                let mut conversation_id__ = None;
                let mut proposer__ = None;
                let mut assignee__ = None;
                let mut title__ = None;
                let mut steps__ = None;
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
                        GeneratedField::Proposer => {
                            if proposer__.is_some() {
                                return Err(serde::de::Error::duplicate_field("proposer"));
                            }
                            proposer__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Assignee => {
                            if assignee__.is_some() {
                                return Err(serde::de::Error::duplicate_field("assignee"));
                            }
                            assignee__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Title => {
                            if title__.is_some() {
                                return Err(serde::de::Error::duplicate_field("title"));
                            }
                            title__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Steps => {
                            if steps__.is_some() {
                                return Err(serde::de::Error::duplicate_field("steps"));
                            }
                            steps__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(TaskProposal {
                    task_id: task_id__.unwrap_or_default(),
                    conversation_id: conversation_id__.unwrap_or_default(),
                    proposer: proposer__.unwrap_or_default(),
                    assignee: assignee__.unwrap_or_default(),
                    title: title__.unwrap_or_default(),
                    steps: steps__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.TaskProposal", FIELDS, GeneratedVisitor)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct TaskApprovalBinding {
    #[prost(string, tag = "1")]
    pub conversation_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub task_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub step_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub opening_revision: u64,
    #[prost(string, tag = "5")]
    pub requester: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub assignee: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub executor_device_id: ::prost::alloc::string::String,
}
impl serde::Serialize for TaskApprovalBinding {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.conversation_id.is_empty() {
            len += 1;
        }
        if !self.task_id.is_empty() {
            len += 1;
        }
        if !self.step_id.is_empty() {
            len += 1;
        }
        if self.opening_revision != 0 {
            len += 1;
        }
        if !self.requester.is_empty() {
            len += 1;
        }
        if !self.assignee.is_empty() {
            len += 1;
        }
        if !self.executor_device_id.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.TaskApprovalBinding", len)?;
        if !self.conversation_id.is_empty() {
            struct_ser.serialize_field("conversationId", &self.conversation_id)?;
        }
        if !self.task_id.is_empty() {
            struct_ser.serialize_field("taskId", &self.task_id)?;
        }
        if !self.step_id.is_empty() {
            struct_ser.serialize_field("stepId", &self.step_id)?;
        }
        if self.opening_revision != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "openingRevision",
                ToString::to_string(&self.opening_revision).as_str(),
            )?;
        }
        if !self.requester.is_empty() {
            struct_ser.serialize_field("requester", &self.requester)?;
        }
        if !self.assignee.is_empty() {
            struct_ser.serialize_field("assignee", &self.assignee)?;
        }
        if !self.executor_device_id.is_empty() {
            struct_ser.serialize_field("executorDeviceId", &self.executor_device_id)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskApprovalBinding {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "conversation_id",
            "conversationId",
            "task_id",
            "taskId",
            "step_id",
            "stepId",
            "opening_revision",
            "openingRevision",
            "requester",
            "assignee",
            "executor_device_id",
            "executorDeviceId",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            ConversationId,
            TaskId,
            StepId,
            OpeningRevision,
            Requester,
            Assignee,
            ExecutorDeviceId,
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
                            "conversationId" | "conversation_id" => {
                                Ok(GeneratedField::ConversationId)
                            }
                            "taskId" | "task_id" => Ok(GeneratedField::TaskId),
                            "stepId" | "step_id" => Ok(GeneratedField::StepId),
                            "openingRevision" | "opening_revision" => {
                                Ok(GeneratedField::OpeningRevision)
                            }
                            "requester" => Ok(GeneratedField::Requester),
                            "assignee" => Ok(GeneratedField::Assignee),
                            "executorDeviceId" | "executor_device_id" => {
                                Ok(GeneratedField::ExecutorDeviceId)
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
            type Value = TaskApprovalBinding;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskApprovalBinding")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskApprovalBinding, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut conversation_id__ = None;
                let mut task_id__ = None;
                let mut step_id__ = None;
                let mut opening_revision__ = None;
                let mut requester__ = None;
                let mut assignee__ = None;
                let mut executor_device_id__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::ConversationId => {
                            if conversation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversationId"));
                            }
                            conversation_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::TaskId => {
                            if task_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("taskId"));
                            }
                            task_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::StepId => {
                            if step_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("stepId"));
                            }
                            step_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::OpeningRevision => {
                            if opening_revision__.is_some() {
                                return Err(serde::de::Error::duplicate_field("openingRevision"));
                            }
                            opening_revision__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
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
                        GeneratedField::ExecutorDeviceId => {
                            if executor_device_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("executorDeviceId"));
                            }
                            executor_device_id__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(TaskApprovalBinding {
                    conversation_id: conversation_id__.unwrap_or_default(),
                    task_id: task_id__.unwrap_or_default(),
                    step_id: step_id__.unwrap_or_default(),
                    opening_revision: opening_revision__.unwrap_or_default(),
                    requester: requester__.unwrap_or_default(),
                    assignee: assignee__.unwrap_or_default(),
                    executor_device_id: executor_device_id__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.TaskApprovalBinding",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

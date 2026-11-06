// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaskUpdate {
    #[prost(string, tag = "1")]
    pub task_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub version: u64,
    #[prost(message, optional, tag = "3")]
    pub state: ::core::option::Option<TaskStatus>,
    #[prost(message, repeated, tag = "4")]
    pub steps: ::prost::alloc::vec::Vec<TaskStep>,
    #[prost(string, optional, tag = "5")]
    pub result_ref: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "6")]
    pub result_summary: ::core::option::Option<::prost::alloc::string::String>,
}
impl serde::Serialize for TaskUpdate {
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
        if self.version != 0 {
            len += 1;
        }
        if self.state.is_some() {
            len += 1;
        }
        if !self.steps.is_empty() {
            len += 1;
        }
        if self.result_ref.is_some() {
            len += 1;
        }
        if self.result_summary.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.TaskUpdate", len)?;
        if !self.task_id.is_empty() {
            struct_ser.serialize_field("taskId", &self.task_id)?;
        }
        if self.version != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("version", ToString::to_string(&self.version).as_str())?;
        }
        if let Some(v) = self.state.as_ref() {
            struct_ser.serialize_field("state", v)?;
        }
        if !self.steps.is_empty() {
            struct_ser.serialize_field("steps", &self.steps)?;
        }
        if let Some(v) = self.result_ref.as_ref() {
            struct_ser.serialize_field("resultRef", v)?;
        }
        if let Some(v) = self.result_summary.as_ref() {
            struct_ser.serialize_field("resultSummary", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskUpdate {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "task_id",
            "taskId",
            "version",
            "state",
            "steps",
            "result_ref",
            "resultRef",
            "result_summary",
            "resultSummary",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            TaskId,
            Version,
            State,
            Steps,
            ResultRef,
            ResultSummary,
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
                            "version" => Ok(GeneratedField::Version),
                            "state" => Ok(GeneratedField::State),
                            "steps" => Ok(GeneratedField::Steps),
                            "resultRef" | "result_ref" => Ok(GeneratedField::ResultRef),
                            "resultSummary" | "result_summary" => Ok(GeneratedField::ResultSummary),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskUpdate;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskUpdate")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskUpdate, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut task_id__ = None;
                let mut version__ = None;
                let mut state__ = None;
                let mut steps__ = None;
                let mut result_ref__ = None;
                let mut result_summary__ = None;
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
                        GeneratedField::Version => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::State => {
                            if state__.is_some() {
                                return Err(serde::de::Error::duplicate_field("state"));
                            }
                            state__ = map_.next_value()?;
                        }
                        GeneratedField::Steps => {
                            if steps__.is_some() {
                                return Err(serde::de::Error::duplicate_field("steps"));
                            }
                            steps__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ResultRef => {
                            if result_ref__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resultRef"));
                            }
                            result_ref__ = map_.next_value()?;
                        }
                        GeneratedField::ResultSummary => {
                            if result_summary__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resultSummary"));
                            }
                            result_summary__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TaskUpdate {
                    task_id: task_id__.unwrap_or_default(),
                    version: version__.unwrap_or_default(),
                    state: state__,
                    steps: steps__.unwrap_or_default(),
                    result_ref: result_ref__,
                    result_summary: result_summary__,
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.TaskUpdate", FIELDS, GeneratedVisitor)
    }
}

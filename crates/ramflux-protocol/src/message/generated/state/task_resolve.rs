// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct TaskResolve {
    #[prost(string, tag = "1")]
    pub task_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub base_revision: u64,
    #[prost(string, tag = "3")]
    pub step_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub target: ::core::option::Option<NeedsMe>,
    #[prost(string, tag = "5")]
    pub decision_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "6")]
    pub decision: ::core::option::Option<TaskDecision>,
}
impl serde::Serialize for TaskResolve {
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
        if self.base_revision != 0 {
            len += 1;
        }
        if !self.step_id.is_empty() {
            len += 1;
        }
        if self.target.is_some() {
            len += 1;
        }
        if !self.decision_id.is_empty() {
            len += 1;
        }
        if self.decision.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.TaskResolve", len)?;
        if !self.task_id.is_empty() {
            struct_ser.serialize_field("taskId", &self.task_id)?;
        }
        if self.base_revision != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "baseRevision",
                ToString::to_string(&self.base_revision).as_str(),
            )?;
        }
        if !self.step_id.is_empty() {
            struct_ser.serialize_field("stepId", &self.step_id)?;
        }
        if let Some(v) = self.target.as_ref() {
            struct_ser.serialize_field("target", v)?;
        }
        if !self.decision_id.is_empty() {
            struct_ser.serialize_field("decisionId", &self.decision_id)?;
        }
        if let Some(v) = self.decision.as_ref() {
            struct_ser.serialize_field("decision", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskResolve {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "task_id",
            "taskId",
            "base_revision",
            "baseRevision",
            "step_id",
            "stepId",
            "target",
            "decision_id",
            "decisionId",
            "decision",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            TaskId,
            BaseRevision,
            StepId,
            Target,
            DecisionId,
            Decision,
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
                            "baseRevision" | "base_revision" => Ok(GeneratedField::BaseRevision),
                            "stepId" | "step_id" => Ok(GeneratedField::StepId),
                            "target" => Ok(GeneratedField::Target),
                            "decisionId" | "decision_id" => Ok(GeneratedField::DecisionId),
                            "decision" => Ok(GeneratedField::Decision),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskResolve;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskResolve")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskResolve, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut task_id__ = None;
                let mut base_revision__ = None;
                let mut step_id__ = None;
                let mut target__ = None;
                let mut decision_id__ = None;
                let mut decision__ = None;
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
                        GeneratedField::BaseRevision => {
                            if base_revision__.is_some() {
                                return Err(serde::de::Error::duplicate_field("baseRevision"));
                            }
                            base_revision__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::StepId => {
                            if step_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("stepId"));
                            }
                            step_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Target => {
                            if target__.is_some() {
                                return Err(serde::de::Error::duplicate_field("target"));
                            }
                            target__ = map_.next_value()?;
                        }
                        GeneratedField::DecisionId => {
                            if decision_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("decisionId"));
                            }
                            decision_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Decision => {
                            if decision__.is_some() {
                                return Err(serde::de::Error::duplicate_field("decision"));
                            }
                            decision__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TaskResolve {
                    task_id: task_id__.unwrap_or_default(),
                    base_revision: base_revision__.unwrap_or_default(),
                    step_id: step_id__.unwrap_or_default(),
                    target: target__,
                    decision_id: decision_id__.unwrap_or_default(),
                    decision: decision__,
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.TaskResolve", FIELDS, GeneratedVisitor)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Message)]
pub struct RecoveryQuorumMemberKind {
    #[prost(oneof = "recovery_quorum_member_kind::Value", tags = "1, 2, 3, 4")]
    pub value: ::core::option::Option<recovery_quorum_member_kind::Value>,
}
/// Nested message and enum types in `RecoveryQuorumMemberKind`.
pub mod recovery_quorum_member_kind {
    #[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "1")]
        RootShare(super::RecoveryQuorumMemberKindRootShare),
        #[prost(message, tag = "2")]
        DeviceShare(super::RecoveryQuorumMemberKindDeviceShare),
        #[prost(message, tag = "3")]
        GuardianShare(super::RecoveryQuorumMemberKindGuardianShare),
        #[prost(message, tag = "4")]
        HardwareTokenShare(super::RecoveryQuorumMemberKindHardwareTokenShare),
    }
}
impl serde::Serialize for RecoveryQuorumMemberKind {
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
            serializer.serialize_struct("ramflux.message.v1.RecoveryQuorumMemberKind", len)?;
        if let Some(v) = self.value.as_ref() {
            match v {
                recovery_quorum_member_kind::Value::RootShare(v) => {
                    struct_ser.serialize_field("rootShare", v)?;
                }
                recovery_quorum_member_kind::Value::DeviceShare(v) => {
                    struct_ser.serialize_field("deviceShare", v)?;
                }
                recovery_quorum_member_kind::Value::GuardianShare(v) => {
                    struct_ser.serialize_field("guardianShare", v)?;
                }
                recovery_quorum_member_kind::Value::HardwareTokenShare(v) => {
                    struct_ser.serialize_field("hardwareTokenShare", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for RecoveryQuorumMemberKind {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "root_share",
            "rootShare",
            "device_share",
            "deviceShare",
            "guardian_share",
            "guardianShare",
            "hardware_token_share",
            "hardwareTokenShare",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            RootShare,
            DeviceShare,
            GuardianShare,
            HardwareTokenShare,
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
                            "rootShare" | "root_share" => Ok(GeneratedField::RootShare),
                            "deviceShare" | "device_share" => Ok(GeneratedField::DeviceShare),
                            "guardianShare" | "guardian_share" => Ok(GeneratedField::GuardianShare),
                            "hardwareTokenShare" | "hardware_token_share" => {
                                Ok(GeneratedField::HardwareTokenShare)
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
            type Value = RecoveryQuorumMemberKind;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.RecoveryQuorumMemberKind")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<RecoveryQuorumMemberKind, V::Error>
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
                        GeneratedField::RootShare => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("rootShare"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(recovery_quorum_member_kind::Value::RootShare);
                        }
                        GeneratedField::DeviceShare => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("deviceShare"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(recovery_quorum_member_kind::Value::DeviceShare);
                        }
                        GeneratedField::GuardianShare => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("guardianShare"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(recovery_quorum_member_kind::Value::GuardianShare);
                        }
                        GeneratedField::HardwareTokenShare => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "hardwareTokenShare",
                                ));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(recovery_quorum_member_kind::Value::HardwareTokenShare);
                        }
                    }
                }
                Ok(RecoveryQuorumMemberKind { value: value__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.RecoveryQuorumMemberKind",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

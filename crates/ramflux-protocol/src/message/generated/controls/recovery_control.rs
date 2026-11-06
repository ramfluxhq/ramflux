// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct RecoveryControl {
    #[prost(oneof = "recovery_control::Payload", tags = "1, 2")]
    pub payload: ::core::option::Option<recovery_control::Payload>,
}
/// Nested message and enum types in `RecoveryControl`.
pub mod recovery_control {
    #[derive(Clone, PartialEq, Eq, Hash, ::prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "1")]
        Invite(super::GuardianInvite),
        #[prost(message, tag = "2")]
        Accept(super::GuardianAccept),
    }
}
impl serde::Serialize for RecoveryControl {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.payload.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.RecoveryControl", len)?;
        if let Some(v) = self.payload.as_ref() {
            match v {
                recovery_control::Payload::Invite(v) => {
                    struct_ser.serialize_field("invite", v)?;
                }
                recovery_control::Payload::Accept(v) => {
                    struct_ser.serialize_field("accept", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for RecoveryControl {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["invite", "accept"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Invite,
            Accept,
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
                            "invite" => Ok(GeneratedField::Invite),
                            "accept" => Ok(GeneratedField::Accept),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = RecoveryControl;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.RecoveryControl")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<RecoveryControl, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut payload__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Invite => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("invite"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(recovery_control::Payload::Invite);
                        }
                        GeneratedField::Accept => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("accept"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(recovery_control::Payload::Accept);
                        }
                    }
                }
                Ok(RecoveryControl { payload: payload__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.RecoveryControl",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

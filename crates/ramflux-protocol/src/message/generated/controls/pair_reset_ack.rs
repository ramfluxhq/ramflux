// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Message)]
pub struct PairResetAck {
    #[prost(uint64, tag = "1")]
    pub rejected_bootstrap_floor: u64,
}
impl serde::Serialize for PairResetAck {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.rejected_bootstrap_floor != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.PairResetAck", len)?;
        if self.rejected_bootstrap_floor != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "rejectedBootstrapFloor",
                ToString::to_string(&self.rejected_bootstrap_floor).as_str(),
            )?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for PairResetAck {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["rejected_bootstrap_floor", "rejectedBootstrapFloor"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            RejectedBootstrapFloor,
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
                            "rejectedBootstrapFloor" | "rejected_bootstrap_floor" => {
                                Ok(GeneratedField::RejectedBootstrapFloor)
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
            type Value = PairResetAck;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.PairResetAck")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<PairResetAck, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut rejected_bootstrap_floor__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::RejectedBootstrapFloor => {
                            if rejected_bootstrap_floor__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "rejectedBootstrapFloor",
                                ));
                            }
                            rejected_bootstrap_floor__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(PairResetAck {
                    rejected_bootstrap_floor: rejected_bootstrap_floor__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.PairResetAck", FIELDS, GeneratedVisitor)
    }
}

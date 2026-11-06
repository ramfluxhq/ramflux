// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct ContactControl {
    #[prost(message, optional, tag = "1")]
    pub consent: ::core::option::Option<NativeContactConsent>,
}
impl serde::Serialize for ContactControl {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.consent.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.ContactControl", len)?;
        if let Some(v) = self.consent.as_ref() {
            struct_ser.serialize_field("consent", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ContactControl {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["consent"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Consent,
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
                            "consent" => Ok(GeneratedField::Consent),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ContactControl;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.ContactControl")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<ContactControl, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut consent__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Consent => {
                            if consent__.is_some() {
                                return Err(serde::de::Error::duplicate_field("consent"));
                            }
                            consent__ = map_.next_value()?;
                        }
                    }
                }
                Ok(ContactControl { consent: consent__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.ContactControl",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

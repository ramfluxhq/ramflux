// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct SignedFields {
    #[prost(string, tag = "1")]
    pub signing_key_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub signature_alg: ::core::option::Option<SignatureAlg>,
    #[prost(string, tag = "3")]
    pub signature: ::prost::alloc::string::String,
}
impl serde::Serialize for SignedFields {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.signing_key_id.is_empty() {
            len += 1;
        }
        if self.signature_alg.is_some() {
            len += 1;
        }
        if !self.signature.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.SignedFields", len)?;
        if !self.signing_key_id.is_empty() {
            struct_ser.serialize_field("signingKeyId", &self.signing_key_id)?;
        }
        if let Some(v) = self.signature_alg.as_ref() {
            struct_ser.serialize_field("signatureAlg", v)?;
        }
        if !self.signature.is_empty() {
            struct_ser.serialize_field("signature", &self.signature)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SignedFields {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["signing_key_id", "signingKeyId", "signature_alg", "signatureAlg", "signature"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            SigningKeyId,
            SignatureAlg,
            Signature,
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
                            "signingKeyId" | "signing_key_id" => Ok(GeneratedField::SigningKeyId),
                            "signatureAlg" | "signature_alg" => Ok(GeneratedField::SignatureAlg),
                            "signature" => Ok(GeneratedField::Signature),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SignedFields;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SignedFields")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SignedFields, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut signing_key_id__ = None;
                let mut signature_alg__ = None;
                let mut signature__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::SigningKeyId => {
                            if signing_key_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signingKeyId"));
                            }
                            signing_key_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SignatureAlg => {
                            if signature_alg__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signatureAlg"));
                            }
                            signature_alg__ = map_.next_value()?;
                        }
                        GeneratedField::Signature => {
                            if signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(SignedFields {
                    signing_key_id: signing_key_id__.unwrap_or_default(),
                    signature_alg: signature_alg__,
                    signature: signature__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.SignedFields", FIELDS, GeneratedVisitor)
    }
}

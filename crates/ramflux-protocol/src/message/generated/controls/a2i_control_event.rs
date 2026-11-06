// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct A2iControlEvent {
    #[prost(string, tag = "1")]
    pub schema: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub version: u32,
    #[prost(string, tag = "3")]
    pub domain: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub ext: ::core::option::Option<Ext>,
    #[prost(message, optional, tag = "5")]
    pub signed: ::core::option::Option<SignedFields>,
    #[prost(message, optional, tag = "6")]
    pub event_type: ::core::option::Option<A2iControlEventType>,
    #[prost(message, optional, tag = "7")]
    pub control_domain: ::core::option::Option<ControlDomain>,
    #[prost(string, tag = "8")]
    pub action: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "9")]
    pub subject: ::core::option::Option<JsonValue>,
    #[prost(string, tag = "10")]
    pub correlation_id: ::prost::alloc::string::String,
    #[prost(string, tag = "11")]
    pub source_device_id: ::prost::alloc::string::String,
    #[prost(string, tag = "12")]
    pub target_device_id: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "13")]
    pub grant_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag = "14")]
    pub expires_at: ::core::option::Option<i64>,
}
impl serde::Serialize for A2iControlEvent {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.schema.is_empty() {
            len += 1;
        }
        if self.version != 0 {
            len += 1;
        }
        if !self.domain.is_empty() {
            len += 1;
        }
        if self.ext.is_some() {
            len += 1;
        }
        if self.signed.is_some() {
            len += 1;
        }
        if self.event_type.is_some() {
            len += 1;
        }
        if self.control_domain.is_some() {
            len += 1;
        }
        if !self.action.is_empty() {
            len += 1;
        }
        if self.subject.is_some() {
            len += 1;
        }
        if !self.correlation_id.is_empty() {
            len += 1;
        }
        if !self.source_device_id.is_empty() {
            len += 1;
        }
        if !self.target_device_id.is_empty() {
            len += 1;
        }
        if self.grant_id.is_some() {
            len += 1;
        }
        if self.expires_at.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.A2iControlEvent", len)?;
        if !self.schema.is_empty() {
            struct_ser.serialize_field("schema", &self.schema)?;
        }
        if self.version != 0 {
            struct_ser.serialize_field("version", &self.version)?;
        }
        if !self.domain.is_empty() {
            struct_ser.serialize_field("domain", &self.domain)?;
        }
        if let Some(v) = self.ext.as_ref() {
            struct_ser.serialize_field("ext", v)?;
        }
        if let Some(v) = self.signed.as_ref() {
            struct_ser.serialize_field("signed", v)?;
        }
        if let Some(v) = self.event_type.as_ref() {
            struct_ser.serialize_field("eventType", v)?;
        }
        if let Some(v) = self.control_domain.as_ref() {
            struct_ser.serialize_field("controlDomain", v)?;
        }
        if !self.action.is_empty() {
            struct_ser.serialize_field("action", &self.action)?;
        }
        if let Some(v) = self.subject.as_ref() {
            struct_ser.serialize_field("subject", v)?;
        }
        if !self.correlation_id.is_empty() {
            struct_ser.serialize_field("correlationId", &self.correlation_id)?;
        }
        if !self.source_device_id.is_empty() {
            struct_ser.serialize_field("sourceDeviceId", &self.source_device_id)?;
        }
        if !self.target_device_id.is_empty() {
            struct_ser.serialize_field("targetDeviceId", &self.target_device_id)?;
        }
        if let Some(v) = self.grant_id.as_ref() {
            struct_ser.serialize_field("grantId", v)?;
        }
        if let Some(v) = self.expires_at.as_ref() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("expiresAt", ToString::to_string(&v).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for A2iControlEvent {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "schema",
            "version",
            "domain",
            "ext",
            "signed",
            "event_type",
            "eventType",
            "control_domain",
            "controlDomain",
            "action",
            "subject",
            "correlation_id",
            "correlationId",
            "source_device_id",
            "sourceDeviceId",
            "target_device_id",
            "targetDeviceId",
            "grant_id",
            "grantId",
            "expires_at",
            "expiresAt",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Schema,
            Version,
            Domain,
            Ext,
            Signed,
            EventType,
            ControlDomain,
            Action,
            Subject,
            CorrelationId,
            SourceDeviceId,
            TargetDeviceId,
            GrantId,
            ExpiresAt,
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
                            "schema" => Ok(GeneratedField::Schema),
                            "version" => Ok(GeneratedField::Version),
                            "domain" => Ok(GeneratedField::Domain),
                            "ext" => Ok(GeneratedField::Ext),
                            "signed" => Ok(GeneratedField::Signed),
                            "eventType" | "event_type" => Ok(GeneratedField::EventType),
                            "controlDomain" | "control_domain" => Ok(GeneratedField::ControlDomain),
                            "action" => Ok(GeneratedField::Action),
                            "subject" => Ok(GeneratedField::Subject),
                            "correlationId" | "correlation_id" => Ok(GeneratedField::CorrelationId),
                            "sourceDeviceId" | "source_device_id" => {
                                Ok(GeneratedField::SourceDeviceId)
                            }
                            "targetDeviceId" | "target_device_id" => {
                                Ok(GeneratedField::TargetDeviceId)
                            }
                            "grantId" | "grant_id" => Ok(GeneratedField::GrantId),
                            "expiresAt" | "expires_at" => Ok(GeneratedField::ExpiresAt),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = A2iControlEvent;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.A2iControlEvent")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<A2iControlEvent, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut schema__ = None;
                let mut version__ = None;
                let mut domain__ = None;
                let mut ext__ = None;
                let mut signed__ = None;
                let mut event_type__ = None;
                let mut control_domain__ = None;
                let mut action__ = None;
                let mut subject__ = None;
                let mut correlation_id__ = None;
                let mut source_device_id__ = None;
                let mut target_device_id__ = None;
                let mut grant_id__ = None;
                let mut expires_at__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Schema => {
                            if schema__.is_some() {
                                return Err(serde::de::Error::duplicate_field("schema"));
                            }
                            schema__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Version => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Domain => {
                            if domain__.is_some() {
                                return Err(serde::de::Error::duplicate_field("domain"));
                            }
                            domain__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Ext => {
                            if ext__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ext"));
                            }
                            ext__ = map_.next_value()?;
                        }
                        GeneratedField::Signed => {
                            if signed__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signed"));
                            }
                            signed__ = map_.next_value()?;
                        }
                        GeneratedField::EventType => {
                            if event_type__.is_some() {
                                return Err(serde::de::Error::duplicate_field("eventType"));
                            }
                            event_type__ = map_.next_value()?;
                        }
                        GeneratedField::ControlDomain => {
                            if control_domain__.is_some() {
                                return Err(serde::de::Error::duplicate_field("controlDomain"));
                            }
                            control_domain__ = map_.next_value()?;
                        }
                        GeneratedField::Action => {
                            if action__.is_some() {
                                return Err(serde::de::Error::duplicate_field("action"));
                            }
                            action__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Subject => {
                            if subject__.is_some() {
                                return Err(serde::de::Error::duplicate_field("subject"));
                            }
                            subject__ = map_.next_value()?;
                        }
                        GeneratedField::CorrelationId => {
                            if correlation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("correlationId"));
                            }
                            correlation_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SourceDeviceId => {
                            if source_device_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sourceDeviceId"));
                            }
                            source_device_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::TargetDeviceId => {
                            if target_device_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("targetDeviceId"));
                            }
                            target_device_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::GrantId => {
                            if grant_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("grantId"));
                            }
                            grant_id__ = map_.next_value()?;
                        }
                        GeneratedField::ExpiresAt => {
                            if expires_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("expiresAt"));
                            }
                            expires_at__ = map_
                                .next_value::<
                                    ::std::option::Option<
                                        ::pbjson::private::NumberDeserialize<_>,
                                    >,
                                >()?
                                .map(|x| x.0);
                        }
                    }
                }
                Ok(A2iControlEvent {
                    schema: schema__.unwrap_or_default(),
                    version: version__.unwrap_or_default(),
                    domain: domain__.unwrap_or_default(),
                    ext: ext__,
                    signed: signed__,
                    event_type: event_type__,
                    control_domain: control_domain__,
                    action: action__.unwrap_or_default(),
                    subject: subject__,
                    correlation_id: correlation_id__.unwrap_or_default(),
                    source_device_id: source_device_id__.unwrap_or_default(),
                    target_device_id: target_device_id__.unwrap_or_default(),
                    grant_id: grant_id__,
                    expires_at: expires_at__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.A2iControlEvent",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

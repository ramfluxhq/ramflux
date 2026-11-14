// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refuse restore counts during deserialization, before accumulating an oversized collection.
use ramflux_protocol::contact_reach::StateRecord;
use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeMap, fmt};
const LIMIT: usize = 8192;

pub(in crate::account_db) fn records<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<StateRecord>, D::Error> {
    struct Records;
    impl<'de> Visitor<'de> for Records {
        type Value = Vec<StateRecord>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 8192 retained reach records")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|count| count > LIMIT) {
                return Err(A::Error::custom("reach record capacity"));
            }
            let mut records = Vec::new();
            while let Some(record) = sequence.next_element()? {
                if records.len() >= LIMIT {
                    return Err(A::Error::custom("reach record capacity"));
                }
                records.push(record);
            }
            Ok(records)
        }
    }
    decoder.deserialize_seq(Records)
}
pub(in crate::account_db) fn restrictions<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<BTreeMap<String, StateRecord>, D::Error> {
    struct Restrictions;
    impl<'de> Visitor<'de> for Restrictions {
        type Value = BTreeMap<String, StateRecord>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 8192 independent reach restrictions")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            if map.size_hint().is_some_and(|count| count > LIMIT) {
                return Err(A::Error::custom("reach restriction capacity"));
            }
            let mut restrictions = BTreeMap::new();
            while let Some((key, record)) = map.next_entry()? {
                if restrictions.len() >= LIMIT || restrictions.insert(key, record).is_some() {
                    return Err(A::Error::custom("reach restriction capacity or duplicate"));
                }
            }
            Ok(restrictions)
        }
    }
    decoder.deserialize_map(Restrictions)
}

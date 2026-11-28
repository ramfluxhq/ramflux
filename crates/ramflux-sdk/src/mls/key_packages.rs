// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `KeyPackage` publication and fetch (spec §3.5): wire types of the four gateway frames, the
//! top-up plan (publish ≤ 50, hold ≤ 100, refill below 20) and the checked fetch.
//!
//! The wire types mirror `ramflux-node-core::router_store::key_packages` field by field; the
//! gateway answers `Nack mls_dm_frames_unsupported` until the node wires the frames, which every
//! driver here reports as [`TopUpOutcome::NotYetAvailable`] / [`FetchOutcome::NotYetAvailable`].
#![allow(dead_code, reason = "MLS: allowance removed in D5")]

use ramflux_mls::{GroupKind, Mls, MlsKv};
use serde::{Deserialize, Serialize};

use super::order::is_not_yet_available;
use crate::SdkError;
use crate::gateway::access::MlsFrameAccess;

/// Most one-time `KeyPackages` in one publish.
pub(crate) const PUBLISH_ONE_TIME_MAX: usize = 50;
/// Most one-time `KeyPackages` the node holds per device.
pub(crate) const ONE_TIME_STORED_MAX: usize = 100;
/// Below this many stored one-time `KeyPackages` the device tops up.
pub(crate) const TOP_UP_BELOW: usize = 20;
/// Stored count a top-up aims for.
pub(crate) const REFILL_TARGET: usize = 50;
/// Largest `KeyPackage` the node accepts or a fetch hands out.
pub(crate) const KEY_PACKAGE_MAX_BYTES: usize = 64 * 1024;
/// Most devices one fetch answer may name.
pub(crate) const FETCH_DEVICES_MAX: usize = 64;

/// Base64url form of binary fields in the JSON frames.
pub(crate) mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&ramflux_protocol::encode_base64url(value))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        ramflux_protocol::decode_base64url(&text).map_err(serde::de::Error::custom)
    }
}

/// A list of binary fields in the JSON frames.
mod b64_list {
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        values: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(&ramflux_protocol::encode_base64url(value))?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|text| ramflux_protocol::decode_base64url(text).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// An optional binary field in the JSON frames.
mod opt_b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option, reason = "serde `with` hands the field by reference")]
    pub(super) fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_str(&ramflux_protocol::encode_base64url(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| ramflux_protocol::decode_base64url(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Publish request of the authenticated device.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyPackagePublishRequest {
    /// One-time `KeyPackages` (at most 50).
    #[serde(default, with = "b64_list")]
    pub one_time: Vec<Vec<u8>>,
    /// The device's last-resort `KeyPackage`; replaces the stored one.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_b64")]
    pub last_resort: Option<Vec<u8>>,
}

/// Why a publish was refused.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPackageRefusal {
    /// More than 50 one-time `KeyPackages` in one publish, or nothing to store.
    BadCount,
    /// A `KeyPackage` is empty or over 64 KiB.
    BadSize,
    /// The device would hold more than 100 one-time `KeyPackages`.
    Quota,
    /// Malformed anchor or device id.
    BadDevice,
}

impl KeyPackageRefusal {
    const fn code(self) -> &'static str {
        match self {
            Self::BadCount => "key_package_bad_count",
            Self::BadSize => "key_package_bad_size",
            Self::Quota => "key_package_quota",
            Self::BadDevice => "key_package_bad_device",
        }
    }
}

/// What the node holds for this device.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyPackageStatusResponse {
    /// One-time `KeyPackages` stored.
    pub one_time: u32,
    /// A last-resort `KeyPackage` is stored.
    pub last_resort: bool,
    /// Fewer than 20 one-time `KeyPackages`: publish more.
    pub top_up: bool,
}

/// The answer to a publish.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum KeyPackagePublishOutcome {
    /// Stored.
    Stored {
        /// Stored state after the publish.
        status: KeyPackageStatusResponse,
    },
    /// Refused.
    Refused {
        /// Why.
        code: KeyPackageRefusal,
    },
}

/// One device's `KeyPackage` in a fetch answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FetchedKeyPackage {
    /// Device the `KeyPackage` belongs to.
    pub device_id: String,
    /// The `KeyPackage` (opaque).
    #[serde(with = "b64")]
    pub key_package: Vec<u8>,
    /// The last-resort (reusable) `KeyPackage` rather than a popped one-time one.
    pub last_resort: bool,
}

/// The answer to a fetch.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyPackageFetchResponse {
    /// One `KeyPackage` per device that has any.
    pub key_packages: Vec<FetchedKeyPackage>,
}

/// What a top-up publishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TopUpPlan {
    /// One-time `KeyPackages` to mint.
    pub(crate) one_time: usize,
    /// Mint and publish a last-resort `KeyPackage` too.
    pub(crate) last_resort: bool,
}

impl TopUpPlan {
    /// Nothing to publish.
    pub(crate) const fn is_empty(self) -> bool {
        self.one_time == 0 && !self.last_resort
    }
}

/// The publish plan for the node's answer to `KeyPackageStatus`. A device that never published
/// (`None`) starts with a full batch and a last-resort `KeyPackage`.
pub(crate) fn plan_top_up(status: Option<&KeyPackageStatusResponse>) -> TopUpPlan {
    let (stored, last_resort_stored) = status.map_or((0, false), |status| {
        (usize::try_from(status.one_time).unwrap_or(ONE_TIME_STORED_MAX), status.last_resort)
    });
    let one_time = if stored < TOP_UP_BELOW {
        REFILL_TARGET
            .saturating_sub(stored)
            .min(PUBLISH_ONE_TIME_MAX)
            .min(ONE_TIME_STORED_MAX.saturating_sub(stored))
    } else {
        0
    };
    TopUpPlan { one_time, last_resort: !last_resort_stored }
}

/// Mint the `KeyPackages` of `plan`. Each is its own staged operation, committed at once.
///
/// # Errors
/// Missing device identity, storage or provider failure.
pub(crate) fn mint<K: MlsKv>(
    mls: &Mls<K>,
    plan: TopUpPlan,
) -> Result<KeyPackagePublishRequest, SdkError> {
    let mut one_time = Vec::with_capacity(plan.one_time.min(PUBLISH_ONE_TIME_MAX));
    for _ in 0..plan.one_time.min(PUBLISH_ONE_TIME_MAX) {
        one_time.push(mint_one(mls)?);
    }
    let last_resort = if plan.last_resort { Some(mint_one(mls)?) } else { None };
    Ok(KeyPackagePublishRequest { one_time, last_resort })
}

fn mint_one<K: MlsKv>(mls: &Mls<K>) -> Result<Vec<u8>, SdkError> {
    let output =
        mls.key_package(GroupKind::Dm)?.commit_plain().map_err(ramflux_mls::MlsError::from)?;
    if output.bytes.len() > KEY_PACKAGE_MAX_BYTES {
        return Err(SdkError::Mls {
            code: "too_large",
            detail: "a minted KeyPackage exceeds the publish bound".to_owned(),
        });
    }
    Ok(output.bytes)
}

/// How a top-up ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TopUpOutcome {
    /// The node holds enough; nothing was published.
    Sufficient,
    /// Published; the node's state afterwards.
    Published(KeyPackageStatusResponse),
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// Ask the node what it holds and publish what the plan asks for.
///
/// # Errors
/// Gateway failures other than the not-yet-available answer, a refused publish, minting errors.
pub(crate) async fn top_up<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
) -> Result<TopUpOutcome, SdkError> {
    let status = match access.key_package_status().await {
        Ok(status) => Some(status),
        Err(error) if is_not_yet_available(&error) => return Ok(TopUpOutcome::NotYetAvailable),
        Err(error) => return Err(error),
    };
    let plan = plan_top_up(status.as_ref());
    if plan.is_empty() {
        return Ok(TopUpOutcome::Sufficient);
    }
    let request = mint(mls, plan)?;
    match access.publish_key_packages(request).await {
        Ok(KeyPackagePublishOutcome::Stored { status }) => Ok(TopUpOutcome::Published(status)),
        Ok(KeyPackagePublishOutcome::Refused { code }) => {
            Err(SdkError::Mls { code: code.code(), detail: format!("publish refused: {code:?}") })
        }
        Err(error) if is_not_yet_available(&error) => Ok(TopUpOutcome::NotYetAvailable),
        Err(error) => Err(error),
    }
}

/// How a fetch ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FetchOutcome {
    /// One checked `KeyPackage` per device.
    Fetched(Vec<FetchedKeyPackage>),
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// True the first time `owner` is seen.
fn first_of_owner(seen: &mut Vec<String>, owner: &str) -> bool {
    if seen.iter().any(|known| known == owner) {
        return false;
    }
    seen.push(owner.to_owned());
    true
}

/// Keep the entries the adder can use: non-empty, within the size bound, one per device, at most
/// [`FETCH_DEVICES_MAX`]. The lifetime and directory checks happen when the adder stages the Add
/// (rule V: only the adding device checks a `KeyPackage`'s lifetime).
pub(crate) fn check_fetched(response: KeyPackageFetchResponse) -> Vec<FetchedKeyPackage> {
    let mut seen: Vec<String> = Vec::new();
    response
        .key_packages
        .into_iter()
        .filter(|entry| {
            !entry.key_package.is_empty()
                && entry.key_package.len() <= KEY_PACKAGE_MAX_BYTES
                && first_of_owner(&mut seen, &entry.device_id)
        })
        .take(FETCH_DEVICES_MAX)
        .collect()
}

/// Fetch one `KeyPackage` per device of `anchor` from the own home.
///
/// # Errors
/// Gateway failures other than the not-yet-available answer.
pub(crate) async fn fetch(
    access: &mut impl MlsFrameAccess,
    anchor: &str,
) -> Result<FetchOutcome, SdkError> {
    match access.fetch_key_packages(anchor).await {
        Ok(response) => Ok(FetchOutcome::Fetched(check_fetched(response))),
        Err(error) if is_not_yet_available(&error) => Ok(FetchOutcome::NotYetAvailable),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(one_time: u32, last_resort: bool) -> KeyPackageStatusResponse {
        KeyPackageStatusResponse { one_time, last_resort, top_up: one_time < 20 }
    }

    #[test]
    fn first_publish_is_a_full_batch_with_last_resort() {
        let plan = plan_top_up(None);
        assert_eq!(plan, TopUpPlan { one_time: REFILL_TARGET, last_resort: true }, "fresh device");
    }

    #[test]
    fn enough_stored_publishes_nothing() {
        let plan = plan_top_up(Some(&status(20, true)));
        assert!(plan.is_empty(), "20 stored one-time packages and a last resort need no top-up");
    }

    #[test]
    fn below_threshold_refills_to_target() {
        let plan = plan_top_up(Some(&status(5, true)));
        assert_eq!(plan.one_time, REFILL_TARGET - 5, "refill up to the target");
        assert!(!plan.last_resort, "the stored last resort is kept");
    }

    #[test]
    fn missing_last_resort_is_republished() {
        let plan = plan_top_up(Some(&status(30, false)));
        assert_eq!(plan, TopUpPlan { one_time: 0, last_resort: true }, "only the last resort");
    }

    #[test]
    fn fetched_entries_are_deduplicated_and_bounded() {
        let entry = |device: &str, len: usize| FetchedKeyPackage {
            device_id: device.to_owned(),
            key_package: vec![1; len],
            last_resort: false,
        };
        let kept = check_fetched(KeyPackageFetchResponse {
            key_packages: vec![
                entry("a", 10),
                entry("a", 10),
                entry("b", 0),
                entry("c", KEY_PACKAGE_MAX_BYTES + 1),
                entry("d", KEY_PACKAGE_MAX_BYTES),
            ],
        });
        let devices: Vec<&str> = kept.iter().map(|entry| entry.device_id.as_str()).collect();
        assert_eq!(devices, ["a", "d"], "duplicates, empty and oversized entries are dropped");
    }
}

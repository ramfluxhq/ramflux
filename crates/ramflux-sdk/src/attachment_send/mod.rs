// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-scoped file prepare, one authored Inner, and import.
//! `large_attachments` stays off until an account record enables it.
//! The button uses the same prepare and import methods. It does not read the daemon
//! data directory, and it does not display the file key, the entries, or the capabilities.
//! It stays usable when this account's own layer declaration is absent or expired.

mod budget;
mod bus;
mod chunks;
mod codes;
mod digest;
mod grant_wrap;
mod handles;
pub(crate) mod hooks;
mod import_job;
#[cfg(test)]
mod listener;
mod meta;
mod owner_wire;
mod path_admit;
mod plane;
mod preflight;
mod publish;
mod seal;
mod scheduler;
mod seal_job;
#[cfg(test)]
mod section10;
mod store;
mod targets;

pub(crate) use bus::{AuthorityPin, authority, dispatch, open_store, plane_for, unix_now};
pub(crate) use codes::{
    CODE_AUTHORITY_UNAVAILABLE, CODE_CANCELLED, CODE_DUPLICATE, CODE_LAYOUT_INVALID,
    CODE_MANIFEST_TOO_LARGE, CODE_STREAM_CLOSED, Refusal, refusal_for,
};
pub use digest::PlaintextDigester;
pub(crate) use meta::{MAX_ATTACHMENTS, Phase, Recipient, Row};
pub(crate) use plane::{OwnerCall, Plane, ReadCall, RegisterCall, RetireCall};
pub(crate) use publish::{PublishInput, publish_all, upload_all, wrap_all};
pub(crate) use grant_wrap::{load as grants_of, stored_media};
pub(crate) use handles::remember_sent;
pub(crate) use store::Store;
pub(crate) use targets::{MediaDevice, MediaScope, choose_targets};

/// Account config directory record. Absent means the feature is off.
pub(crate) const CONFIG_DIRECTORY: &str = "config";
pub(crate) const CONFIG_ID: &str = "large_attachments";

#[must_use]
pub(crate) fn enabled_value(value: Option<&serde_json::Value>) -> bool {
    value.and_then(|row| row.get("enabled")).and_then(serde_json::Value::as_bool).unwrap_or(false)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Phone master ceremony. The recovery phrase is borrowed and never enters a bus payload.

use super::buffer;
use super::runtime::Client;
use super::{RamfluxV2Status, credential::UsernameParent};
use crate::SdkError;
use crate::username_directory::{
    SignedUsernameChange, UsernameChange, UsernameDraft, authorize_username_draft,
    configured_center,
};
use ramflux_protocol::username_directory::{DirectoryCode, NativeDirectoryPin};
use serde::Deserialize;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

const PUBLIC_LIMIT: usize = 64 * 1024;
const PHRASE_LIMIT: usize = 4096;
const DRAFT_LIFETIME_SECS: u64 = 300;

pub(super) struct AuthorizeInput {
    pub public_json: *const u8,
    pub public_len: usize,
    pub phrase: *const u8,
    pub phrase_len: usize,
    pub out_signed: *mut *mut super::super::RamfluxBuffer,
    pub out_error: *mut *mut super::super::RamfluxBuffer,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicRequest {
    account_id: String,
    #[serde(deserialize_with = "de_request_id")]
    request_id: u64,
    draft: UsernameDraft,
    expected_change: UsernameChange,
}

struct Ceremony<'a> {
    client: &'a Client,
    request_id: u64,
    out_signed: *mut *mut super::super::RamfluxBuffer,
    out_error: *mut *mut super::super::RamfluxBuffer,
}

pub(super) fn authorize(
    client: &Client,
    input: &AuthorizeInput,
) -> Result<bool, super::super::CAbiError> {
    let public = copy_public(input.public_json, input.public_len)?;
    let (account_id, request_id) = loose_ids(&public)?;
    let parent = bound_parent(client, request_id, &account_id)?;
    let ceremony =
        Ceremony { client, request_id, out_signed: input.out_signed, out_error: input.out_error };
    if retired(&ceremony)? {
        return cancel(&ceremony);
    }
    let request = strict_request(&public)?;
    if request.account_id != account_id || request.request_id != request_id {
        return Err(invalid("username request"));
    }
    let center = match checked(&parent, &request, &client.data_root) {
        Ok(center) => center,
        Err(error) => return refuse(&ceremony, &error),
    };
    let phrase = match copy_phrase(input.phrase, input.phrase_len) {
        Ok(phrase) => phrase,
        Err(error) => return refuse(&ceremony, &error),
    };
    if contains_phrase(&public, &phrase) {
        return refuse(&ceremony, &DirectoryCode::AuthenticationRequired.into());
    }
    let hold = match client.shared.credentials.hold_username_master() {
        Ok(hold) => hold,
        Err(error) => return refuse(&ceremony, &error),
    };
    if retired(&ceremony)? || hold.retired() {
        return cancel(&ceremony);
    }
    sign_and_publish(&ceremony, request, phrase, hold, &center)
}

fn sign_and_publish(
    ceremony: &Ceremony<'_>,
    request: PublicRequest,
    phrase: Zeroizing<String>,
    hold: super::super::pairing::UsernameMasterHold,
    center: &NativeDirectoryPin,
) -> Result<bool, super::super::CAbiError> {
    let signed = match sign(phrase, request, center) {
        Ok(signed) => signed,
        Err(error) => return refuse(ceremony, &error),
    };
    if retired(ceremony)? || hold.retired() {
        return cancel(ceremony);
    }
    buffer::write_json_buffer(ceremony.out_signed, &signed)?;
    drop(signed);
    let discard = match retired(ceremony) {
        Ok(retired) => retired || hold.retired(),
        Err(error) => {
            buffer::discard_output(ceremony.out_signed);
            return Err(error);
        }
    };
    if discard {
        buffer::discard_output(ceremony.out_signed);
        return cancel(ceremony);
    }
    drop(hold);
    Ok(false)
}

fn sign(
    phrase: Zeroizing<String>,
    request: PublicRequest,
    center: &NativeDirectoryPin,
) -> Result<SignedUsernameChange, SdkError> {
    let now = crate::custody::network_now()?;
    authorize_username_draft(phrase, request.draft, center, &request.expected_change, now)
}

fn checked(
    parent: &UsernameParent,
    request: &PublicRequest,
    root: &std::path::Path,
) -> Result<NativeDirectoryPin, SdkError> {
    profile_alias(parent, request)?;
    if request.draft.change.normalized()? != request.expected_change.normalized()? {
        return Err(DirectoryCode::Replay.into());
    }
    let center = configured_center()?;
    if request.draft.center != center {
        return Err(DirectoryCode::Replay.into());
    }
    account_matches(root, &parent.account_id, &request.draft)?;
    draft_window(&request.draft)?;
    Ok(center)
}

fn profile_alias(parent: &UsernameParent, request: &PublicRequest) -> Result<(), SdkError> {
    if parent.method != "profile.update" {
        return Ok(());
    }
    if matches!(request.draft.change, UsernameChange::Profile { .. })
        && matches!(request.expected_change, UsernameChange::Profile { .. })
    {
        return Ok(());
    }
    Err(DirectoryCode::InvalidProfile.into())
}

fn account_matches(
    root: &std::path::Path,
    account_id: &str,
    draft: &UsernameDraft,
) -> Result<(), SdkError> {
    let now = crate::custody::network_now()?;
    let account = crate::custody::load_account(root, account_id, now)?;
    let body = &account.record().body;
    if draft.master_public_key == body.master_certificate.body.master_public_key
        && draft.operation.principal_commitment == body.account_anchor
    {
        return Ok(());
    }
    Err(DirectoryCode::OwnershipMismatch.into())
}

fn draft_window(draft: &UsernameDraft) -> Result<(), SdkError> {
    let width = draft.operation.expires_at.checked_sub(draft.operation.issued_at);
    if width == Some(DRAFT_LIFETIME_SECS) {
        return Ok(());
    }
    Err(DirectoryCode::Replay.into())
}

fn bound_parent(
    client: &Client,
    id: u64,
    account_id: &str,
) -> Result<UsernameParent, super::super::CAbiError> {
    let parent =
        client.shared.credentials.username_parent(id).map_err(|error| bridge_error(&error))?;
    let Some(parent) = parent else {
        return Err(invalid("username operation"));
    };
    if parent.account_id != account_id
        || !matches!(parent.method.as_str(), "username.mutate" | "profile.update")
    {
        return Err(invalid("username operation"));
    }
    Ok(parent)
}

fn retired(ceremony: &Ceremony<'_>) -> Result<bool, super::super::CAbiError> {
    if ceremony.client.closing.load(Ordering::Acquire)
        || ceremony.client.shared.closed.load(Ordering::Acquire)
    {
        return Ok(true);
    }
    let operations = ceremony.client.shared.operations.lock().map_err(|_| internal())?;
    let Some(operation) = operations.get(&ceremony.request_id) else {
        return Err(invalid("username operation"));
    };
    let state = operation.state.lock().map_err(|_| internal())?;
    Ok(state.cancelled || state.detached)
}

fn copy_public(ptr: *const u8, len: usize) -> Result<Zeroizing<Vec<u8>>, super::super::CAbiError> {
    if ptr.is_null() || len == 0 || len > PUBLIC_LIMIT {
        return Err(invalid("username request"));
    }
    // SAFETY: len is non-zero, at most PUBLIC_LIMIT, and the caller keeps those bytes readable.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(Zeroizing::new(bytes.to_vec()))
}

fn copy_phrase(ptr: *const u8, len: usize) -> Result<Zeroizing<String>, SdkError> {
    if ptr.is_null() || len == 0 || len > PHRASE_LIMIT {
        return Err(DirectoryCode::AuthenticationRequired.into());
    }
    let mut buffer = Zeroizing::new([0_u8; PHRASE_LIMIT]);
    // SAFETY: len is at most PHRASE_LIMIT and the caller keeps those bytes readable.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, buffer.as_mut_ptr(), len);
    }
    let bytes = buffer.get(..len).ok_or(DirectoryCode::AuthenticationRequired)?;
    let text = std::str::from_utf8(bytes).map_err(|_| DirectoryCode::AuthenticationRequired)?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn contains_phrase(public: &[u8], phrase: &str) -> bool {
    let needle = phrase.as_bytes();
    if needle.is_empty() || needle.len() > public.len() {
        return false;
    }
    public.windows(needle.len()).any(|window| window == needle)
}

fn loose_ids(bytes: &[u8]) -> Result<(String, u64), super::super::CAbiError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| canonical())?;
    let account = value
        .get("account_id")
        .and_then(serde_json::Value::as_str)
        .filter(|item| !item.is_empty())
        .map(str::to_owned);
    let Some(account) = account else {
        return Err(invalid("username request"));
    };
    let request_id = json_request_id(value.get("request_id"))?;
    Ok((account, request_id))
}

fn json_request_id(value: Option<&serde_json::Value>) -> Result<u64, super::super::CAbiError> {
    match value {
        Some(serde_json::Value::Number(number)) => {
            number.as_u64().filter(|id| *id != 0).ok_or_else(|| invalid("username request"))
        }
        Some(serde_json::Value::String(text)) => decimal_id(text),
        _ => Err(invalid("username request")),
    }
}

fn decimal_id(text: &str) -> Result<u64, super::super::CAbiError> {
    let id = text.parse::<u64>().map_err(|_| invalid("username request"))?;
    if id == 0 || text != id.to_string() {
        return Err(invalid("username request"));
    }
    Ok(id)
}

fn strict_request(bytes: &[u8]) -> Result<PublicRequest, super::super::CAbiError> {
    serde_json::from_slice(bytes).map_err(|_| invalid("username request"))
}

fn de_request_id<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl serde::de::Visitor<'_> for Visitor {
        type Value = u64;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("decimal operation id")
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<u64, E> {
            if value == 0 {
                return Err(E::custom("operation"));
            }
            Ok(value)
        }
        fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<u64, E> {
            let value = text.parse::<u64>().map_err(|_| E::custom("operation"))?;
            if value == 0 || text != value.to_string() {
                return Err(E::custom("operation"));
            }
            Ok(value)
        }
    }
    deserializer.deserialize_any(Visitor)
}

fn cancel(ceremony: &Ceremony<'_>) -> Result<bool, super::super::CAbiError> {
    buffer::write_json_buffer(
        ceremony.out_error,
        &serde_json::json!({
            "code": RamfluxV2Status::Cancelled as i32,
            "name": "Cancelled",
        }),
    )?;
    Ok(true)
}

fn refuse(ceremony: &Ceremony<'_>, error: &SdkError) -> Result<bool, super::super::CAbiError> {
    if matches!(error, SdkError::PairingCode("Retired")) {
        return cancel(ceremony);
    }
    if matches!(error, SdkError::PairingField("credential_provider")) {
        write_error(ceremony.out_error, super::super::RamfluxErrorCode::PermissionDenied, None)?;
        return Err(error_code(super::super::RamfluxErrorCode::PermissionDenied));
    }
    let directory = match error {
        SdkError::UsernameDirectoryRefused(code) => Some(code.as_str()),
        _ => None,
    };
    let code = super::super::sdk_error_code(error);
    write_error(ceremony.out_error, code, directory)?;
    Err(error_code(code))
}

fn write_error(
    out: *mut *mut super::super::RamfluxBuffer,
    code: super::super::RamfluxErrorCode,
    directory: Option<&str>,
) -> Result<(), super::super::CAbiError> {
    let mut value = serde_json::json!({"code": code as i32, "name": code.name()});
    if let Some(token) = directory {
        value["directory"] = serde_json::json!(token);
    }
    buffer::write_json_buffer(out, &value)
}

fn bridge_error(error: &SdkError) -> super::super::CAbiError {
    if matches!(error, SdkError::LocalBus(_)) {
        return internal();
    }
    error_code(super::super::sdk_error_code(error))
}

fn invalid(message: &'static str) -> super::super::CAbiError {
    super::super::CAbiError::new(super::super::RamfluxErrorCode::InvalidArgument, message)
}

fn canonical() -> super::super::CAbiError {
    super::super::CAbiError::new(
        super::super::RamfluxErrorCode::InvalidCanonicalJson,
        "username request",
    )
}

fn internal() -> super::super::CAbiError {
    super::super::CAbiError::new(super::super::RamfluxErrorCode::Internal, "username")
}

fn error_code(code: super::super::RamfluxErrorCode) -> super::super::CAbiError {
    super::super::CAbiError::new(code, "username")
}

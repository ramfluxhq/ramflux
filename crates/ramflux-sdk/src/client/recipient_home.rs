// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recipient directory origin. A caller URL is never a fetch or a submit target.

use crate::prelude::*;

const UNPINNED: &str = "pinned home is required before a remote recipient directory fetch";

/// Remote home node id, or `None` when the recipient stays on this session's directory.
///
/// # Errors
/// Returns an error when `caller_target` names a different node than the pin.
pub(crate) fn pin_choice(
    client: &RamfluxClient,
    commitment: &str,
    caller_target: Option<&str>,
) -> Result<Option<String>, SdkError> {
    let principal = principal_for_commitment(client, commitment)?;
    let recorded = match principal.as_deref() {
        Some(principal) => pinned_home(client, principal)?,
        None => None,
    };
    let home = match recorded {
        Some(home) => Some(home),
        None => crate::client::foreign_manifest::stored_source(client, commitment)?
            .map(|(home, _)| home),
    };
    let caller = node_id(caller_target);
    if let (Some(home), Some(caller)) = (&home, caller.as_deref())
        && caller != home
    {
        return Err(SdkError::LocalBus("caller target_node disagrees with the pinned home".into()));
    }
    Ok(home)
}

/// Public prekey base for `home`, or `None` when the session directory is the origin.
///
/// # Errors
/// Returns an error when a remote pin has no card fingerprint or signed public
/// endpoint, or when a federation route has neither a pin nor a session directory.
pub(crate) async fn fetch_base(
    home: Option<String>,
    pinned_fingerprint: Option<&str>,
    session_directory: bool,
) -> Result<Option<String>, SdkError> {
    match home {
        Some(home) => {
            let fingerprint = pinned_fingerprint.ok_or_else(fingerprint_required)?;
            Ok(Some(public_prekey_base(&home, fingerprint).await?))
        }
        None if session_directory => Ok(None),
        None => Err(SdkError::LocalBus(UNPINNED.into())),
    }
}

pub(crate) fn pinned_home(
    client: &RamfluxClient,
    principal: &str,
) -> Result<Option<String>, SdkError> {
    let Some(identity) = client.account_db()?.client_record("identity", principal)? else {
        return Ok(None);
    };
    if let Some(home) = node_id(identity.get("home_node_id").and_then(serde_json::Value::as_str)) {
        if let Some(root) =
            identity.get("contact_identity_commitment").and_then(serde_json::Value::as_str)
            && let Some((stored, _)) = crate::client::foreign_manifest::stored_source(client, root)?
            && stored != home
        {
            return Err(SdkError::LocalBus(
                "pinned home disagrees with the verified source".into(),
            ));
        }
        return Ok(Some(home));
    }
    let Some(root) =
        identity.get("contact_identity_commitment").and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    Ok(crate::client::foreign_manifest::stored_source(client, root)?.map(|(home, _)| home))
}

pub(crate) fn principal_for_commitment(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<Option<String>, SdkError> {
    let Some(row) = client.account_db()?.client_record("commitment", commitment)? else {
        return Ok(None);
    };
    Ok(row
        .get("principal_id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned))
}

/// Card node-key fingerprint stored at import (`identity.node.key_fingerprint`).
///
/// # Errors
/// Returns an error when the contact has no stored card fingerprint.
pub(crate) fn pinned_node_fingerprint(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<String, SdkError> {
    let card = match principal_for_commitment(client, commitment)? {
        Some(principal) => client
            .account_db()?
            .client_record("identity", &principal)?
            .as_ref()
            .and_then(|identity| identity.get("node"))
            .and_then(|node| node.get("key_fingerprint"))
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        None => None,
    };
    let stored = crate::client::foreign_manifest::stored_source(client, commitment)?
        .map(|(_, fingerprint)| fingerprint);
    match (card, stored) {
        (Some(card), Some(stored)) if card != stored => {
            Err(SdkError::LocalBus("pinned home disagrees with the verified source".into()))
        }
        (Some(card), _) => Ok(card),
        (None, Some(stored)) => Ok(stored),
        (None, None) => Err(fingerprint_required()),
    }
}

pub(crate) const PINNED_FINGERPRINT_CODE: &str = "pinned_node_fingerprint_required";
pub(crate) const PINNED_HOME_CONFLICT_CODE: &str = "pinned_home_conflict";

/// 64 hex digits from a contact card, stored lowercase.
///
/// # Errors
/// Returns `InvalidCard` when `value` is empty or not 64 hex digits.
pub(crate) fn require_card_fingerprint(value: &str) -> Result<String, SdkError> {
    let fingerprint = value.to_ascii_lowercase();
    if fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(fingerprint)
    } else {
        Err(crate::ContactReason::InvalidCard.into())
    }
}

pub(crate) fn fingerprint_required() -> SdkError {
    SdkError::LocalBusRefused {
        code: PINNED_FINGERPRINT_CODE.into(),
        message: "pinned node fingerprint is required".into(),
        body: Box::new(serde_json::json!({ "reason_code": PINNED_FINGERPRINT_CODE })),
    }
}

pub(crate) fn pinned_fingerprint_required(error: &SdkError) -> bool {
    matches!(
        error.directory_source(),
        SdkError::LocalBusRefused { code, .. } if code == PINNED_FINGERPRINT_CODE
    )
}

/// Receive code when this entry is blocked by a pinned home.
///
/// A missing fingerprint keeps its own code. A disagreement, a malformed source
/// pin, or a remote fetch the pin refuses is `pinned_home_conflict`. Other local
/// refusals stay unclassified so a session or storage error still stops the pass.
pub(crate) fn pinned_receive_code(error: &SdkError) -> Option<&'static str> {
    if pinned_fingerprint_required(error) {
        return Some(PINNED_FINGERPRINT_CODE);
    }
    let SdkError::LocalBus(message) = error.directory_source() else {
        return None;
    };
    match message.as_str() {
        "pinned home disagrees with the verified source"
        | "verified source home is malformed"
        | "pinned home is not a node id"
        | "pinned source home capacity exhausted"
        | "source home root is malformed"
        | "pinned home does not match the signed client record"
        | "pinned home has no public prekey endpoint"
        | "caller target_node disagrees with the pinned home"
        | "pinned home is required before a remote recipient directory fetch" => {
            Some(PINNED_HOME_CONFLICT_CODE)
        }
        _ => None,
    }
}

/// `prekey_http_url` from the pinned home's signed client record.
///
/// The discovered node key must equal `pinned_fingerprint`. The endpoint is
/// returned only after that check.
///
/// # Errors
/// Returns an error when `home` is not a node id, the fingerprint is empty, the
/// signed record names a different node or key, or the record has no public
/// prekey endpoint.
pub(crate) async fn public_prekey_base(
    home: &str,
    pinned_fingerprint: &str,
) -> Result<String, SdkError> {
    let home = node_id(Some(home))
        .ok_or_else(|| SdkError::LocalBus("pinned home is not a node id".into()))?;
    if pinned_fingerprint.is_empty() {
        return Err(fingerprint_required());
    }
    #[cfg(test)]
    if let Some(base) = test_public_base(&home) {
        return Ok(base);
    }
    let record = crate::node::fetch_client_record(&home).await?;
    if record.node_id != home {
        return Err(SdkError::LocalBus(
            "pinned home does not match the signed client record".into(),
        ));
    }
    if crate::contact_node_fingerprint(&record.node_public_key)? != pinned_fingerprint {
        return Err(crate::ContactReason::NodeFingerprintMismatch.into());
    }
    if record.prekey_http_url.is_empty() {
        return Err(SdkError::LocalBus("pinned home has no public prekey endpoint".into()));
    }
    Ok(record.prekey_http_url)
}

/// Public prekey base, or `None` when `session_directory` selects the local gateway.
///
/// # Errors
/// Returns an error when the caller names a different node than the pin, or when
/// a remote fetch has neither a pin nor a session directory.
pub(crate) async fn directory_base(
    client: &RamfluxClient,
    commitment: &str,
    caller_target: Option<&str>,
    session_directory: bool,
) -> Result<Option<String>, SdkError> {
    let home = pin_choice(client, commitment, caller_target)?;
    let fingerprint = match &home {
        Some(_) => Some(pinned_node_fingerprint(client, commitment)?),
        None => None,
    };
    fetch_base(home, fingerprint.as_deref(), session_directory).await
}

/// Signed public prekey base. A missing pin fails before any socket.
///
/// # Errors
/// Returns an error when the recipient has no pinned home or the signed record
/// has no public prekey endpoint.
pub(crate) async fn required_public_base(
    client: &RamfluxClient,
    commitment: &str,
    caller_target: Option<&str>,
) -> Result<String, SdkError> {
    directory_base(client, commitment, caller_target, false)
        .await?
        .ok_or_else(|| SdkError::LocalBus(UNPINNED.into()))
}

/// Pinned home when it names a different node from this account.
///
/// `None` keeps the session directory and a local gateway submit.
///
/// # Errors
/// Returns an error when the account record cannot be read.
pub(crate) fn foreign_target(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<Option<String>, SdkError> {
    let from_identity = match principal_for_commitment(client, commitment)? {
        Some(principal) => pinned_home(client, &principal)?,
        None => None,
    };
    let home = match from_identity {
        Some(home) => Some(home),
        None => crate::client::foreign_manifest::stored_source(client, commitment)?
            .map(|(home, _)| home),
    };
    let Some(home) = home else { return Ok(None) };
    let own = client.account_db()?.load_actor_state::<String>("account/node-id")?;
    if own.as_deref() == Some(home.as_str()) { Ok(None) } else { Ok(Some(home)) }
}

/// Device manifest from the pinned home's signed public prekey endpoint.
///
/// # Errors
/// Returns an error when the signed record or the manifest response is refused.
pub(crate) async fn public_device_manifest(
    home: &str,
    pinned_fingerprint: &str,
    commitment: &str,
) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
    let base = public_prekey_base(home, pinned_fingerprint).await?;
    let started = std::time::Instant::now();
    let manifest =
        crate::prekey::http_async::get::<Option<crate::prekey::SdkDeviceManifestResponse>>(
            &base,
            &format!("/mvp1/device-manifest/{commitment}"),
            std::time::Duration::from_secs(10),
        )
        .await?
        .ok_or_else(|| SdkError::InboundRejected("device manifest unavailable".into()))?
        .fetched_from(started);
    Ok(manifest)
}

/// Own-gateway submit. A foreign pinned home is carried as `target_node`.
///
/// # Errors
/// Returns an error when the pin cannot be read or the gateway refuses the envelope.
pub(crate) async fn submit_addressed(
    client: &RamfluxClient,
    engine: &mut impl GatewaySessionAccess,
    envelope: ramflux_protocol::Envelope,
    commitment: Option<&str>,
) -> Result<GatewayInboxEntry, SdkError> {
    let target = match commitment {
        Some(commitment) => foreign_target(client, commitment)?,
        None => None,
    };
    if target.is_none() {
        return engine.submit_envelope(envelope).await;
    }
    match engine.submit_classified_to(envelope, target).await? {
        Ok(entry) => Ok(entry),
        Err(refusal) => Err(SdkError::GatewaySessionRejected(refusal.reason().to_owned())),
    }
}

/// Submit target copied from the pin. An unpinned caller target is dropped.
pub(crate) fn submit_route(
    route: &crate::LocalBusFederationRoute,
    submit_target: Option<&str>,
) -> crate::LocalBusFederationRoute {
    let mut route = route.clone();
    submit_target.unwrap_or("").clone_into(&mut route.target_node_id);
    route
}

/// Route stored for a submit. The caller's node id is kept only when it is the pin.
///
/// # Errors
/// Returns an error when `route` names a different node than the pinned home.
pub(crate) fn submit_copy(
    client: &RamfluxClient,
    commitment: &str,
    route: Option<crate::LocalBusFederationRoute>,
) -> Result<Option<crate::LocalBusFederationRoute>, SdkError> {
    let Some(route) = route else { return Ok(None) };
    let target = pin_choice(client, commitment, Some(route.target_node_id.as_str()))?;
    Ok(Some(submit_route(&route, target.as_deref())))
}

/// Inputs for [`seal_member`]. The route value is moved into the seal.
pub(crate) struct MemberSeal<'a> {
    pub message: &'a GatewayDirectMessage,
    pub body: &'a [u8],
    pub commitment: &'a str,
    pub federation: Option<&'a crate::LocalBusFederationRoute>,
    pub route: crate::client::routed::Route,
}

/// Seal for the pinned public directory, or the session directory when there is no pin.
///
/// # Errors
/// Returns an error when the pin check, the public endpoint, or the seal fails.
pub(crate) async fn seal_member(
    client: &RamfluxClient,
    engine: &mut impl GatewaySessionAccess,
    seal: MemberSeal<'_>,
) -> Result<crate::client::routed::SealedRouted, SdkError> {
    let caller = seal.federation.map(|federation| federation.target_node_id.as_str());
    let foreign = foreign_target(client, seal.commitment)?;
    if (foreign.is_some() || caller.is_some())
        && let Some(base) = directory_base(client, seal.commitment, caller, true).await?
    {
        client.seal_routed_federated_as(engine, seal.message, seal.body, Some(&base), seal.route)
    } else {
        client.seal_routed_as(engine, seal.message, seal.body, seal.route).await
    }
}

pub(crate) fn node_id(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    let bytes = value.as_bytes();
    let edges = bytes.first().is_some_and(|b| *b == b'.' || *b == b'-')
        || bytes.last().is_some_and(|b| *b == b'.' || *b == b'-');
    let body = bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-');
    if (1..=63).contains(&bytes.len()) && !edges && body { Some(value.to_owned()) } else { None }
}

#[cfg(test)]
thread_local! {
    static TEST_PUBLIC_BASE: std::cell::RefCell<Option<(String, String)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct TestPublicBase {
    _private: (),
}

#[cfg(test)]
impl Drop for TestPublicBase {
    fn drop(&mut self) {
        TEST_PUBLIC_BASE.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn install_test_public_base(home: &str, base: &str) -> TestPublicBase {
    TEST_PUBLIC_BASE.with(|slot| {
        *slot.borrow_mut() = Some((home.to_owned(), base.to_owned()));
    });
    TestPublicBase { _private: () }
}

#[cfg(test)]
fn test_public_base(home: &str) -> Option<String> {
    TEST_PUBLIC_BASE.with(|slot| {
        slot.borrow().as_ref().filter(|(pinned, _)| pinned == home).map(|(_, base)| base.clone())
    })
}

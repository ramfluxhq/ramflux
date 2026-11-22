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
    let home = match principal.as_deref() {
        Some(principal) => pinned_home(client, principal)?,
        None => None,
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
/// Returns an error when a remote pin has no signed public endpoint, or when a
/// federation route has neither a pin nor a session directory.
pub(crate) async fn fetch_base(
    home: Option<String>,
    session_directory: bool,
) -> Result<Option<String>, SdkError> {
    match home {
        Some(home) => Ok(Some(public_prekey_base(&home).await?)),
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
    Ok(node_id(identity.get("home_node_id").and_then(serde_json::Value::as_str)))
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

/// `prekey_http_url` from the pinned home's signed client record.
///
/// # Errors
/// Returns an error when `home` is not a node id, the signed record names a
/// different node, or the record has no public prekey endpoint.
pub(crate) async fn public_prekey_base(home: &str) -> Result<String, SdkError> {
    let home = node_id(Some(home))
        .ok_or_else(|| SdkError::LocalBus("pinned home is not a node id".into()))?;
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
    fetch_base(pin_choice(client, commitment, caller_target)?, session_directory).await
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

/// Submit target copied from the pin. An unpinned caller target is dropped.
pub(crate) fn submit_route(
    route: &crate::LocalBusFederationRoute,
    submit_target: Option<&str>,
) -> crate::LocalBusFederationRoute {
    let mut route = route.clone();
    submit_target.unwrap_or("").clone_into(&mut route.target_node_id);
    route.recipient_prekey_url = None;
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
    let Some(federation) = seal.federation else {
        return client.seal_routed_as(engine, seal.message, seal.body, seal.route).await;
    };
    if let Some(base) =
        directory_base(client, seal.commitment, Some(federation.target_node_id.as_str()), true)
            .await?
    {
        client.seal_routed_federated_as(engine, seal.message, seal.body, Some(&base), seal.route)
    } else {
        client.seal_routed_as(engine, seal.message, seal.body, seal.route).await
    }
}

fn node_id(value: Option<&str>) -> Option<String> {
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

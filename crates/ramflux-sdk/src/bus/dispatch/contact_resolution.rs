// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-scoped contact selectors and root-pinned card transport discovery.
use crate::client::contact_resolution::{ContactResolution, lookup_failure};
use crate::prelude::*;
use crate::{ContactCardBody, ContactNode, ContactReason};
use serde_json::{Value, json};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Add {
    note: Option<String>,
    principal_id: Option<String>,
    card: Option<String>,
    replace_provisional_root: Option<String>,
}

/// Only the verified directory adapter can construct this input; no caller-supplied root or URL.
pub(in crate::bus) async fn add_username(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    resolved: &crate::username_directory::ResolvedUsername,
) -> Result<LocalBusDispatchResult, SdkError> {
    let home = account_home(state, account_id)?;
    if home.node_id != resolved.node {
        return Err(SdkError::LocalBusRefused {
            code: "contact_home_node_unsupported".into(),
            message: "Contact requests to a different home node are not available yet".into(),
            body: Box::new(
                json!({"node": &resolved.node, "root_commitment": &resolved.root_commitment}),
            ),
        });
    }
    let account = local_bus_account_mut(state, account_id)?;
    let own = account.gateway_config.clone();
    if resolved.principal_id == own.principal_id
        || resolved.root_commitment == account.principal_commitment
    {
        return Err(ContactReason::SelfContact.into());
    }
    resolved.validate_for_add(crate::custody::network_now()?)?;
    // Explicit Add pins the observed name before any request can enter the outbox. A failed
    // transport may leave this historical pin, but cannot silently repoint a later retry.
    resolved.pin_for_add(account.client.account_db()?)?;
    if let Some(contact) = account.client.accepted_contact_retry(&resolved.principal_id, None)? {
        if contact["root_commitment"].as_str() != Some(&resolved.root_commitment) {
            return Err(ContactReason::RootConflict.into());
        }
        account.client.pin_contact_home(&resolved.principal_id, &resolved.node)?;
        return Ok(local_bus_ok(contact_response(account, &contact, None)?));
    }
    let mut engine = account.live_session_client().map_err(lookup_failure)?;
    let link =
        crate::client::contact_roots::contact_link_id(&own.principal_id, &resolved.principal_id)?;
    let result = account
        .client
        .resolve_contact(
            &own,
            &own,
            ContactResolution {
                send_request: true,
                request_note: None,
                selector: &resolved.principal_id,
                expected_root: Some(&resolved.root_commitment),
                card: None,
                link_id: link,
                allow_commitment: false,
                requester_is_peer: false,
                replace_provisional_root: None,
                verification: None,
                directory_base: None,
            },
            &mut engine,
        )
        .await;
    account.apply_session_metadata(engine);
    let contact = result?;
    account.client.pin_contact_home(&resolved.principal_id, &resolved.node)?;
    if let Some(handle) = &account.connection {
        handle.wake_couriers();
    }
    Ok(local_bus_ok(contact_response(account, &contact, None)?))
}

#[allow(clippy::too_many_lines)]
pub(super) async fn add(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let Selection { legacy, card, selector, requester_is_peer, replace_provisional_root } =
        parse_selector(request, local_bus_account(state, account_id)?)?;
    let account = local_bus_account(state, account_id)?;
    let own = account.gateway_config.clone();
    if selector == own.principal_id || selector == account.principal_commitment {
        return Err(ContactReason::SelfContact.into());
    }
    if let Some(old) = &legacy
        && old.requester_id != own.principal_id
        && old.requester_id != account.principal_commitment
        && !(request.method == "contact.accept"
            && (old.target_id == own.principal_id || old.target_id == account.principal_commitment))
    {
        return Err(ContactReason::InvalidCard.into());
    }
    if request.method == "contact.accept" && replace_provisional_root.is_none() {
        // Validate the requested link and persist card provenance in the same writer phase.
        let retry = account.client.account_db()?.write_transaction(|| {
            account
                .client
                .accepted_contact_retry(&selector, card.as_ref())?
                .map(|contact| contact_response(account, &contact, legacy.as_ref()))
                .transpose()
        })?;
        if let Some(response) = retry {
            return Ok(local_bus_ok(response));
        }
    }

    if legacy.is_none()
        && card.is_none()
        && !account.client.contact_request_retryable(&selector)?
        && (account.client.friend_link_peer_is_accepted(&selector)?
            || account
                .client
                .account_db()?
                .client_record("identity", &selector)?
                .and_then(|r| r["contact_identity_commitment"].as_str().map(str::to_owned))
                .map(|c| account.client.friend_link_peer_is_accepted(&c))
                .transpose()?
                .unwrap_or(false))
    {
        return Err(ContactReason::AlreadyContact.into());
    }
    if let Some(card) = card.as_ref()
        && let Some(done) = pin_accepted_card(state, account_id, card, &selector).await?
    {
        return Ok(done);
    }
    let mut verified_home = None;
    let mut directory_base = None;
    let gateway = match card.as_ref() {
        Some(card) => {
            let profile = account_home(state, account_id)?;
            let verified = card_gateway(card, &own, &state.config.data_root, &profile).await?;
            // The signed client record names the home. A foreign node keeps this session
            // and is reached through `target_node` after the pin below.
            verified_home = Some(verified.node_id);
            directory_base = verified.directory_base;
            verified.gateway
        }
        None => own.clone(),
    };
    let link = match &legacy {
        Some(old) => old.link_id.clone(),
        None => crate::client::contact_roots::contact_link_id(&own.principal_id, &selector)?,
    };
    let account = local_bus_account_mut(state, account_id)?;
    let mut engine = account.session_client().await.map_err(lookup_failure)?;
    let result = account
        .client
        .resolve_contact(
            &gateway,
            &own,
            ContactResolution {
                send_request: true,
                request_note: request.body["note"].as_str(),
                selector: &selector,
                expected_root: card.as_ref().map(|c| c.root_commitment.as_str()),
                card: card.as_ref(),
                link_id: link.clone(),
                allow_commitment: legacy.is_some(),
                requester_is_peer,
                replace_provisional_root: replace_provisional_root.as_deref(),
                verification: None,
                directory_base: directory_base.as_deref(),
            },
            &mut engine,
        )
        .await;
    account.apply_session_metadata(engine);
    let contact = result?;
    if let (Some(home), Some(principal)) = (verified_home, contact["principal_id"].as_str()) {
        if let Some(card) = card.as_ref() {
            account.client.pin_verified_card_home(
                principal,
                &home,
                &card.node.url,
                &card.node.key_fingerprint,
            )?;
        } else {
            account.client.pin_contact_home(principal, &home)?;
        }
    }
    #[cfg(test)]
    if let Err(error) = Box::pin(crate::client::contact_requests::flush(account)).await {
        tracing::debug!(%error,"contact request queued for retry");
    }
    if let Some(handle) = &account.connection {
        handle.wake_couriers();
    }
    #[cfg(test)]
    if let Err(error) = super::super::own_device_copy::flush(account).await {
        tracing::warn!(%error, "accepted contact copy deferred to account sync");
    }
    Ok(local_bus_ok(contact_response(account, &contact, legacy.as_ref())?))
}

/// An accepted non-lookup contact keeps its card refusal, except when no home is pinned.
/// The verified card's home is then recorded so attachment send can name the grantee.
async fn pin_accepted_card(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    card: &ContactCardBody,
    selector: &str,
) -> Result<Option<LocalBusDispatchResult>, SdkError> {
    let account = local_bus_account(state, account_id)?;
    if account.client.contact_request_retryable(selector)? {
        return Ok(None);
    }
    let Some(old) = account.client.account_db()?.client_record("identity", selector)? else {
        return Ok(None);
    };
    if old["contact_identity_commitment"].as_str() != Some(card.root_commitment.as_str())
        || account.client.contact_root_source(&old)? == crate::ContactRootSource::Lookup
        || !account.client.friend_link_peer_is_accepted(&card.root_commitment)?
    {
        return Ok(None);
    }
    if account.client.born_v3_account.is_none() {
        return Err(ContactReason::AlreadyContact.into());
    }
    // Refuse before any pin. A parsed card can still arrive without 64 hex digits.
    let fingerprint =
        crate::client::recipient_home::require_card_fingerprint(&card.node.key_fingerprint)?;
    let recorded_home = old
        .get("home_node_id")
        .and_then(Value::as_str)
        .filter(|home| !home.is_empty())
        .map(str::to_owned);
    let recorded_fingerprint = old
        .get("node")
        .and_then(|node| node.get("key_fingerprint"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if recorded_home.is_some() && recorded_fingerprint.is_some() {
        return Err(ContactReason::AlreadyContact.into());
    }
    let home = account_home(state, account_id)?;
    let own = local_bus_account(state, account_id)?.gateway_config.clone();
    let root = state.config.data_root.clone();
    let verified = card_gateway(card, &own, &root, &home).await?;
    if recorded_home.as_deref().is_some_and(|recorded| recorded != verified.node_id) {
        return Err(ContactReason::RootConflict.into());
    }
    let account = local_bus_account_mut(state, account_id)?;
    account.client.pin_verified_card_home(
        selector,
        &verified.node_id,
        &card.node.url,
        &fingerprint,
    )?;
    let contact = account.client.contact_entry(selector)?;
    Ok(Some(local_bus_ok(contact_response(account, &contact, None)?)))
}

fn contact_response(
    account: &LocalBusAccountState,
    contact: &Value,
    legacy: Option<&LocalBusContactAddRequest>,
) -> Result<Value, SdkError> {
    let root =
        contact["root_commitment"].as_str().ok_or(ContactReason::ManifestInvalid)?.to_owned();
    let delivery = crate::client::contact_requests::delivery_status(&account.client, &root)?;
    let mut response = json!({"contact":contact,"request_delivery":delivery});
    if let Some(old) = legacy {
        let db = account.client.account_db()?;
        let record = match db.find_friend_link(&old.link_id)? {
            Some(record) => {
                let principal =
                    contact["principal_id"].as_str().ok_or(ContactReason::UnknownPrincipal)?;
                if ![record.requester_id.as_str(), record.target_id.as_str()]
                    .iter()
                    .any(|end| *end == root || *end == principal)
                {
                    return Err(ContactReason::RootConflict.into());
                }
                record
            }
            None => db.friend_link_for_peer(&root)?.ok_or(ContactReason::UnknownPrincipal)?,
        };
        if let Value::Object(fields) = serde_json::to_value(record)? {
            response.as_object_mut().ok_or(ContactReason::InvalidCard)?.extend(fields);
        }
    }
    Ok(response)
}

struct CardHome {
    gateway: GatewaySessionConfig,
    node_id: String,
    /// Public prekey base when the card's home is not this node. `None` uses the session directory.
    directory_base: Option<String>,
}

fn known_home_pin_refused(
    card: &ContactCardBody,
    home: &crate::NodeProfile,
) -> Result<bool, SdkError> {
    let Ok(home_origin) = home.discovery_origin() else {
        return Ok(false);
    };
    let Ok(card_origin) = crate::node::discovery_origin(&card.node.url) else {
        return Ok(false);
    };
    if card_origin != home_origin {
        return Ok(false);
    }
    Ok(crate::contact_node_fingerprint(&home.node_public_key)? != card.node.key_fingerprint)
}

async fn card_gateway(
    card: &ContactCardBody,
    own: &GatewaySessionConfig,
    root: &Path,
    home: &crate::NodeProfile,
) -> Result<CardHome, SdkError> {
    // A card that names this home but a different node key is refused before discovery.
    // A foreign origin is still fetched; the signed record, not the URL text, names that home.
    if known_home_pin_refused(card, home)? {
        return Err(ContactReason::NodeFingerprintMismatch.into());
    }
    let record =
        crate::node::fetch_client_record(&card.node.url).await.map_err(|error| match error {
            SdkError::Transport(_) | SdkError::Io(_) => lookup_failure(error),
            _ => ContactReason::ManifestInvalid.into(),
        })?;
    if crate::contact_node_fingerprint(&record.node_public_key)? != card.node.key_fingerprint {
        return Err(ContactReason::NodeFingerprintMismatch.into());
    }
    let node_id = crate::client::recipient_home::node_id(Some(record.node_id.as_str()))
        .ok_or(ContactReason::InvalidCard)?;
    if node_id == home.node_id {
        return same_home_gateway(card, own, root, home, record).await;
    }
    if record.prekey_http_url.is_empty() {
        return Err(ContactReason::ManifestInvalid.into());
    }
    Ok(CardHome { gateway: own.clone(), node_id, directory_base: Some(record.prekey_http_url) })
}

async fn same_home_gateway(
    card: &ContactCardBody,
    own: &GatewaySessionConfig,
    root: &Path,
    home: &crate::NodeProfile,
    record: ramflux_protocol::WellKnownClientRecord,
) -> Result<CardHome, SdkError> {
    if crate::contact_node_fingerprint(&home.node_public_key)? != card.node.key_fingerprint {
        return Err(ContactReason::NodeFingerprintMismatch.into());
    }
    if home.node_public_key != record.node_public_key {
        return Err(ContactReason::NodeFingerprintMismatch.into());
    }
    let profile =
        crate::node::NodeProfile::from_record(record, now_unix_timestamp().unsigned_abs());
    let mut gateway = own.clone();
    gateway.gateway_addr = crate::node::resolve_node_addr(&profile.gateway.quic_addr)
        .await
        .map_err(|error| SdkError::ContactUnavailable(Box::new(error)))?;
    gateway.tcp_gateway_addr = Some(
        crate::node::resolve_node_addr(&profile.gateway.tcp_addr)
            .await
            .map_err(|error| SdkError::ContactUnavailable(Box::new(error)))?,
    );
    gateway.server_name.clone_from(&profile.gateway.server_name);
    gateway.ca_cert = profile.write_ca(&root.join("contact_nodes"))?;
    Ok(CardHome { gateway, node_id: home.node_id.clone(), directory_base: None })
}

pub(super) async fn export(
    state: &LocalBusDaemonState,
    id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account(state, id)?;
    let profile = account_home(state, id)?;
    let agent_retired = account.connection.as_ref().is_some_and(|connection| {
        connection
            .snapshot()
            .cause
            .as_ref()
            .is_some_and(crate::AccountNetworkingReason::agent_retired)
    });
    if let Some(native) = &account.client.born_v3_account {
        if agent_retired {
            return Err(SdkError::AgentCreationRefused("agent_retired"));
        }
        let now = crate::custody::network_now()?;
        let current =
            crate::custody::load_account_after_install(&state.config.data_root, id, now).await?;
        if current.record() != native.record() || current.branch_pending() {
            return Err(SdkError::NetworkingPending);
        }
        let body = ramflux_protocol::custody::ContactCardV3 {
            version: 3,
            principal_id: current.record().body.principal_id.clone(),
            account_anchor: current.record().body.account_anchor.clone(),
            master_public_key: current
                .record()
                .body
                .master_certificate
                .body
                .master_public_key
                .clone(),
            master_certificate: current.record().body.master_certificate.clone(),
            authority_head_hash: ramflux_protocol::custody::object_hash(current.record())?,
            authority_epoch: current.record().body.device_set_epoch,
            devices: current.record().body.devices.clone(),
            node_url: profile.discovery_origin().map_err(|_| ContactReason::HomeProfileStale)?,
            node_key_fingerprint: crate::contact_node_fingerprint(&profile.node_public_key)?,
            display_name: current.record().body.profile.display_name.clone(),
            issued_at: now,
            expires_at: now.saturating_add(7 * 24 * 60 * 60),
        };
        let card = current.sign_contact_card(
            super::super::custody_setup::primary_provider(&state.config).as_ref(),
            body,
            now,
        )?;
        let (card, link) = crate::contact_card_native::encode(&card, now_unix_timestamp())?;
        return Ok(local_bus_ok(json!({"card":card,"link":link})));
    }
    let root = account.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let identity = account
        .client
        .account_db()?
        .client_record("identity", &root.principal_id)?
        .unwrap_or_else(|| json!({}));
    let now = now_unix_timestamp();
    let (card, link) = crate::contact_card::encode_contact_card(
        ContactCardBody {
            version: 1,
            principal_id: root.principal_id.clone(),
            root_commitment: account.principal_commitment.clone(),
            root_public_key: ramflux_protocol::encode_base64url(
                root.signing_key.verifying_key().to_bytes(),
            ),
            node: ContactNode {
                url: profile.discovery_origin().map_err(|_| ContactReason::HomeProfileStale)?,
                key_fingerprint: crate::contact_node_fingerprint(&profile.node_public_key)?,
            },
            display_name: identity["display_name"].as_str().map(str::to_owned),
            kind_asserted: identity["kind"].as_str().map(str::to_owned),
            issued_at: now,
            expires_at: now.saturating_add(7 * 24 * 60 * 60),
            native_authority: None,
        },
        root.signing_key.to_bytes(),
        now,
    )?;
    Ok(local_bus_ok(json!({"card":card,"link":link})))
}

struct Selection {
    legacy: Option<LocalBusContactAddRequest>,
    card: Option<ContactCardBody>,
    selector: String,
    requester_is_peer: bool,
    replace_provisional_root: Option<String>,
}
fn parse_selector(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
) -> Result<Selection, SdkError> {
    let now = now_unix_timestamp();
    let legacy = if request.method == "contact.accept"
        && request.body.as_object().is_some_and(|o| o.len() == 1)
        && request.body.get("link_id").is_some()
    {
        let id = request.body["link_id"].as_str().ok_or(ContactReason::InvalidCard)?;
        let stored = account.client.account_db()?.friend_link(id)?;
        let own = [&account.gateway_config.principal_id, &account.principal_commitment];
        if !own.contains(&&stored.requester_id) && !own.contains(&&stored.target_id) {
            return Err(ContactReason::InvalidCard.into());
        }
        Some(LocalBusContactAddRequest {
            link_id: id.to_owned(),
            requester_id: stored.requester_id,
            target_id: stored.target_id,
        })
    } else if request.body.get("link_id").is_some()
        && request.body.get("principal_id").is_none()
        && request.body.get("card").is_none()
    {
        Some(serde_json::from_value::<LocalBusContactAddRequest>(request.body.clone())?)
    } else {
        None
    };
    let parsed: Option<Add> = if legacy.is_none() {
        Some(serde_json::from_value(request.body.clone()).map_err(|_| ContactReason::InvalidCard)?)
    } else {
        None
    };
    if parsed.as_ref().and_then(|add| add.note.as_ref()).is_some_and(|note| {
        note.chars().count() > 140 || !ramflux_protocol::text_safety::single_line_is_safe(note)
    }) {
        return Err(ContactReason::InvalidRequestNote.into());
    }
    let card = parsed
        .as_ref()
        .and_then(|a| a.card.as_deref())
        .map(|c| crate::parse_contact_card(c, now))
        .transpose()?;
    if let Some(card) = &card
        && account.client.born_v3_account.is_some()
        && card.version != 3
    {
        return Err(SdkError::CustodyModeDowngrade);
    }
    let selector = match (&parsed, &legacy, &card) {
        (
            Some(Add {
                principal_id: Some(id), card: None, replace_provisional_root: None, ..
            }),
            _,
            _,
        ) => id.clone(),
        (Some(Add { principal_id: None, card: Some(_), .. }), _, Some(c)) => c.principal_id.clone(),
        (_, Some(old), _) => {
            if request.method == "contact.accept"
                && (old.target_id == account.gateway_config.principal_id
                    || old.target_id == account.principal_commitment)
            {
                old.requester_id.clone()
            } else {
                old.target_id.clone()
            }
        }
        _ => return Err(ContactReason::InvalidCard.into()),
    };
    let requester_is_peer = request.method == "contact.accept"
        && legacy.as_ref().is_none_or(|old| old.requester_id == selector);
    let replace_provisional_root = parsed.and_then(|a| a.replace_provisional_root);
    // `@name` waits for the username directory (USERNAME-DIR-LIVE, #461). That
    // directory is not on this branch, so a leading `@` is an invalid card.
    username_directory_selector(&selector)?;
    Ok(Selection { legacy, card, selector, requester_is_peer, replace_provisional_root })
}

fn username_directory_selector(selector: &str) -> Result<(), SdkError> {
    if selector.as_bytes().first() == Some(&b'@') {
        return Err(ContactReason::InvalidCard.into());
    }
    Ok(())
}

fn account_home(state: &LocalBusDaemonState, id: &str) -> Result<crate::NodeProfile, SdkError> {
    let account = local_bus_account(state, id)?;
    let _born = account.client.born_v3_account.as_ref().ok_or(SdkError::CustodyModeDowngrade)?;
    let node = account.client.account_db()?.load_actor_state::<String>("account/node-id")?;
    let node = node.as_deref().ok_or(ContactReason::HomeProfileMissing)?;
    let profile = state.nodes.profiles.get(node).ok_or(ContactReason::HomeProfileMissing)?;
    if !profile.enabled
        || profile.expires_at <= now_unix_timestamp().unsigned_abs()
        || profile.safety_warnings.contains("key_changed")
        || crate::contact_node_fingerprint(&profile.node_public_key).is_err()
    {
        return Err(ContactReason::HomeProfileStale.into());
    }
    Ok(profile.clone())
}

#[cfg(test)]
#[path = "tests/native_contact_card.rs"]
mod native_card_tests;

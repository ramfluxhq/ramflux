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
    principal_id: Option<String>,
    card: Option<String>,
}

pub(super) async fn add(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let Selection { legacy, card, selector, requester_is_peer } =
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
    if legacy.is_none()
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
    let gateway = match card.as_ref() {
        Some(card) => {
            let home = account_home(state, account_id)?;
            card_gateway(card, &own, &state.config.data_root, home.as_ref()).await?
        }
        None => own.clone(),
    };
    let link = legacy.as_ref().map_or_else(
        || {
            format!(
                "contact:{}",
                ramflux_protocol::hash_hex(
                    "ramflux.contact.link.v1",
                    format!("{}:{selector}", own.principal_id).as_bytes()
                )
            )
        },
        |old| old.link_id.clone(),
    );
    let account = local_bus_account(state, account_id)?;
    let contact = account
        .client
        .resolve_contact(
            &gateway,
            &own,
            ContactResolution {
                selector: &selector,
                expected_root: card.as_ref().map(|c| c.root_commitment.as_str()),
                card: card.as_ref(),
                link_id: link.clone(),
                allow_commitment: legacy.is_some(),
                requester_is_peer,
            },
        )
        .await?;
    let mut response = json!({"contact":contact});
    if legacy.is_some() {
        let record = account
            .client
            .friend_links()?
            .into_iter()
            .find(|r| r.link_id == link)
            .ok_or(ContactReason::UnknownPrincipal)?;
        if let Value::Object(fields) = serde_json::to_value(record)? {
            response.as_object_mut().ok_or(ContactReason::InvalidCard)?.extend(fields);
        }
    }
    Ok(local_bus_ok(response))
}

async fn card_gateway(
    card: &ContactCardBody,
    own: &GatewaySessionConfig,
    root: &Path,
    home: Option<&crate::NodeProfile>,
) -> Result<GatewaySessionConfig, SdkError> {
    let record = crate::node::fetch_client_record(&card.node.url).await.map_err(lookup_failure)?;
    if crate::contact_node_fingerprint(&record.node_public_key)? != card.node.key_fingerprint {
        return Err(ContactReason::CardSignatureInvalid.into());
    }
    if let Some(home) = home {
        if home.node_id != record.node_id {
            return Err(SdkError::ContactHomeNodeUnsupported);
        }
        if home.node_public_key != record.node_public_key {
            return Err(ContactReason::CardSignatureInvalid.into());
        }
    } else if record.gateway_server_name != own.server_name
        || record.node_ca_cert_pem.trim() != std::fs::read_to_string(&own.ca_cert)?.trim()
    {
        return Err(SdkError::ContactHomeNodeUnsupported);
    }
    let profile =
        crate::node::NodeProfile::from_record(record, now_unix_timestamp().unsigned_abs());
    let mut gateway = own.clone();
    gateway.gateway_addr =
        crate::node::resolve_node_addr(&profile.gateway.quic_addr).await.map_err(lookup_failure)?;
    gateway.tcp_gateway_addr = Some(
        crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await.map_err(lookup_failure)?,
    );
    gateway.server_name.clone_from(&profile.gateway.server_name);
    gateway.ca_cert = profile.write_ca(&root.join("contact_nodes"))?;
    Ok(gateway)
}

pub(super) fn export(
    state: &LocalBusDaemonState,
    id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account(state, id)?;
    let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
        &state.config.data_root,
        id,
    ))?;
    let node_id = manifest
        .node_id
        .as_deref()
        .ok_or_else(|| SdkError::LocalBus("contact cards require a bound home node".into()))?;
    let profile = state
        .nodes
        .selected(Some(node_id), false)?
        .ok_or_else(|| SdkError::LocalBus("contact cards require a configured home node".into()))?;
    if profile.expires_at <= now_unix_timestamp().unsigned_abs()
        || profile.safety_warnings.contains("key_changed")
    {
        return Err(SdkError::LocalBus(
            "refresh the home node before exporting a contact card".into(),
        ));
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
                url: if profile.discovery_url.is_empty() {
                    format!("https://{}", profile.node_id)
                } else {
                    profile.discovery_url
                },
                key_fingerprint: crate::contact_node_fingerprint(&profile.node_public_key)?,
            },
            display_name: identity["display_name"].as_str().map(str::to_owned),
            kind_asserted: identity["kind"].as_str().map(str::to_owned),
            issued_at: now,
            expires_at: now.saturating_add(7 * 24 * 60 * 60),
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
    let card = parsed
        .as_ref()
        .and_then(|a| a.card.as_deref())
        .map(|c| crate::parse_contact_card(c, now))
        .transpose()?;
    let selector = match (&parsed, &legacy, &card) {
        (Some(Add { principal_id: Some(id), card: None }), _, _) => id.clone(),
        (Some(Add { principal_id: None, card: Some(_) }), _, Some(c)) => c.principal_id.clone(),
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
    Ok(Selection { legacy, card, selector, requester_is_peer })
}

fn account_home(
    state: &LocalBusDaemonState,
    id: &str,
) -> Result<Option<crate::NodeProfile>, SdkError> {
    let path = local_bus_account_manifest_path(&state.config.data_root, id);
    if !path.exists() {
        return Ok(None);
    }
    let account = read_local_bus_account_manifest(&path)?;
    account
        .node_id
        .as_deref()
        .map(|id| state.nodes.selected(Some(id), false))
        .transpose()
        .map(Option::flatten)
}

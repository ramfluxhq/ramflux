// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compare-and-record contact safety. Only material reloaded inside the commit is verified.
use super::own_contact::{contact_link_restricted, contact_peer};
use crate::{
    ContactReason, RamfluxClient, SdkContactSafetyNumber, SdkDeviceManifestResponse, SdkError,
};
use prost::Message as _;
use ramflux_protocol::message as g;
use ramflux_protocol::message::identity;
use ramflux_storage::ContactVerificationUpdate;
use std::cell::Cell;

thread_local! {
    static INTERRUPT_AT: Cell<u8> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn test_interrupt_cas_at(step: u8) {
    INTERRUPT_AT.with(|interrupt| interrupt.set(step));
}

#[cfg(test)]
type BeforeCasHook = Box<dyn FnMut(&RamfluxClient) -> Result<(), SdkError>>;

#[cfg(test)]
thread_local! {
    static BEFORE_TXN: std::cell::RefCell<Option<BeforeCasHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn test_before_cas_transaction(hook: BeforeCasHook) {
    BEFORE_TXN.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(test)]
pub(crate) fn test_clear_cas_hooks() {
    INTERRUPT_AT.with(|interrupt| interrupt.set(0));
    BEFORE_TXN.with(|slot| *slot.borrow_mut() = None);
}

fn interrupt(step: u8) -> Result<(), SdkError> {
    let armed = INTERRUPT_AT.with(std::cell::Cell::get);
    if armed == step {
        return Err(SdkError::LocalBus("contact safety commit interrupted".into()));
    }
    Ok(())
}

#[cfg(test)]
fn before_transaction(client: &RamfluxClient) -> Result<(), SdkError> {
    let hook = BEFORE_TXN.with(|slot| slot.borrow_mut().take());
    if let Some(mut hook) = hook {
        return hook(client);
    }
    Ok(())
}

fn required(reason: ContactReason) -> SdkError {
    SdkError::ContactInput(reason)
}

fn confirmation_key(commitment: &str) -> String {
    format!("identity/contact_safety_confirmation/{commitment}")
}

fn origin_inner_key(commitment: &str) -> String {
    format!("identity/contact_safety_origin_inner/{commitment}")
}

fn canonical_commitment(value: &str) -> bool {
    ramflux_protocol::decode_base64url(value)
        .is_ok_and(|bytes| bytes.len() == 32 && ramflux_protocol::encode_base64url(&bytes) == value)
}

fn validate_expected(expected: &g::ExpectedContactSafety) -> Result<(), SdkError> {
    let strings = [
        expected.self_identity_commitment.as_str(),
        expected.contact_identity_commitment.as_str(),
        expected.safety_number_hash.as_str(),
        expected.contact_device_set_hash.as_str(),
        expected.contact_lineage_head.as_str(),
        expected.self_authority_head.as_str(),
        expected.contact_authority_head.as_str(),
        expected.principal_id.as_str(),
        expected.link_id.as_str(),
    ];
    if expected.algorithm_version.is_none()
        || strings.iter().any(|value| value.is_empty())
        || expected.replace_provisional_root.as_ref().is_some_and(String::is_empty)
    {
        return Err(required(ContactReason::ExpectedSafetyRequired));
    }
    Ok(())
}

fn material_eq(left: &g::ExpectedContactSafety, right: &g::ExpectedContactSafety) -> bool {
    left.algorithm_version == right.algorithm_version
        && left.self_identity_commitment == right.self_identity_commitment
        && left.contact_identity_commitment == right.contact_identity_commitment
        && left.safety_number_hash == right.safety_number_hash
        && left.contact_device_set_hash == right.contact_device_set_hash
        && left.contact_lineage_head == right.contact_lineage_head
        && left.self_authority_head == right.self_authority_head
        && left.contact_authority_head == right.contact_authority_head
        && left.principal_id == right.principal_id
        && left.link_id == right.link_id
}

struct Snapshot {
    expected: g::ExpectedContactSafety,
    stamp: String,
    safety: SdkContactSafetyNumber,
}

fn custody_snapshot(
    client: &RamfluxClient,
    commitment: &str,
    link_id: &str,
) -> Result<Snapshot, SdkError> {
    let now = crate::custody::network_now()?;
    let own_anchor = client.own_account_anchor()?;
    let own =
        client.current_custody_authority(&own_anchor, now)?.ok_or(SdkError::NetworkingPending)?;
    let peer =
        client.current_custody_authority(commitment, now)?.ok_or(SdkError::NetworkingPending)?;
    let safety = super::native_safety::safety_from_native(&own, &peer, "unverified".into())?;
    let stamp = safety.contact_device_set_hash.clone();
    let expected = expected_from_safety(
        &safety,
        ramflux_protocol::custody::object_hash(own.envelope())?,
        ramflux_protocol::custody::object_hash(peer.envelope())?,
        peer.envelope().body.principal_id.clone(),
        link_id,
    );
    Ok(Snapshot { expected, stamp, safety })
}

fn expected_from_safety(
    safety: &SdkContactSafetyNumber,
    self_authority_head: String,
    contact_authority_head: String,
    principal_id: String,
    link_id: &str,
) -> g::ExpectedContactSafety {
    g::ExpectedContactSafety {
        algorithm_version: Some(safety.algorithm_version),
        self_identity_commitment: safety.self_identity_commitment.clone(),
        contact_identity_commitment: safety.contact_identity_commitment.clone(),
        safety_number_hash: safety.safety_number_hash.clone(),
        contact_device_set_hash: safety.contact_device_set_hash.clone(),
        contact_lineage_head: safety.contact_lineage_head.clone(),
        self_authority_head,
        contact_authority_head,
        principal_id,
        link_id: link_id.to_owned(),
        replace_provisional_root: None,
    }
}

fn fill_replacement(
    client: &RamfluxClient,
    expected: &mut g::ExpectedContactSafety,
) -> Result<(), SdkError> {
    let Some(identity) = client.account_db()?.client_record("identity", &expected.principal_id)?
    else {
        return Ok(());
    };
    let Some(old) = identity["contact_identity_commitment"].as_str() else {
        return Ok(());
    };
    if old == expected.contact_identity_commitment {
        return Ok(());
    }
    if client.contact_root_source(&identity)? != crate::ContactRootSource::Lookup {
        return Ok(());
    }
    expected.replace_provisional_root = Some(old.to_owned());
    if expected.link_id.is_empty() {
        let anchor = client.own_account_anchor()?;
        if let Some(link) = client
            .friend_links()?
            .into_iter()
            .find(|link| link.state == "accepted" && contact_peer(link, &anchor) == Some(old))
        {
            expected.link_id = link.link_id;
        }
    }
    Ok(())
}

fn held_pair(
    client: &RamfluxClient,
    own: &str,
    commitment: &str,
) -> (Option<SdkDeviceManifestResponse>, Option<SdkDeviceManifestResponse>) {
    let held = client.held_manifests.borrow();
    (held.get(own).cloned(), held.get(commitment).cloned())
}

fn held_custody_snapshot(
    client: &RamfluxClient,
    commitment: &str,
    link_id: &str,
) -> Result<Snapshot, SdkError> {
    let own_anchor = client.own_account_anchor()?;
    let (own_manifest, peer_manifest) = held_pair(client, &own_anchor, commitment);
    let own_manifest = own_manifest.ok_or(SdkError::NetworkingPending)?;
    let peer_manifest = peer_manifest.ok_or(SdkError::NetworkingPending)?;
    let own_native = own_manifest.custody.as_deref().ok_or(SdkError::CustodyModeDowngrade)?;
    let peer_native = peer_manifest.custody.as_deref().ok_or(SdkError::CustodyModeDowngrade)?;
    let own = RamfluxClient::authenticate_custody_manifest(own_native, &own_anchor)?;
    let peer = RamfluxClient::authenticate_custody_manifest(peer_native, commitment)?;
    let safety = super::native_safety::safety_from_native(&own, &peer, "unverified".into())?;
    let stamp = safety.contact_device_set_hash.clone();
    let expected = expected_from_safety(
        &safety,
        ramflux_protocol::custody::object_hash(own.envelope())?,
        ramflux_protocol::custody::object_hash(peer.envelope())?,
        peer.envelope().body.principal_id.clone(),
        link_id,
    );
    Ok(Snapshot { expected, stamp, safety })
}

fn load_snapshot(
    client: &RamfluxClient,
    commitment: &str,
    link_id: &str,
) -> Result<Snapshot, SdkError> {
    // Every account is born-v3. A missing custody account is not a second comparison.
    if client.born_v3_account.is_none() {
        return Err(SdkError::CustodyModeDowngrade);
    }
    let now = crate::custody::network_now()?;
    let own = client.own_account_anchor()?;
    // One custody algorithm. Admitted pins win. Until this commit stores them, the
    // in-memory hold is the same material the preview returned.
    if client.current_custody_authority(&own, now)?.is_some()
        && client.current_custody_authority(commitment, now)?.is_some()
    {
        return custody_snapshot(client, commitment, link_id);
    }
    held_custody_snapshot(client, commitment, link_id)
}

fn persist_held_for_commit(client: &RamfluxClient, contact: &str) -> Result<(), SdkError> {
    let own = client.own_account_anchor()?;
    let keys = [own, contact.to_owned()];
    let manifests = {
        let held = client.held_manifests.borrow();
        keys.iter().filter_map(|key| held.get(key).cloned()).collect::<Vec<_>>()
    };
    if client.born_v3_account.is_none() {
        return Err(SdkError::CustodyModeDowngrade);
    }
    for manifest in &manifests {
        retain_compared_manifest(client, manifest)?;
        if let Some(custody) = manifest.custody.as_deref() {
            client.stage_candidate_pins(custody, &manifest.principal_commitment)?;
        }
    }
    Ok(())
}

fn release_compared_manifests(
    client: &RamfluxClient,
    expected: &g::ExpectedContactSafety,
) -> Result<(), SdkError> {
    let own = client.own_account_anchor()?;
    let mut held = client.held_manifests.borrow_mut();
    held.remove(&own);
    held.remove(&expected.contact_identity_commitment);
    Ok(())
}

pub(crate) fn retain_compared_manifest(
    client: &RamfluxClient,
    manifest: &SdkDeviceManifestResponse,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    if let Some(record) = manifest.signed_device_set.as_ref() {
        client.check_observed_set(record)?;
        db.persist_actor_state(
            &super::identity_authority::record_key(&record.principal_commitment),
            record,
        )?;
    }
    // A fetched candidate is display material. It does not adopt the principal pin.
    db.persist_actor_state(
        &format!("identity/manifest-root/{}", manifest.principal_commitment),
        manifest,
    )?;
    if db.client_record("commitment", &manifest.principal_commitment)?.is_none() {
        db.persist_client_record(
            "commitment",
            &manifest.principal_commitment,
            &serde_json::json!({ "principal_id": manifest.principal_id }),
        )?;
    }
    Ok(())
}

/// Read the authenticated safety fields a human can compare. Does not record a grant.
///
/// # Errors
/// Returns authority, link, and storage errors. Missing authority is [`SdkError::NetworkingPending`].
#[cfg(test)]
#[must_use = "the snapshot is the only value a later compare-and-record may submit"]
pub(crate) fn preview_contact_safety_expectation(
    client: &RamfluxClient,
    commitment: &str,
    link_id: &str,
) -> Result<g::ExpectedContactSafety, SdkError> {
    Ok(load_snapshot(client, commitment, link_id)?.expected)
}

#[cfg(test)]
pub(crate) fn current_contact_safety_expectation(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<g::ExpectedContactSafety, SdkError> {
    let own = client.own_account_anchor()?;
    let links = client.friend_links()?;
    let linked =
        |link: &ramflux_storage::FriendLinkRecord| contact_peer(link, &own) == Some(commitment);
    let link_id = links
        .iter()
        .find(|link| link.state == "accepted" && linked(link))
        .or_else(|| links.iter().find(|link| contact_link_restricted(link) && linked(link)))
        .map(|link| link.link_id.clone())
        .ok_or_else(|| SdkError::LocalBus("contact is not linked to this account".into()))?;
    preview_contact_safety_expectation(client, commitment, &link_id)
}

fn stored_confirmation(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<Option<(g::ContactSafetyConfirmation, Vec<u8>)>, SdkError> {
    let db = client.account_db()?;
    let Some(encoded) = db.load_actor_state::<String>(&confirmation_key(commitment))? else {
        return Ok(None);
    };
    let bytes = ramflux_protocol::decode_base64url(&encoded)
        .map_err(|_| SdkError::InboundRejected("safety confirmation encoding".into()))?;
    let confirmation = g::ContactSafetyConfirmation::decode(bytes.as_slice())
        .map_err(|_| SdkError::InboundRejected("safety confirmation malformed".into()))?;
    let Some(inner_encoded) = db.load_actor_state::<String>(&origin_inner_key(commitment))? else {
        return Ok(None);
    };
    let inner = ramflux_protocol::decode_base64url(&inner_encoded)
        .map_err(|_| SdkError::InboundRejected("safety origin encoding".into()))?;
    Ok(Some((confirmation, inner)))
}

fn confirmation_is_current(
    confirmation: &g::ContactSafetyConfirmation,
    inner: &[u8],
    snapshot: &g::ExpectedContactSafety,
) -> bool {
    let Some(expected) = confirmation.expected.as_ref() else {
        return false;
    };
    let Some(origin) = confirmation.origin.as_ref() else {
        return false;
    };
    if !material_eq(expected, snapshot)
        || confirmation.verified_at.is_none_or(|at| at < 0)
        || identity::verify(origin).is_err()
    {
        return false;
    }
    let Ok(decoded) = g::Inner::decode(inner) else {
        return false;
    };
    decoded.identity.as_ref() == Some(origin)
        && decoded.identity.as_ref().is_some_and(|identity| identity.group_id.is_none())
        && decoded.identity.as_ref().is_some_and(|identity| identity.group_epoch.is_none())
}

enum Decision {
    Blocked,
    Ready { state: String, snapshot: Box<Snapshot> },
}

fn link_id_for(client: &RamfluxClient, anchor: &str, commitment: &str) -> Result<String, SdkError> {
    Ok(client
        .friend_links()?
        .into_iter()
        .find(|link| link.state == "accepted" && contact_peer(link, anchor) == Some(commitment))
        .map(|link| link.link_id)
        .unwrap_or_default())
}

fn restricted(client: &RamfluxClient, anchor: &str, commitment: &str) -> Result<bool, SdkError> {
    Ok(client.friend_links()?.iter().any(|link| {
        contact_peer(link, anchor) == Some(commitment) && contact_link_restricted(link)
    }))
}

fn derive_available(
    stored: Option<&ramflux_storage::ContactVerificationRecord>,
    saved: Option<&(g::ContactSafetyConfirmation, Vec<u8>)>,
    snapshot: &Snapshot,
) -> String {
    if let Some((confirmation, inner)) = saved
        && confirmation_is_current(confirmation, inner, &snapshot.expected)
    {
        return "verified".into();
    }
    if stored.is_some_and(|row| row.verification_state == "changed") {
        return "changed".into();
    }
    if saved.is_some() {
        return "verification_stale".into();
    }
    "unverified".into()
}

fn decide(client: &RamfluxClient, commitment: &str) -> Result<Decision, SdkError> {
    let db = client.account_db()?;
    let stored = db.contact_verification(commitment)?;
    if stored.as_ref().is_some_and(|row| row.verification_state == "blocked_by_policy") {
        return Ok(Decision::Blocked);
    }
    let anchor = client.own_account_anchor()?;
    if restricted(client, &anchor, commitment)? {
        return Ok(Decision::Blocked);
    }
    let link_id = link_id_for(client, &anchor, commitment)?;
    let snapshot = load_snapshot(client, commitment, &link_id)?;
    let saved = stored_confirmation(client, commitment)?;
    if stored.as_ref().is_some_and(|row| row.verification_state == "verified") && saved.is_none() {
        return Err(SdkError::InboundRejected("safety confirmation missing".into()));
    }
    let state = derive_available(stored.as_ref(), saved.as_ref(), &snapshot);
    Ok(Decision::Ready { state, snapshot: Box::new(snapshot) })
}

fn effective_in_place(client: &RamfluxClient, commitment: &str) -> Result<String, SdkError> {
    Ok(match decide(client, commitment)? {
        Decision::Blocked => "blocked_by_policy".into(),
        Decision::Ready { state, .. } => state,
    })
}

pub(crate) fn effective_state(
    client: &RamfluxClient,
    commitment: &str,
    _observed_hash: Option<&str>,
) -> Result<String, SdkError> {
    // A missing custody account is the same typed error as the other gates.
    if client.born_v3_account.is_none() {
        return Err(SdkError::CustodyModeDowngrade);
    }
    let db = client.account_db()?;
    if db.is_query_only()? || db.in_transaction()? {
        effective_in_place(client, commitment)
    } else {
        db.read_snapshot(|| effective_in_place(client, commitment))
    }
}

pub(crate) fn compared_safety_json(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<serde_json::Value, SdkError> {
    match decide(client, commitment)? {
        Decision::Blocked => blocked_compared_json(client, commitment),
        Decision::Ready { state, mut snapshot } => {
            fill_replacement(client, &mut snapshot.expected)?;
            ready_compared_json(state, *snapshot)
        }
    }
}

fn ready_compared_json(state: String, snapshot: Snapshot) -> Result<serde_json::Value, SdkError> {
    let mut safety = snapshot.safety;
    safety.verification_state = state;
    let mut value = serde_json::to_value(safety)?;
    value["expected"] = serde_json::to_value(snapshot.expected)?;
    Ok(value)
}

fn blocked_compared_json(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<serde_json::Value, SdkError> {
    let mut safety = client.contact_safety_number(commitment)?;
    safety.verification_state = "blocked_by_policy".into();
    let mut value = serde_json::to_value(safety)?;
    if let Ok(anchor) = client.own_account_anchor() {
        let link_id = link_id_for(client, &anchor, commitment)?;
        if let Ok(snapshot) = load_snapshot(client, commitment, &link_id) {
            let mut expected = snapshot.expected;
            fill_replacement(client, &mut expected)?;
            value["expected"] = serde_json::to_value(expected)?;
        }
    }
    Ok(value)
}

fn author_matches(
    client: &RamfluxClient,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    author: &g::QualifiedDevice,
) -> Result<bool, SdkError> {
    let epoch = client
        .account_db()?
        .client_device_record(source)?
        .and_then(|record| record["device_epoch"].as_u64());
    Ok(author.account_anchor == source.root_commitment()
        && author.device_id == source.device_id()
        && Some(author.device_epoch) == epoch)
}

fn persist_grant(
    client: &RamfluxClient,
    snapshot: &Snapshot,
    confirmation: &g::ContactSafetyConfirmation,
    exact_inner: &[u8],
    verified_by: &str,
    verified_at: i64,
) -> Result<(), SdkError> {
    let commitment = snapshot.expected.contact_identity_commitment.as_str();
    let db = client.account_db()?;
    interrupt(1)?;
    db.persist_actor_state(
        &confirmation_key(commitment),
        &ramflux_protocol::encode_base64url(confirmation.encode_to_vec()),
    )?;
    db.persist_actor_state(
        &origin_inner_key(commitment),
        &ramflux_protocol::encode_base64url(exact_inner),
    )?;
    interrupt(2)?;
    db.mark_contact_verified(ContactVerificationUpdate {
        contact_identity_commitment: commitment,
        safety_number_hash: &snapshot.expected.safety_number_hash,
        device_set_hash: &snapshot.expected.contact_device_set_hash,
        lineage_head: &snapshot.expected.contact_lineage_head,
        verified_at,
        verified_by_device_id: verified_by,
    })?;
    db.persist_actor_state(&format!("identity/safety_verified_set/{commitment}"), &snapshot.stamp)?;
    interrupt(3)?;
    let origin =
        confirmation.origin.as_ref().map(|identity| identity.id.as_slice()).unwrap_or_default();
    db.append_journal(
        &format!(
            "contact-safety-cas:{}:{}",
            commitment,
            ramflux_protocol::encode_base64url(origin)
        ),
        "safety.changed",
        &serde_json::json!({
            "contact_identity_commitment": commitment,
            "reason": "contact_safety_verified",
        }),
        verified_at,
        Some(commitment),
    )?;
    interrupt(4)?;
    Ok(())
}

fn higher_order(left: &g::EventIdentity, right: &g::EventIdentity) -> Result<bool, SdkError> {
    let left = identity::order_key(left).map_err(|_| SdkError::ReplayMismatch)?;
    let right = identity::order_key(right).map_err(|_| SdkError::ReplayMismatch)?;
    Ok(left > right)
}

fn install_matching(
    client: &RamfluxClient,
    confirmation: &g::ContactSafetyConfirmation,
    exact_inner: &[u8],
    snapshot: &Snapshot,
) -> Result<(), SdkError> {
    let commitment = snapshot.expected.contact_identity_commitment.as_str();
    let origin = confirmation.origin.as_ref().ok_or(SdkError::ReplayMismatch)?;
    if let Some((stored, stored_inner)) = stored_confirmation(client, commitment)? {
        let stored_origin = stored.origin.as_ref().ok_or(SdkError::ReplayMismatch)?;
        if stored_origin.id == origin.id && stored_inner != exact_inner {
            return Err(SdkError::ReplayMismatch);
        }
        let stored_is_current = confirmation_is_current(&stored, &stored_inner, &snapshot.expected);
        if stored_is_current
            && stored_origin.id != origin.id
            && !higher_order(origin, stored_origin)?
        {
            return Ok(());
        }
    }
    let verified_at = confirmation.verified_at.ok_or(SdkError::ReplayMismatch)?;
    let device = origin.author.as_ref().map_or("", |author| author.device_id.as_str());
    persist_grant(client, snapshot, confirmation, exact_inner, device, verified_at)
}

pub(crate) fn install_sibling_confirmation(
    client: &RamfluxClient,
    sync: &g::OwnContactSync,
    identity: &g::EventIdentity,
    exact_inner: &[u8],
) -> Result<(), SdkError> {
    let Some(confirmation) = sync.safety_confirmation.as_ref() else {
        return Ok(());
    };
    let Some(expected) = confirmation.expected.as_ref() else {
        return Ok(());
    };
    let Some(origin) = confirmation.origin.as_ref() else {
        return Ok(());
    };
    if origin != identity
        || identity::verify(origin).is_err()
        || confirmation.verified_at.is_none_or(|at| at < 0)
    {
        return Ok(());
    }
    let own = client.own_account_anchor()?;
    let db = client.account_db()?;
    let Ok(link) = db.friend_link(&expected.link_id) else {
        return Ok(());
    };
    if contact_link_restricted(&link)
        || contact_peer(&link, &own).is_none()
        || db
            .contact_verification(&expected.contact_identity_commitment)?
            .is_some_and(|row| row.verification_state == "blocked_by_policy")
    {
        return Ok(());
    }
    let snapshot =
        match load_snapshot(client, &expected.contact_identity_commitment, &expected.link_id) {
            Ok(snapshot) => snapshot,
            Err(SdkError::NetworkingPending) => return Err(SdkError::NetworkingPending),
            Err(_) => return Ok(()),
        };
    if !material_eq(expected, &snapshot.expected) {
        return Ok(());
    }
    install_matching(client, confirmation, exact_inner, &snapshot)
}

/// Installs a sibling confirmation only when its origin is the authenticated source device.
/// A confirmation authored by any other device, or whose origin differs from the carrying
/// identity, is dropped without a trace.
pub(crate) fn install_sibling_confirmation_from(
    client: &RamfluxClient,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    sync: &g::OwnContactSync,
    identity: &g::EventIdentity,
    exact_inner: &[u8],
) -> Result<(), SdkError> {
    let Some(origin) = sync.safety_confirmation.as_ref().and_then(|c| c.origin.as_ref()) else {
        return Ok(());
    };
    let Some(author) = origin.author.as_ref() else {
        return Ok(());
    };
    if origin != identity || !author_matches(client, source, author)? {
        return Ok(());
    }
    install_sibling_confirmation(client, sync, identity, exact_inner)
}

pub(crate) fn stage_stored_origin(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<(), SdkError> {
    let Some((confirmation, inner)) = stored_confirmation(client, commitment)? else {
        return Ok(());
    };
    let Some(author) = confirmation.origin.as_ref().and_then(|origin| origin.author.as_ref())
    else {
        return Ok(());
    };
    let local = client.owned_device_identity()?;
    if !author_matches(client, &local, author)? {
        return Ok(());
    }
    client.stage_exact_own_contact_inner(&inner)?;
    Ok(())
}

pub(crate) fn history_item_carries_safety_grant(exact_inner: &[u8]) -> bool {
    let Ok(scanned) = g::validation::scan_inner(exact_inner) else {
        return false;
    };
    let Ok(control) = g::Control::decode(scanned.body) else {
        return false;
    };
    matches!(
        control.payload,
        Some(g::control::Payload::OwnContactSync(sync)) if sync.safety_confirmation.is_some()
    )
}

fn own_sync_body(
    client: &RamfluxClient,
    snapshot: &Snapshot,
    confirmation: g::ContactSafetyConfirmation,
) -> Result<g::OwnContactSync, SdkError> {
    let db = client.account_db()?;
    let link = db.friend_link(&snapshot.expected.link_id)?;
    let manifest = db
        .load_actor_state::<SdkDeviceManifestResponse>(&format!(
            "identity/manifest-root/{}",
            snapshot.expected.contact_identity_commitment
        ))?
        .or(db.load_actor_state::<SdkDeviceManifestResponse>(&format!(
            "identity/manifest/{}",
            snapshot.expected.principal_id
        ))?)
        .ok_or_else(|| required(ContactReason::ExpectedSafetyRequired))?;
    let manifest = g::NativeDeviceManifest::decode(
        client.encode_generated_task_manifest(&manifest)?.as_slice(),
    )
    .map_err(|_| required(ContactReason::ExpectedSafetyRequired))?;
    Ok(g::OwnContactSync {
        manifest: Some(manifest),
        link: Some(g::FriendLinkRecord {
            link_id: link.link_id,
            requester_id: link.requester_id,
            target_id: link.target_id,
            state: link.state,
            remove_scope: link.remove_scope,
            blocked: link.blocked,
            capability_revoked_at: link.capability_revoked_at,
        }),
        safety_confirmation: Some(confirmation),
    })
}

fn commit_compared(
    client: &RamfluxClient,
    expected: &g::ExpectedContactSafety,
) -> Result<g::ContactSafetyVerifyResult, SdkError> {
    let db = client.account_db()?;
    let own = client.own_account_anchor()?;
    let link = db.friend_link(&expected.link_id)?;
    if contact_link_restricted(&link)
        || db
            .contact_verification(&expected.contact_identity_commitment)?
            .is_some_and(|row| row.verification_state == "blocked_by_policy")
    {
        return Err(SdkError::LocalBus("contact safety verification is blocked".into()));
    }
    if contact_peer(&link, &own).is_none() {
        return Err(required(ContactReason::SafetyMaterialMismatch));
    }
    persist_held_for_commit(client, &expected.contact_identity_commitment)?;
    let mut snapshot = load_snapshot(client, &expected.contact_identity_commitment, &link.link_id)?;
    if !material_eq(expected, &snapshot.expected) {
        return Err(required(ContactReason::SafetyMaterialMismatch));
    }
    let identity_row = db
        .client_record("identity", &expected.principal_id)?
        .ok_or_else(|| required(ContactReason::SafetyMaterialMismatch))?;
    let replacement = client.contact_replacement(
        &identity_row,
        &expected.principal_id,
        &expected.contact_identity_commitment,
        expected.replace_provisional_root.as_deref(),
    )?;
    if let Some(change) = replacement {
        let linked = contact_peer(&link, &own)
            .ok_or_else(|| required(ContactReason::SafetyMaterialMismatch))?;
        if linked != change.previous_root_commitment {
            return Err(required(ContactReason::SafetyMaterialMismatch));
        }
        client.clear_provisional_contact(&identity_row, &change, &own)?;
        let mut pinned = identity_row.clone();
        pinned["contact_identity_commitment"] =
            serde_json::json!(expected.contact_identity_commitment);
        pinned["root_source"] = serde_json::json!(crate::ContactRootSource::Verified);
        db.persist_client_record("identity", &expected.principal_id, &pinned)?;
        snapshot = load_snapshot(client, &expected.contact_identity_commitment, &expected.link_id)?;
        if !material_eq(expected, &snapshot.expected) {
            return Err(required(ContactReason::SafetyMaterialMismatch));
        }
    } else if contact_peer(&link, &own) != Some(expected.contact_identity_commitment.as_str()) {
        return Err(required(ContactReason::SafetyMaterialMismatch));
    } else {
        let mut pinned = identity_row;
        pinned["root_source"] = serde_json::json!(crate::ContactRootSource::Verified);
        db.persist_client_record("identity", &expected.principal_id, &pinned)?;
    }
    let verified_at = crate::time::now_unix_timestamp();
    if verified_at < 0 {
        return Err(required(ContactReason::ExpectedSafetyRequired));
    }
    let origin = client.allocate_generated_identity_in(
        "own-contact",
        super::generated_identity::now_ms(),
        true,
    )?;
    if origin.group_id.is_some()
        || origin.group_epoch.is_some()
        || identity::verify(&origin).is_err()
    {
        return Err(required(ContactReason::ExpectedSafetyRequired));
    }
    let confirmation = g::ContactSafetyConfirmation {
        expected: Some(expected.clone()),
        origin: Some(origin.clone()),
        verified_at: Some(verified_at),
    };
    let sync = own_sync_body(client, &snapshot, confirmation.clone())?;
    let control =
        super::generated_control::control_from_payload(g::control::Payload::OwnContactSync(sync))?;
    let exact = RamfluxClient::encode_generated_inner(
        origin.clone(),
        &g::Content { value: Some(g::content::Value::Control(control)) },
    )?;
    let device = origin.author.as_ref().map_or("", |author| author.device_id.as_str());
    persist_grant(client, &snapshot, &confirmation, &exact, device, verified_at)?;
    let pending = client.stage_exact_own_contact_inner(&exact)?;
    interrupt(5)?;
    Ok(g::ContactSafetyVerifyResult {
        safety_confirmation: Some(confirmation),
        verification_state: "verified".into(),
        sibling_delivery_pending: Some(pending),
    })
}

impl RamfluxClient {
    /// Record verification only when every expected field matches reloaded local material.
    ///
    /// Authority is fetched before the immediate transaction. The transaction reloads it and
    /// rolls every confirmation effect back when comparison, replacement, or a later write fails.
    ///
    /// # Errors
    /// Returns [`ContactReason::ExpectedSafetyRequired`] for missing input,
    /// [`ContactReason::SafetyMaterialMismatch`] when any compared field differs,
    /// [`SdkError::ContactConfirmationRequired`] when a provisional root still needs its old pin,
    /// and the existing authority errors when material is fenced, expired, or unavailable.
    #[must_use = "the committed result is the verification grant; a sibling queue is not"]
    pub fn compare_and_record_contact_safety_verified(
        &self,
        expected: &g::ExpectedContactSafety,
    ) -> Result<g::ContactSafetyVerifyResult, SdkError> {
        validate_expected(expected)?;
        if !canonical_commitment(&expected.contact_identity_commitment) {
            return Err(required(ContactReason::SafetyMaterialMismatch));
        }
        let _ = load_snapshot(self, &self.own_account_anchor()?, "")?;
        let _ = load_snapshot(self, &expected.contact_identity_commitment, &expected.link_id)?;
        // A fence commits on its own, before the compare transaction can roll it back.
        refuse_fenced_held(self, &expected.contact_identity_commitment)?;
        #[cfg(test)]
        before_transaction(self)?;
        let committed =
            match self.account_db()?.write_transaction(|| commit_compared(self, expected)) {
                Err(error) if fence_rolled_back(&error) => {
                    refuse_fenced_held(self, &expected.contact_identity_commitment)?;
                    return Err(error);
                }
                other => other?,
            };
        release_compared_manifests(self, expected)?;
        let advanced = self.advance_committed_own_authority();
        let retired = self.finish_pair_retirement();
        advanced?;
        retired?;
        Ok(committed)
    }
}

fn fence_rolled_back(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::InboundRejected(message)
            if message == "identity authority: custody authority equivocation fenced"
    )
}

fn refuse_fenced_held(client: &RamfluxClient, contact: &str) -> Result<(), SdkError> {
    if client.born_v3_account.is_none() {
        return Err(SdkError::CustodyModeDowngrade);
    }
    let own = client.own_account_anchor()?;
    let manifests = {
        let held = client.held_manifests.borrow();
        [own, contact.to_owned()]
            .into_iter()
            .filter_map(|key| held.get(&key).cloned())
            .collect::<Vec<_>>()
    };
    for manifest in manifests {
        if let Some(custody) = manifest.custody.as_deref() {
            client.commit_equivocation_fence(custody, &manifest.principal_commitment)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "contact_verification_cas_tests.rs"]
mod contact_verification_cas_tests;

#[cfg(test)]
pub(crate) fn verify_linked_contact(
    client: &RamfluxClient,
    commitment: &str,
) -> Result<g::ContactSafetyVerifyResult, SdkError> {
    let expected = current_contact_safety_expectation(client, commitment)?;
    client.compare_and_record_contact_safety_verified(&expected)
}

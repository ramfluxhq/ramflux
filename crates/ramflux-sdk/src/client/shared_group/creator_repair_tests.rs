// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-fork repair is deferred on accept and signed natively when the primary is available.
use super::*;
use crate::bus::state::LocalBusAccountState;
use ramflux_protocol::SharedGroupRole;

const MARKER_PREFIX: &str = "group-state/creator-repair/";

struct Fork {
    phone: LocalBusAccountState,
    laptop: LocalBusAccountState,
    peer: LocalBusAccountState,
    incoming: ramflux_crypto::VerifiedGroupState,
}

fn stored(account: &LocalBusAccountState) -> Result<ramflux_crypto::VerifiedGroupState, SdkError> {
    account
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or_else(|| StorageError::GroupPermissionDenied.into())
}

fn markers(account: &LocalBusAccountState) -> Result<usize, SdkError> {
    Ok(account.client.account_db()?.list_actor_states::<serde_json::Value>(MARKER_PREFIX)?.len())
}

/// The owner's laptop renames the group while the phone durably removed a member: the phone
/// must repair the removal on top of the laptop's state before it may adopt it.
fn fork() -> Result<Fork, SdkError> {
    let mut phone = native_person("owner", "phone")?;
    let laptop = native_sibling(&mut phone, "owner-laptop", "laptop")?;
    let peer = native_person("peer", "peer")?;
    phone.client.fixture_group_create("group", "thread", None, "phone")?;
    let base = phone.client.fixture_group_change(
        "group",
        "phone",
        GroupStateChange::Add {
            member: peer.client.fixture_group_actor("peer")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    laptop.client.fixture_accept_group_state(&base, "laptop")?;
    phone.client.fixture_group_change(
        "group",
        "phone",
        GroupStateChange::Remove {
            root_commitment: peer.client.owned_device_identity()?.root_commitment().into(),
            device_id: "peer".into(),
        },
    )?;
    phone.client.account_db()?.remove_actor_state(&format!(
        "group-state/creator-pending/{}",
        ramflux_protocol::encode_base64url("group")
    ))?;
    for name in ["laptop first", "laptop latest"] {
        laptop.client.fixture_group_change(
            "group",
            "laptop",
            GroupStateChange::SetName { name: name.into() },
        )?;
    }
    let incoming = stored(&laptop)?;
    Ok(Fork { phone, laptop, peer, incoming })
}

fn assert_natively_repaired(fork: &Fork, repaired: &ramflux_crypto::VerifiedGroupState) {
    assert_eq!(repaired.view().name.as_deref(), Some("laptop latest"), "the winning name is kept");
    assert!(
        repaired
            .view()
            .effective_role(
                fork.peer
                    .client
                    .owned_device_identity()
                    .expect("test: peer identity")
                    .root_commitment(),
                "peer"
            )
            .is_none(),
        "the durable removal is repaired"
    );
    let issuer = &repaired.snapshot().issuer;
    assert!(issuer.native_authority.is_some(), "the repair carries native authority");
    assert!(issuer.root_signature.is_empty(), "the repair is not root-signed");
    assert_eq!(
        issuer.identity.device_id,
        fork.phone.client.owned_device_identity().expect("test: phone identity").device_id(),
        "the repair is signed by the creator device that redrove it"
    );
}

#[test]
fn accept_records_a_pending_repair_and_unlock_signs_it_natively() -> Result<(), SdkError> {
    let fork = fork()?;
    let target = native_target(&fork.phone.client)?;
    let before = stored(&fork.phone)?;
    assert!(
        !fork.phone.client.accept_shared_group_state(&fork.incoming, &target)?,
        "the accept path cannot sign, so it adopts nothing yet"
    );
    assert_eq!(markers(&fork.phone)?, 1, "one typed marker is pending");
    assert!(fork.phone.client.has_pending_creator_repairs()?);
    assert_eq!(
        stored(&fork.phone)?.snapshot().state_hash,
        before.snapshot().state_hash,
        "the unrepaired fork is never committed"
    );
    let primary = fork.phone.client.fixture_primary()?;
    assert_eq!(fork.phone.client.redrive_creator_repairs(primary.as_ref())?, 1);
    assert_eq!(markers(&fork.phone)?, 0, "the marker is cleared with the repair");
    let repaired = stored(&fork.phone)?;
    assert_natively_repaired(&fork, &repaired);
    assert_eq!(repaired.view().epoch, fork.incoming.view().epoch + 1, "one removal was signed");
    assert!(fork.laptop.client.fixture_accept_group_state(&repaired, "laptop")?);
    Ok(())
}

#[test]
fn a_missing_primary_keeps_the_repair_pending_with_a_typed_error() -> Result<(), SdkError> {
    let fork = fork()?;
    let target = native_target(&fork.phone.client)?;
    let before = stored(&fork.phone)?;
    assert!(!fork.phone.client.accept_shared_group_state(&fork.incoming, &target)?);
    assert!(
        matches!(
            fork.phone.client.redrive_creator_repairs(None),
            Err(SdkError::CustodyVaultUnavailable)
        ),
        "a missing primary is CustodyVaultUnavailable, never a root-signed fallback"
    );
    assert_eq!(markers(&fork.phone)?, 1, "the marker stays pending");
    assert_eq!(stored(&fork.phone)?.snapshot().state_hash, before.snapshot().state_hash);
    let primary = fork.phone.client.fixture_primary()?;
    assert_eq!(fork.phone.client.redrive_creator_repairs(primary.as_ref())?, 1);
    assert_natively_repaired(&fork, &stored(&fork.phone)?);
    Ok(())
}

#[test]
fn a_repeated_accept_around_the_redrive_repairs_exactly_once() -> Result<(), SdkError> {
    let fork = fork()?;
    let target = native_target(&fork.phone.client)?;
    assert!(!fork.phone.client.accept_shared_group_state(&fork.incoming, &target)?);
    assert!(!fork.phone.client.accept_shared_group_state(&fork.incoming, &target)?);
    assert_eq!(markers(&fork.phone)?, 1, "a repeated accept keeps one marker");
    let primary = fork.phone.client.fixture_primary()?;
    assert_eq!(fork.phone.client.redrive_creator_repairs(primary.as_ref())?, 1);
    let repaired = stored(&fork.phone)?;
    assert!(
        !fork.phone.client.accept_shared_group_state(&fork.incoming, &target)?,
        "the already-repaired fork is superseded"
    );
    assert_eq!(markers(&fork.phone)?, 0, "an accept after the repair records no new marker");
    assert_eq!(fork.phone.client.redrive_creator_repairs(primary.as_ref())?, 0);
    let after = stored(&fork.phone)?;
    assert_eq!(after.snapshot().state_hash, repaired.snapshot().state_hash, "no double advance");
    assert_eq!(after.view().epoch, fork.incoming.view().epoch + 1, "exactly one repair advance");
    Ok(())
}

#[test]
fn a_failing_repair_marker_does_not_block_the_next_group() -> Result<(), SdkError> {
    let fork = fork()?;
    let target = native_target(&fork.phone.client)?;
    assert!(!fork.phone.client.accept_shared_group_state(&fork.incoming, &target)?);
    // A marker that sorts before the good one and can never be repaired: its held snapshot fails
    // verification. base64url("a-poison") sorts before base64url("group").
    let mut snapshot = serde_json::to_value(fork.incoming.snapshot())?;
    snapshot["state_hash"] = serde_json::json!(ramflux_protocol::encode_base64url([7_u8; 32]));
    let poison_key = format!("{MARKER_PREFIX}{}", ramflux_protocol::encode_base64url("a-poison"));
    fork.phone.client.account_db()?.persist_actor_state(
        &poison_key,
        &serde_json::json!({
            "group_id": "a-poison", "target": target, "incoming": snapshot,
            "recorded_at": 1, "failures": 0, "last_error": null,
        }),
    )?;
    assert_eq!(markers(&fork.phone)?, 2, "one poisoned and one good marker are pending");
    let primary = fork.phone.client.fixture_primary()?;
    assert_eq!(
        fork.phone.client.redrive_creator_repairs(primary.as_ref())?,
        1,
        "the good group is repaired although the poisoned marker fails"
    );
    assert_natively_repaired(&fork, &stored(&fork.phone)?);
    assert_eq!(markers(&fork.phone)?, 1, "only the failing marker stays pending");
    let poisoned = fork
        .phone
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&poison_key)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(poisoned["failures"], 1, "the failure is recorded on the marker");
    assert!(poisoned["last_error"].as_str().is_some_and(|text| !text.is_empty()));
    Ok(())
}

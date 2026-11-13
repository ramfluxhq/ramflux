// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Construct one authenticated full-cap snapshot without replaying hundreds of SDK fanouts.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::group_state::{MAX_GROUP_STATE_MEMBERS, SharedGroupMember, SharedGroupRole};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;
pub(super) fn populate(
    client: &RamfluxClient,
    target: &str,
    primary: &ramflux_crypto::custody::SelfSigningKey,
) -> TestResult {
    let previous = client.account_db()?.shared_group_state("group")?.ok_or("group state")?;
    let mut snapshot = previous.snapshot().clone();
    snapshot.previous_hash = Some(snapshot.state_hash.clone());
    snapshot.epoch += 1;
    snapshot.state.epoch = snapshot.epoch;
    for index in 2..MAX_GROUP_STATE_MEMBERS {
        let mut seed = [0xd5; 32];
        let (counter, _) = seed.split_first_chunk_mut::<8>().ok_or("seed width")?;
        counter.copy_from_slice(&u64::try_from(index)?.to_le_bytes());
        let principal = format!("member-{index}");
        let identity = ramflux_crypto::certify_group_state_actor(
            &ramflux_crypto::create_identity_root(&principal, seed),
            &ramflux_crypto::create_device_branch(&principal, &format!("phone-{index}"), 1, seed),
            &format!("target-{index}"),
        )?
        .identity;
        snapshot.state.members.push(SharedGroupMember {
            identity,
            role: SharedGroupRole::Member,
            joined_epoch: snapshot.epoch,
        });
    }
    snapshot.state.members.sort_by(|a, b| {
        (&a.identity.root_commitment, &a.identity.device_id)
            .cmp(&(&b.identity.root_commitment, &b.identity.device_id))
    });
    // The full-state wire contract permits a creator-signed snapshot across arbitrary lag.
    // Keep native genesis and authority; sign the final roster once, then use the real verifier.
    let mut core = snapshot.state.clone();
    core.head_hash.clear();
    let content = json!({"domain":ramflux_protocol::group_state::GROUP_STATE_SNAPSHOT_DOMAIN,
        "genesis":snapshot.genesis, "creator":snapshot.creator, "transfers":snapshot.transfers,
        "group_id":snapshot.group_id, "epoch":snapshot.epoch, "previous_hash":snapshot.previous_hash,
        "state":core, "issued_at":snapshot.issued_at});
    snapshot.state_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.group_state.content.v2",
        &ramflux_protocol::canonical_json_bytes(&content)?,
    );
    snapshot.state.head_hash.clone_from(&snapshot.state_hash);
    let root_body = json!({"domain":"ramflux.group_state.creator_signature.v2",
        "content":content, "state_hash":snapshot.state_hash});
    snapshot.root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::canonical_json_bytes(&root_body)?,
        *primary.vault_seed(),
    );
    let mut transport = serde_json::to_value(&snapshot)?;
    transport.as_object_mut().ok_or("snapshot object")?.remove("signature");
    snapshot.signature = ramflux_crypto::sign_with_device_branch(
        client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &transport,
    )?;
    let verified = ramflux_crypto::verify_group_state_snapshot(snapshot)?;
    client
        .account_db()?
        .commit_shared_group_state(&verified, &client.owned_group_actor(target)?)?;
    Ok(())
}

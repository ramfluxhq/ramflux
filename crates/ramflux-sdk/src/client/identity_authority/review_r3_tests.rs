// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Qualified imports and root-bound enrollment retain their own authority checks.
use super::*;
#[tokio::test]
async fn own_import_checks_pending_local_fences_even_when_the_node_still_reports_active()
-> TestResult {
    let source = Actor::new("alice", "one", 101, 102, 1)?;
    let target = Actor::new("alice", "two", 101, 103, 1)?;
    let mut manifest = source.manifest()?;
    manifest.devices.extend(target.manifest()?.devices);
    sign_set(&source, &mut manifest, 1)?;
    observe(&target.client, &manifest)?;
    let reference = ramflux_protocol::qualified_device_id(&manifest.principal_commitment, "one")?;
    target.client.account_db()?.persist_actor_state(
        &RamfluxClient::device_revocation_key(&target.client.device_identity(&reference)?),
        &true,
    )?;
    // The pending local fence is checked before any node or cached authority can vouch for the
    // device, so a sibling the node still reports active cannot be used for own-device traffic.
    let identity = target.client.device_identity(&reference)?;
    let error = target
        .client
        .require_cached_root_authority(HeadUse::NewAuthorization, &identity)
        .err()
        .ok_or("pending revoked source was accepted")?;
    assert!(error.to_string().contains("locally fenced"), "{error}");
    assert_eq!(
        target.client.account_db()?.client_directory_ids("object", "", 100)?,
        Vec::<String>::new()
    );
    Ok(())
}
#[test]
fn root_bound_enrollment_rejects_address_shaped_literal_device_names() -> TestResult {
    let root = ramflux_crypto::create_identity_root("alice", [111; 32]);
    for name in [
        "root~junk".to_owned(),
        "legacy~name".to_owned(),
        ramflux_protocol::qualified_device_id("root", "phone")?,
    ] {
        let branch = ramflux_crypto::create_device_branch("alice", &name, 1, [112; 32]);
        assert!(
            ramflux_crypto::authorize_device_branch_v2(
                &root,
                &branch,
                ramflux_crypto::BranchAuthorization {
                    audience: "ramflux-node",
                    capability_scope: vec!["device.delivery.bind".into()],
                    issued_at: 1,
                    expires_at: 3600,
                    principal_kind: PrincipalKind::Human,
                    agreement_identity_public_key: X25519KeyPair::from_seed([113; 32]).public
                }
            )
            .is_err()
        );
    }
    Ok(())
}

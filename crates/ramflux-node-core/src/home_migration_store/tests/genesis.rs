// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Genesis requires a master declaration even after device-only registration.
use super::*;
use ramflux_protocol::home_migration::{AttestRequest, HomeDeclarationV1};

fn request_with(declaration: Option<Signed<HomeDeclarationV1>>) -> TestResult<AttestRequest> {
    let anchor = publication()?.record.body.account_anchor;
    let mut request = attest_request(&anchor, "B", &hash(121), NOW)?;
    request.payload.home_declaration = declaration.map(Box::new);
    request.control.body.payload_hash = ramflux_protocol::custody::framed_hash(
        ramflux_protocol::domain::HOME_ATTEST_REQUEST,
        &request.payload,
    )?;
    let authority = verify_record(&publication()?.record, NOW, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    request.control = crypto::sign_actor(request.control.body, &branch, &authority, NOW)?;
    Ok(request)
}

#[test]
fn genesis_requires_master_declaration_naming_this_node() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let anchor = publication()?.record.body.account_anchor;
    for declaration in [None, Some(declaration("C", NOW)?)] {
        let request = request_with(declaration)?;
        assert!(matches!(
            a.core.attest_home_migration(
                a.store()?,
                &a.node,
                AttestMigration { request: &request },
                NOW,
            ),
            Err(NodeCoreError::HomeMigration(Refusal::HomeDeclarationRequired))
        ));
        assert!(a.store()?.migration_home(&anchor)?.is_none());
    }
    Ok(())
}

#[test]
fn valid_declaration_genesis_is_idempotent_after_restart() -> TestResult {
    let mut a = TestNode::new("A", 8, true)?;
    let request = request_with(Some(declaration("A", NOW)?))?;
    let first = a.core.attest_home_migration(
        a.store()?,
        &a.node,
        AttestMigration { request: &request },
        NOW,
    )?;
    crypto::verify_home_chain(
        &ResolveResult { home: first.home.clone(), predecessors: vec![] },
        &first.home,
        NOW,
    )?;
    a.restart()?;
    let replay = a.core.attest_home_migration(
        a.store()?,
        &a.node,
        AttestMigration { request: &request },
        NOW + 1,
    )?;
    assert_eq!(first.home, replay.home);
    assert_eq!(replay.home.record.epoch(), 0);
    Ok(())
}

#[test]
fn declaration_rejects_branch_key_and_substituted_principal_root_or_home() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let good = declaration("A", NOW)?;
    let authority = verify_record(&publication()?.record, NOW, None, None)?;
    let branch_only = SelfSigningKey::from_vault_seed(&Zeroizing::new([3; 32]));
    assert!(branch_only.sign_home_declaration(good.body.clone(), &authority, NOW).is_err());
    for change in ["principal_id", "account_anchor", "home_node", "nonce", "domain", "signer"] {
        let mut bad = good.clone();
        match change {
            "principal_id" => bad.body.principal_id = "other.example".into(),
            "account_anchor" => bad.body.account_anchor = hash(122),
            "home_node" => bad.body.home_node = "C".into(),
            "nonce" => bad.body.nonce = hash(123),
            "domain" => bad.domain = ramflux_protocol::domain::HOME_AUTHORIZATION.into(),
            _ => {
                bad.signers[0].key = ramflux_protocol::home_migration::SignerKey::Node {
                    node_id: "A".into(),
                    public_key: public(8),
                }
            }
        }
        let request = request_with(Some(bad))?;
        assert!(
            matches!(
                a.core.attest_home_migration(
                    a.store()?,
                    &a.node,
                    AttestMigration { request: &request },
                    NOW,
                ),
                Err(NodeCoreError::HomeMigration(Refusal::HomeDeclarationRequired))
            ),
            "{change}"
        );
    }
    Ok(())
}

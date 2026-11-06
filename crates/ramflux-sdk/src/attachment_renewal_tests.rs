// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::custody::{
    memory_vault::MemoryPrimaryVault,
    tests::{Root, create},
};
use ramflux_protocol::large_attachment::{AttachmentOperation, ScopedAttachmentGrant};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn sdk_renewal_uses_current_account_branch_and_pinned_home() -> Result {
    let now = 1_700_000_001;
    let root = Root::new()?;
    let vault = MemoryPrimaryVault::default();
    let account = create(&root.0, "human", &vault, now)?;
    let (device, credentials) = account.credentials(&vault, "primary", now)?;
    let q = QualifiedOwner {
        account_anchor: device.account_anchor,
        device_id: device.device_id,
        device_epoch: device.device_epoch,
        signing_public_key: credentials.signing.signing_key.verifying_key().to_bytes(),
        home_node_id: "home".into(),
    };
    let owner = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let g = ScopedAttachmentGrant {
        grant_id: [1; 32],
        reference_id: [2; 32],
        object_id: [3; 32],
        manifest_hash: [4; 32],
        owner: QualifiedOwner { signing_public_key: owner.verifying_key().to_bytes(), ..q.clone() },
        grantee: q.clone(),
        epoch: 1,
        rights: 15,
        issued_at: now,
        expires_at: now + 600,
    };
    let grant = ScopedAttachmentGrant::decode_signed(
        &g.signed_bytes(&owner.sign(&g.signing_bytes()?).to_bytes())?,
    )?;
    let target = AttachmentOperation {
        op: 2,
        method: "HEAD".into(),
        path: format!("/attachments/{}/{}/segments/0", "03".repeat(32), "04".repeat(32)),
        audience: "relay".into(),
        object_id: g.object_id,
        manifest_hash: g.manifest_hash,
        grant_id: g.grant_id,
        grant_epoch: 1,
        authority_generation: 1,
        operation_id: [5; 32],
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        length: 0,
        body_digest: ramflux_protocol::large_attachment::body_digest(&[]),
    };
    let request = RenewalRequest::new(&target, "source", [6; 32])?;
    let home = ed25519_dalek::SigningKey::from_bytes(&[72; 32]);
    let home_key = home.verifying_key().to_bytes();
    let trust = RenewalTrust {
        home: "home",
        home_key: &home_key,
        source: "source",
        relay: "relay",
        authority_generation: 1,
    };
    let w = ForwardAttestation {
        requester: q.clone(),
        grant_hash: g.hash()?,
        grant_id: g.grant_id,
        grant_epoch: 1,
        source_issuer: "source".into(),
        home_issuer: "home".into(),
        challenge: [7; 32],
        operation_hash: request.target()?.0.hash()?,
        issued_at: now,
        expires_at: now + 30,
    };
    let sig = home.sign(&w.signing_bytes()?).to_bytes();
    let input = RenewalSigningRequest {
        request: &request,
        grant: &grant,
        trust: &trust,
        attestation: &w,
        home_signature: &sig,
        challenge: &[7; 32],
        nonce: [8; 32],
        now,
    };
    let signed = sign_home_renewal(&account, &vault, &input)?;
    signed.proof.verify(&q.signing_public_key, &signed.signature)?;
    assert_eq!(signed, sign_home_renewal(&account, &vault, &input)?);
    let bad = RenewalTrust { home: "other", ..trust };
    let changed = RenewalSigningRequest { trust: &bad, ..input };
    assert_eq!(
        sign_with_branch(&credentials.signing.signing_key, &q, &changed),
        Err(FormatError("renewal home"))
    );
    let mut changed_w = w.clone();
    changed_w.requester.device_epoch += 1;
    let changed = RenewalSigningRequest { attestation: &changed_w, ..input };
    match sign_home_renewal(&account, &vault, &changed) {
        Err(SdkError::LocalBusRefused { code, body, .. }) => {
            assert_eq!(code, "AttachmentRenewalRefused");
            assert_eq!(body["reason"], "forward request binding");
        }
        result => return Err(format!("unexpected epoch refusal: {result:?}").into()),
    }
    let mut bad_signature = sig;
    bad_signature[0] ^= 1;
    let changed = RenewalSigningRequest { home_signature: &bad_signature, ..input };
    assert_eq!(
        sign_with_branch(&credentials.signing.signing_key, &q, &changed),
        Err(FormatError("grant signature"))
    );
    assert_signing_bindings(&credentials.signing.signing_key, &q, &input)?;
    Ok(())
}

fn assert_signing_bindings(
    key: &ed25519_dalek::SigningKey,
    q: &QualifiedOwner,
    input: &RenewalSigningRequest<'_>,
) -> Result {
    let trust = RenewalTrust { authority_generation: 2, ..*input.trust };
    let changed = RenewalSigningRequest { trust: &trust, ..*input };
    assert_eq!(sign_with_branch(key, q, &changed), Err(FormatError("renewal source generation")));
    let changed = RenewalSigningRequest { challenge: &[9; 32], ..*input };
    assert_eq!(sign_with_branch(key, q, &changed), Err(FormatError("forward request binding")));
    let wrong_home_key = [42; 32];
    let trust = RenewalTrust { home_key: &wrong_home_key, ..*input.trust };
    let changed = RenewalSigningRequest { trust: &trust, ..*input };
    assert_eq!(sign_with_branch(key, q, &changed), Err(FormatError("grant signature")));
    for now in [input.grant.grant().issued_at - 1, input.grant.grant().expires_at] {
        let changed = RenewalSigningRequest { now, ..*input };
        assert_eq!(sign_with_branch(key, q, &changed), Err(FormatError("renewal grant time")));
    }
    let owner = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    for rights in [2, 8] {
        let mut grant = input.grant.grant().clone();
        grant.rights = rights;
        let grant = ScopedAttachmentGrant::decode_signed(
            &grant.signed_bytes(&owner.sign(&grant.signing_bytes()?).to_bytes())?,
        )?;
        let changed = RenewalSigningRequest { grant: &grant, ..*input };
        assert_eq!(sign_with_branch(key, q, &changed), Err(FormatError("renewal rights")));
    }
    Ok(())
}

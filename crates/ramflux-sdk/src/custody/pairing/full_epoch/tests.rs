// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK driver gates with actual confirmed bootstrap trusts; no real HTTP/Fedwire claim.
use super::*;
use ramflux_protocol::custody::pairing::full_transfer::{
    U64,
    lease::BranchKeys,
    relay::{DiscoveryKeys, ResumeTokenFull},
};
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(n: u8) -> String {
    encode_base64url([n; 32])
}
fn discovery(a: &Negotiation<'_>, destination: Option<String>) -> ResultOf<FullDiscovery> {
    let hello = a.hello.as_ref().ok_or("source hello")?;
    Ok(FullDiscovery {
        epoch: hello.epoch.clone(),
        expires_in_ms: U64(10_000),
        hpke_keys: DiscoveryKeys {
            source: hello.hpke_key.clone(),
            destination: destination.clone(),
        },
        kind: "full_discovery".into(),
        lease_id: a.lease.body.lease_id.clone(),
        profile: PROFILE.into(),
        template: destination.map(|destination| ResumeProof {
            schema: "ramflux.pairing.full_transfer.resume_proof.v1".into(),
            version: 1,
            lease_id: a.lease.body.lease_id.clone(),
            boot_id: h(31),
            nonce: h(32),
            role: "initiator".into(),
            hpke_keys: BranchKeys { source: hello.hpke_key.clone(), destination },
            epoch: hello.epoch.clone(),
        }),
    })
}
fn sign(request: &FullResumeProofSigningRequest<'_>) -> Result<String, SdkError> {
    let seed = if request.proof().role == "initiator" { 70 } else { 71 };
    assert_eq!(
        request.own_branch_key(),
        ramflux_crypto::public_key_base64url_from_seed([seed; 32])
    );
    Ok(ramflux_crypto::sign_canonical_bytes_with_seed(
        &request.proof().signing_bytes().map_err(|error| wire(&error))?,
        [seed; 32],
    ))
}
fn reply(own: &Negotiation<'_>, peer: &Negotiation<'_>) -> ResultOf<FullProofReply> {
    let proof = peer.proof.as_ref().ok_or("peer signed proof")?.proof.clone();
    Ok(FullProofReply::Ready(Box::new(ResumeTokenFull {
        epoch: own.hello.as_ref().ok_or("hello")?.epoch.clone(),
        kind: "resume_token_full".into(),
        lease_id: own.lease.body.lease_id.clone(),
        peer_proof: proof,
        profile: PROFILE.into(),
        role: own.role.as_str().into(),
        token: SecretBase64::from_bytes(&[40; 32]),
    })))
}
#[tokio::test]
async fn pairing_full_sdk_epoch_proposes_own_keys_and_checks_both_original_branch_proofs()
-> ResultOf {
    let (at, bt) = super::super::full_bootstrap::tests::epoch_trusts().await?;
    let mut a = Negotiation::new(&at, &mut at.key_owner(None)?)?;
    let mut b = Negotiation::new(&bt, &mut bt.key_owner(None)?)?;
    let deadline = b.deadline;
    assert!(b.hello.is_none());
    b.discovery(&discovery(&a, None)?, &mut sign)?;
    assert_eq!(b.deadline, deadline, "discovery extended local deadline");
    assert_eq!(b.hello.as_ref().ok_or("B hello")?.epoch, a.hello.as_ref().ok_or("A hello")?.epoch);
    let both = discovery(&a, Some(b.hello.as_ref().ok_or("B hello")?.hpke_key.clone()))?;
    a.discovery(&both, &mut sign)?;
    b.discovery(&both, &mut sign)?;
    let ar = reply(&a, &b)?;
    let br = reply(&b, &a)?;
    let ae = a.token(ar)?.ok_or("A proof verified")?;
    let be = b.token(br)?.ok_or("B proof verified")?;
    assert_eq!(ae.epoch, be.epoch);
    assert_eq!(ae.lease_id, be.lease_id);
    assert!(a.key.is_none() && b.key.is_none());
    Ok(())
}
#[tokio::test]
async fn pairing_full_sdk_epoch_node_swapped_key_asymmetric_views_both_refuse() -> ResultOf {
    swapped_key(true).await?;
    swapped_key(false).await
}
async fn swapped_key(source: bool) -> ResultOf {
    let (at, bt) = super::super::full_bootstrap::tests::epoch_trusts().await?;
    let mut a = Negotiation::new(&at, &mut at.key_owner(None)?)?;
    let mut b = Negotiation::new(&bt, &mut bt.key_owner(None)?)?;
    // Different frozen views can each carry valid original-branch signatures, but
    // neither proves the other's exact key tuple. Exercise substitution of either key.
    let mut first = discovery(&a, None)?;
    if source {
        first.hpke_keys.source = h(90);
    }
    b.discovery(&first, &mut sign)?;
    let original = discovery(&a, Some(b.hello.as_ref().ok_or("B hello")?.hpke_key.clone()))?;
    let mut aview = original.clone();
    let mut bview = original;
    if source {
        bview.hpke_keys.source = h(90);
        bview.template.as_mut().ok_or("template")?.hpke_keys.source = h(90);
    } else {
        aview.hpke_keys.destination = Some(h(90));
        aview.template.as_mut().ok_or("template")?.hpke_keys.destination = h(90);
    }
    a.discovery(&aview, &mut sign)?;
    b.discovery(&bview, &mut sign)?;
    let ar = reply(&a, &b)?;
    let br = reply(&b, &a)?;
    assert!(a.token(ar).is_err(), "A accepted node-substituted HPKE key");
    assert!(b.token(br).is_err(), "B accepted asymmetric peer proof");
    Ok(())
}
#[tokio::test]
async fn pairing_full_sdk_epoch_node_signed_peer_proofs_refused_by_both_endpoints() -> ResultOf {
    let (at, bt) = super::super::full_bootstrap::tests::epoch_trusts().await?;
    let mut a = Negotiation::new(&at, &mut at.key_owner(None)?)?;
    let mut b = Negotiation::new(&bt, &mut bt.key_owner(None)?)?;
    b.discovery(&discovery(&a, None)?, &mut sign)?;
    let both = discovery(&a, Some(b.hello.as_ref().ok_or("B hello")?.hpke_key.clone()))?;
    a.discovery(&both, &mut sign)?;
    b.discovery(&both, &mut sign)?;
    {
        let (own, peer) = (&mut a, &mut b);
        let mut ar = reply(own, peer)?;
        let mut br = reply(peer, own)?;
        for reply in [&mut ar, &mut br] {
            let FullProofReply::Ready(token) = reply else { return Err("ready".into()) };
            token.peer_proof.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
                &token.peer_proof.body.signing_bytes()?,
                [99; 32],
            );
        }
        assert!(own.token(ar).is_err(), "A accepted node-only signed peer proof");
        assert!(peer.token(br).is_err(), "B accepted node-only signed peer proof");
    }
    Ok(())
}
#[tokio::test]
async fn pairing_full_sdk_epoch_refuses_foreign_lease_before_signer_and_changed_frozen_source()
-> ResultOf {
    let (at, bt) = super::super::full_bootstrap::tests::epoch_trusts().await?;
    let a = Negotiation::new(&at, &mut at.key_owner(None)?)?;
    let mut b = Negotiation::new(&bt, &mut bt.key_owner(None)?)?;
    let mut calls = 0;
    let mut forbidden = |_: &FullResumeProofSigningRequest<'_>| {
        calls += 1;
        Err(wrong())
    };
    let mut foreign = discovery(&a, None)?;
    foreign.lease_id = h(99);
    assert!(b.discovery(&foreign, &mut forbidden).is_err());
    assert!(b.hello.is_none());
    b.discovery(&discovery(&a, None)?, &mut forbidden)?;
    let mut changed = discovery(&a, Some(b.hello.as_ref().ok_or("B hello")?.hpke_key.clone()))?;
    changed.hpke_keys.source = h(98);
    changed.template.as_mut().ok_or("template")?.hpke_keys.source = h(98);
    assert!(b.discovery(&changed, &mut forbidden).is_err());
    assert_eq!(calls, 0);
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn pairing_full_sdk_epoch_discovery_cannot_extend_original_ten_second_deadline() -> ResultOf {
    let (at, bt) = super::super::full_bootstrap::tests::epoch_trusts().await?;
    let a = Negotiation::new(&at, &mut at.key_owner(None)?)?;
    let mut b = Negotiation::new(&bt, &mut bt.key_owner(None)?)?;
    let bare = discovery(&a, None)?;
    b.discovery(&bare, &mut sign)?;
    tokio::time::advance(Duration::from_secs(9)).await;
    b.discovery(&bare, &mut sign)?;
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(b.discovery(&bare, &mut sign).is_err(), "retry extended original deadline");
    Ok(())
}

pub(super) async fn epochs() -> ResultOf<(FullEpoch, FullEpoch)> {
    let (at, bt) = super::super::full_bootstrap::tests::epoch_trusts().await?;
    let mut a = Negotiation::new(&at, &mut at.key_owner(None)?)?;
    let mut b = Negotiation::new(&bt, &mut bt.key_owner(None)?)?;
    b.discovery(&discovery(&a, None)?, &mut sign)?;
    let both = discovery(&a, Some(b.hello.as_ref().ok_or("B hello")?.hpke_key.clone()))?;
    a.discovery(&both, &mut sign)?;
    b.discovery(&both, &mut sign)?;
    let ar = reply(&a, &b)?;
    let br = reply(&b, &a)?;
    Ok((a.token(ar)?.ok_or("A token")?, b.token(br)?.ok_or("B token")?))
}

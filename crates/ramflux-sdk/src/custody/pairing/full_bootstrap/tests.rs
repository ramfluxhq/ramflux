// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use ed25519_dalek::Signer;
use ramflux_crypto::{X25519KeyPair, custody::pairing::commit};
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::{canonical_json_bytes, custody::pairing::full_transfer::SecretBase64};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
type Fut<T> = Pin<Box<dyn Future<Output = std::result::Result<T, SdkError>> + Send>>;
struct Fixture {
    a: EstablishedSas,
    b: EstablishedSas,
    context: TranscriptV3,
    node: VerifiedNodeRecord,
    start: StartFull,
    grant: DataGrant,
    now: u64,
}
fn fixture() -> Result<Fixture> {
    let now = crate::custody::network_now()?;
    let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ramflux-protocol/fixtures/pairing_v3/vectors.json"
    )))?;
    let mut context =
        TranscriptV3::from_wire_bytes(&canonical_json_bytes(&vectors["transcript"])?)?;
    let invitation = encode_base64url(ramflux_crypto::random_32()?);
    let transfer = encode_base64url(ramflux_crypto::random_32()?);
    for (role, secret, branch) in [(&mut context.initiator, 7, 70), (&mut context.responder, 8, 71)]
    {
        role.sas_key = encode_base64url(X25519KeyPair::from_seed([secret; 32]).public);
        role.branch_key = ramflux_crypto::public_key_base64url_from_seed([branch; 32]);
        role.common.invitation_id = invitation.clone();
        role.common.transfer_id = Some(transfer.clone());
        role.common.expires_at = now + 300;
        role.common.lease_not_before = now;
        role.common.lease_expires_at = now + 604_800;
    }
    let mut a = commit(PairingRole::Initiator, &context.initiator, &[7; 32], &[11; 32])?;
    let mut b = commit(PairingRole::Responder, &context.responder, &[8; 32], &[12; 32])?;
    a.store_peer_commitment(PairingRole::Responder, b.commitment())?;
    b.store_peer_commitment(PairingRole::Initiator, a.commitment())?;
    let mut a = a.establish(&context.responder, &[12; 32])?;
    let mut b = b.establish(&context.initiator, &[11; 32])?;
    let am = a.confirm_local(&a.transcript_hash(), true)?;
    let bm = b.confirm_local(&b.transcript_hash(), true)?;
    a.accept_peer_mac(&bm)?;
    b.accept_peer_mac(&am)?;
    let start = StartFull {
        commitment_opening: SecretBase64::from_bytes(&[22; 32]),
        kind: "start_full".into(),
        manifest_hash: encode_base64url([23; 32]),
        opaque_commitment: encode_base64url(
            ramflux_protocol::custody::pairing::full_transfer::lease::opaque_commitment(
                &[23; 32], &[22; 32],
            ),
        ),
        profile: PROFILE.into(),
        snapshot_id: encode_base64url([24; 32]),
        transfer_id: context.initiator.common.transfer_id.clone().ok_or("transfer_id")?,
    };
    let grant = DataGrant {
        schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
        version: 1,
        transfer_id: start.transfer_id.clone(),
        node_id: "node".into(),
        source_ref: context.initiator.device_ref.clone(),
        destination_ref: context.responder.device_ref.clone(),
        branch_keys: ramflux_protocol::custody::pairing::full_transfer::lease::BranchKeys {
            source: context.initiator.branch_key.clone(),
            destination: context.responder.branch_key.clone(),
        },
        opaque_commitment: start.opaque_commitment.clone(),
        expires_at: now + 604_800,
    };
    let node = crate::custody::network_tests::node(now, encode_base64url([29; 32]))
        .map_err(|error| error.to_string())?;
    Ok(Fixture { a, b, context, node, start, grant, now })
}
fn sign(authorization: &FullGrantSigningRequest<'_>) -> std::result::Result<String, SdkError> {
    let seed = if authorization.role() == "initiator" { 70 } else { 71 };
    Ok(ramflux_crypto::sign_canonical_bytes_with_seed(
        &authorization
            .request()
            .signing_bytes(authorization.role())
            .map_err(|error| wire(&error))?,
        [seed; 32],
    ))
}
struct Native {
    calls: Arc<AtomicUsize>,
    now: u64,
}
impl PairingNative for Native {
    fn issue(
        &self,
        _: ramflux_protocol::custody::pairing::native::CreateSpec,
    ) -> Fut<ramflux_protocol::custody::pairing::native::Issued> {
        Box::pin(async { Err(SdkError::PairingCode("WrongContext")) })
    }
    fn create(
        &self,
        _: ramflux_protocol::custody::pairing::native::Create,
    ) -> Fut<ramflux_protocol::custody::pairing::native::Created> {
        Box::pin(async { Err(SdkError::PairingCode("WrongContext")) })
    }
    fn data_lease(&self, request: LeaseRequest) -> Fut<Envelope<DataLease>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let now = self.now;
        Box::pin(async move {
            for (role, signature, key) in [
                ("initiator", &request.source_signature, &request.grant.branch_keys.source),
                (
                    "responder",
                    &request.destination_signature,
                    &request.grant.branch_keys.destination,
                ),
            ] {
                verify_canonical_signature(
                    &request.signing_bytes(role).map_err(|error| wire(&error))?,
                    signature,
                    key,
                )?;
            }
            let body = DataLease {
                schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
                version: 1,
                lease_id: encode_base64url([30; 32]),
                issued_at: now,
                expires_at: request.grant.expires_at,
                grant: request.grant,
            };
            let signature = encode_base64url(
                ramflux_crypto::fixture_signing_key()
                    .sign(&body.signing_bytes().map_err(|error| wire(&error))?)
                    .to_bytes(),
            );
            Ok(Envelope { body, signature })
        })
    }
}
#[tokio::test]
async fn pairing_full_lease_bootstrap_carriers_are_closed_and_ordered() -> Result {
    let f = fixture()?;
    let mut a =
        FullBootstrap::new(PairingRole::Initiator, f.a, f.context.clone(), f.node.clone(), f.now)?;
    let mut b = FullBootstrap::new(PairingRole::Responder, f.b, f.context, f.node, f.now)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let native = Native { calls: calls.clone(), now: f.now };
    assert!(a.issue_source_lease(&native, f.now).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // Wrong phase is terminal: use a fresh confirmed ceremony for the positive exchange.
    let f = fixture()?;
    let mut a =
        FullBootstrap::new(PairingRole::Initiator, f.a, f.context.clone(), f.node.clone(), f.now)?;
    let mut b2 = FullBootstrap::new(PairingRole::Responder, f.b, f.context, f.node, f.now)?;
    let unexpected = AtomicUsize::new(0);
    let refused = |_: &FullGrantSigningRequest<'_>| {
        unexpected.fetch_add(1, Ordering::SeqCst);
        Err(SdkError::PairingCode("WrongContext"))
    };
    let [start, offer] = a.begin_source(f.start, &f.grant, f.now, sign)?;
    assert_eq!((start.counter, offer.counter), (0, 1));
    assert!(b2.receive(&start, f.now, refused)?.is_none());
    let signed = b2.receive(&offer, f.now, sign)?.ok_or("signed grant")?;
    assert_eq!(signed.counter, 0);
    assert!(a.receive(&signed, f.now, refused)?.is_none());
    closed::carrier(&FullSasControl::GrantOffer(GrantOfferFull {
        grant: f.grant.clone(),
        kind: "grant_offer_full".into(),
        profile: PROFILE.into(),
    }))?;
    closed::carrier(&FullSasControl::GrantSigned(GrantSignedFull {
        destination_signature: a
            .request
            .as_ref()
            .ok_or("test: exact signed grant")?
            .destination_signature
            .clone(),
        kind: "grant_signed_full".into(),
        profile: PROFILE.into(),
    }))?;
    let (lease, local, _a_trust) = a.issue_source_lease(&native, f.now).await?;
    closed::carrier(&FullSasControl::Lease(LeaseFull {
        lease: local.clone(),
        kind: "lease_full".into(),
        profile: PROFILE.into(),
    }))?;
    assert_eq!(lease.counter, 2);
    assert!(
        a.start.is_none() && a.prepared_source.is_none() && a.request.is_none(),
        "issued lease retained private commitment opening"
    );
    let (remote, _b_trust) = b2.accept_destination_lease(&lease, f.now)?;
    assert!(
        b2.start.is_none() && b2.prepared_source.is_none() && b2.request.is_none(),
        "accepted lease retained private commitment opening"
    );
    assert_eq!(canonical_json_bytes(&local)?, canonical_json_bytes(&remote)?);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(unexpected.load(Ordering::SeqCst), 0);
    assert!(b2.accept_destination_lease(&lease, f.now).is_err());
    // A foreign ceremony cannot decrypt/adopt the lease.
    assert!(b.accept_destination_lease(&lease, f.now).is_err());
    reject_unfrozen_grants()?;
    closed::reject_changed_lease().await?;
    Ok(())
}
#[test]
fn pairing_full_bootstrap_rebuilds_grant_before_signer_and_enforces_original_expiry() -> Result {
    reject_unfrozen_grants()
}
fn reject_unfrozen_grants() -> Result {
    for change in 0..6 {
        let f = fixture()?;
        let mut b = FullBootstrap::new(PairingRole::Responder, f.b, f.context, f.node, f.now)?;
        let mut source = f.a;
        let unexpected = AtomicUsize::new(0);
        let refused = |_: &FullGrantSigningRequest<'_>| {
            unexpected.fetch_add(1, Ordering::SeqCst);
            Err(SdkError::PairingCode("WrongContext"))
        };
        let (counter, ciphertext) =
            source.seal(&FullSasControl::Start(f.start).encode_secret()?)?;
        b.receive(&FullBootstrapFrame { counter, ciphertext }, f.now, refused)?;
        let mut grant = f.grant;
        match change {
            0 => grant.branch_keys.source = encode_base64url([90; 32]),
            1 => grant.branch_keys.destination = encode_base64url([91; 32]),
            2 => grant.node_id = "hostile-node".into(),
            3 => grant.opaque_commitment = encode_base64url([92; 32]),
            4 => grant.destination_ref.device_id = "other-peer".into(),
            _ => grant.expires_at = f.now + 604_800 + 301,
        }
        let control = FullSasControl::GrantOffer(GrantOfferFull {
            grant,
            kind: "grant_offer_full".into(),
            profile: PROFILE.into(),
        });
        let (counter, ciphertext) = source.seal(&control.encode_secret()?)?;
        assert!(b.receive(&FullBootstrapFrame { counter, ciphertext }, f.now, refused).is_err());
        assert_eq!(unexpected.load(Ordering::SeqCst), 0);
    }
    let f = fixture()?;
    let unexpected = AtomicUsize::new(0);
    let refused = |_: &FullGrantSigningRequest<'_>| {
        unexpected.fetch_add(1, Ordering::SeqCst);
        Err(SdkError::PairingCode("WrongContext"))
    };
    let mut a = FullBootstrap::new(PairingRole::Initiator, f.a, f.context, f.node, f.now)?;
    assert!(a.begin_source(f.start, &f.grant, f.now + 300, refused).is_err());
    assert_eq!(unexpected.load(Ordering::SeqCst), 0);
    Ok(())
}

mod source;

/// Locally confirmed, bootstrap-verified data trusts for sibling SDK epoch-driver tests.
pub(in crate::custody::pairing) async fn epoch_trusts() -> Result<(FullResumeTrust, FullResumeTrust)>
{
    let f = fixture()?;
    let mut a =
        FullBootstrap::new(PairingRole::Initiator, f.a, f.context.clone(), f.node.clone(), f.now)?;
    let mut b = FullBootstrap::new(PairingRole::Responder, f.b, f.context, f.node, f.now)?;
    let native = Native { calls: Arc::new(AtomicUsize::new(0)), now: f.now };
    let [start, offer] = a.begin_source(f.start, &f.grant, f.now, sign)?;
    b.receive(&start, f.now, sign)?;
    let signed = b.receive(&offer, f.now, sign)?.ok_or("grant signature")?;
    a.receive(&signed, f.now, sign)?;
    let (frame, _, at) = a.issue_source_lease(&native, f.now).await?;
    let (_, bt) = b.accept_destination_lease(&frame, f.now)?;
    Ok((at, bt))
}

mod closed;

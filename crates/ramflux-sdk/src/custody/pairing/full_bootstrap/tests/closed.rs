// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact generated bootstrap carriers stay canonical, bounded and closed.
use super::*;

pub(super) fn carrier(control: &FullSasControl) -> Result {
    let bytes = control.encode_secret()?;
    let round_trip = FullSasControl::from_wire_bytes(&bytes)?.encode_secret()?;
    assert!(bytes == round_trip, "test: closed bootstrap carrier changed canonical bytes");
    let body = bytes.strip_suffix(b"}").ok_or("test: bootstrap carrier is not an object")?;
    let mut extended = zeroize::Zeroizing::new(body.to_vec());
    extended.extend_from_slice(b",\"zz_extra\":null}");
    assert!(extended.len() <= 8192, "test: unknown-field case exceeded the carrier byte cap");
    assert!(
        FullSasControl::from_wire_bytes(&extended).is_err(),
        "test: bootstrap carrier accepted an undeclared field"
    );
    Ok(())
}

pub(super) async fn reject_changed_lease() -> Result {
    let f = fixture()?;
    let mut a =
        FullBootstrap::new(PairingRole::Initiator, f.a, f.context.clone(), f.node.clone(), f.now)?;
    let mut b = FullBootstrap::new(PairingRole::Responder, f.b, f.context, f.node, f.now)?;
    let [start, offer] = a.begin_source(f.start, &f.grant, f.now, sign)?;
    b.receive(&start, f.now, sign)?;
    let signed = b.receive(&offer, f.now, sign)?.ok_or("test: original B grant signature")?;
    a.receive(&signed, f.now, sign)?;
    let native = Native { calls: Arc::new(AtomicUsize::new(0)), now: f.now };
    let mut lease = native.data_lease(a.request.clone().ok_or("test: dual signed grant")?).await?;
    lease.body.grant.opaque_commitment = encode_base64url([93; 32]);
    lease.signature = encode_base64url(
        ramflux_crypto::fixture_signing_key().sign(&lease.body.signing_bytes()?).to_bytes(),
    );
    let bytes = FullSasControl::Lease(LeaseFull {
        kind: "lease_full".into(),
        profile: PROFILE.into(),
        lease,
    })
    .encode_secret()?;
    let (counter, ciphertext) = a.channel.seal(&bytes)?;
    assert!(
        b.accept_destination_lease(&FullBootstrapFrame { counter, ciphertext }, f.now).is_err(),
        "test: a valid node signature replaced B's exact locally signed grant"
    );
    assert!(matches!(b.phase, Phase::Dead), "test: foreign grant retained usable bootstrap state");
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::custody::pairing::{FullResumeTrust, HpkeSecrets};
use ramflux_protocol::custody::{
    Envelope,
    pairing::full_transfer::{
        DataBinding, DataPacket, SecretBase64, U64,
        lease::{BranchKeys, DataGrant, DataLease, ResumeProof},
        relay::ResumeTokenFull,
    },
};
use ramflux_protocol::decode_base64url;
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn b(value: u8) -> String {
    encode_base64url([value; 32])
}
fn secret(value: u8) -> HpkeSecrets {
    HpkeSecrets::from_seed(&mut [value; 32])
}
fn public(value: u8) -> [u8; 32] {
    X25519KeyPair::from_seed([value; 32]).public
}
struct Fixture {
    a: FullResumeTrust,
    b: FullResumeTrust,
    lease: Envelope<DataLease>,
    context: TranscriptV3,
}
fn fixture() -> TestResult<Fixture> {
    let mut context = full_transcript()?;
    context.initiator.branch_key = crate::public_key_base64url_from_seed([70; 32]);
    context.responder.branch_key = crate::public_key_base64url_from_seed([71; 32]);
    context.initiator.hpke_key = Some(encode_base64url(public(21)));
    context.responder.hpke_key = Some(encode_base64url(public(22)));
    let start = context.initiator.common.lease_not_before;
    let grant = DataGrant {
        schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
        version: 1,
        transfer_id: context.initiator.common.transfer_id.clone().ok_or("transfer id")?,
        node_id: "node.example".into(),
        source_ref: context.initiator.device_ref.clone(),
        destination_ref: context.responder.device_ref.clone(),
        branch_keys: BranchKeys {
            source: context.initiator.branch_key.clone(),
            destination: context.responder.branch_key.clone(),
        },
        opaque_commitment: b(9),
        expires_at: start + 604_800,
    };
    let body = DataLease {
        schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
        version: 1,
        lease_id: b(10),
        grant: grant.clone(),
        issued_at: start,
        expires_at: start + 604_800,
    };
    let lease = Envelope {
        signature: crate::sign_canonical_bytes_with_seed(&body.signing_bytes()?, [80; 32]),
        body,
    };
    let mut a = commit(PairingRole::Initiator, &context.initiator, &INIT_SECRET, &INIT_SALT)?;
    let mut bb = commit(PairingRole::Responder, &context.responder, &RESP_SECRET, &RESP_SALT)?;
    a.store_peer_commitment(PairingRole::Responder, bb.commitment())?;
    bb.store_peer_commitment(PairingRole::Initiator, a.commitment())?;
    let mut a = a.establish(&context.responder, &RESP_SALT)?;
    let mut bb = bb.establish(&context.initiator, &INIT_SALT)?;
    let am = a.confirm_local(&a.transcript_hash(), true)?;
    let bm = bb.confirm_local(&bb.transcript_hash(), true)?;
    a.accept_peer_mac(&bm)?;
    bb.accept_peer_mac(&am)?;
    Ok(Fixture {
        a: a.full_resume_trust(context.clone(), grant.clone(), &lease)?,
        b: bb.full_resume_trust(context.clone(), grant, &lease)?,
        lease,
        context,
    })
}
fn template(lease: &Envelope<DataLease>, source: u8, destination: u8) -> ResumeProof {
    ResumeProof {
        schema: "ramflux.pairing.full_transfer.resume_proof.v1".into(),
        version: 1,
        lease_id: lease.body.lease_id.clone(),
        boot_id: b(11),
        nonce: b(12),
        role: "initiator".into(),
        hpke_keys: BranchKeys {
            source: encode_base64url(public(source)),
            destination: encode_base64url(public(destination)),
        },
        epoch: b(13),
    }
}
fn token(own: &ResumeProof, peer: &ResumeProof, signer: u8) -> TestResult<ResumeTokenFull> {
    Ok(ResumeTokenFull {
        epoch: own.epoch.clone(),
        kind: "resume_token_full".into(),
        profile: "primary_transfer_full_v1".into(),
        lease_id: own.lease_id.clone(),
        role: own.role.clone(),
        token: SecretBase64::from_bytes(&[14; 32]),
        peer_proof: Envelope {
            body: peer.clone(),
            signature: crate::sign_canonical_bytes_with_seed(&peer.signing_bytes()?, [signer; 32]),
        },
    })
}
fn binding(f: &Fixture) -> DataBinding {
    DataBinding {
        profile: "primary_transfer_full_v1".into(),
        transfer_id: f.lease.body.grant.transfer_id.clone(),
        manifest_hash: b(15),
        epoch: b(13),
        source_ref: f.context.initiator.device_ref.clone(),
        destination_ref: f.context.responder.device_ref.clone(),
        base_record_hash: f.context.initiator.common.record_hash.clone(),
    }
}
#[test]
fn pairing_full_resume_node_forged_lease_branch_keys_refused() -> TestResult {
    for (as_key, bs_key) in [(true, false), (false, true), (true, true)] {
        let f = fixture()?;
        let mut forged = f.lease.clone();
        if as_key {
            forged.body.grant.branch_keys.source = crate::public_key_base64url_from_seed([81; 32]);
        }
        if bs_key {
            forged.body.grant.branch_keys.destination =
                crate::public_key_base64url_from_seed([82; 32]);
        }
        forged.signature =
            crate::sign_canonical_bytes_with_seed(&forged.body.signing_bytes()?, [80; 32]);
        // The same legitimate node signed both leases. Neither endpoint signs the replacement.
        assert!(matches!(
            f.a.begin(&forged, secret(31), public(32), b(13)),
            Err(CryptoError::Pairing("WrongContext"))
        ));
        assert!(matches!(
            f.b.begin(&forged, secret(32), public(31), b(13)),
            Err(CryptoError::Pairing("WrongContext"))
        ));
    }
    // Asymmetric node views: each endpoint's own key is correct, but its peer slot is swapped.
    // Proofs forged under the node-held keys cannot pass either locally SAS-pinned verifier.
    for role in [PairingRole::Initiator, PairingRole::Responder] {
        let f = fixture()?;
        let (trust, own, peer, node_signer) = match role {
            PairingRole::Initiator => (&f.a, 31, 92, 82),
            PairingRole::Responder => (&f.b, 32, 91, 81),
        };
        let mut attempt = trust.begin(&f.lease, secret(own), public(peer), b(13))?;
        let mut node_template = match role {
            PairingRole::Initiator => template(&f.lease, 31, 92),
            PairingRole::Responder => template(&f.lease, 91, 32),
        };
        let own_body = attempt.proof_to_sign(&node_template)?;
        node_template.role = match role {
            PairingRole::Initiator => "responder",
            PairingRole::Responder => "initiator",
        }
        .into();
        let forged_token = token(&own_body, &node_template, node_signer)?;
        assert!(matches!(
            attempt.verify_token(&forged_token),
            Err(CryptoError::Pairing("WrongContext"))
        ));
    }
    for alter_lease in [false, true] {
        let f = fixture()?;
        let mut a = f.a.begin(&f.lease, secret(31), public(32), b(13))?;
        let own = a.proof_to_sign(&template(&f.lease, 31, 32))?;
        let mut peer = own.clone();
        peer.role = "responder".into();
        if alter_lease {
            peer.lease_id = b(99);
        } else {
            peer.epoch = b(99);
        }
        let reply = token(&own, &peer, 71)?;
        assert!(matches!(a.verify_token(&reply), Err(CryptoError::Pairing("WrongContext"))));
    }
    Ok(())
}
#[test]
fn pairing_full_initial_epoch_uses_a3_with_sas_keys() -> TestResult {
    let f = fixture()?;
    // Fresh peer keys are authenticated by branch proofs, not equality with the SAS HPKE key.
    let mut fresh_a = f.a.begin(&f.lease, secret(31), public(32), b(13))?;
    let mut fresh_b = f.b.begin(&f.lease, secret(32), public(31), b(13))?;
    let t = template(&f.lease, 31, 32);
    let pa = fresh_a.proof_to_sign(&t)?;
    let pb = fresh_b.proof_to_sign(&t)?;
    fresh_a.verify_token(&token(&pa, &pb, 71)?)?;
    fresh_b.verify_token(&token(&pb, &pa, 70)?)?;
    let mut a = f.a.begin(&f.lease, secret(21), public(22), b(13))?;
    let mut bb = f.b.begin(&f.lease, secret(22), public(21), b(13))?;
    let t = template(&f.lease, 21, 22);
    let own_a = a.proof_to_sign(&t)?;
    let own_b = bb.proof_to_sign(&t)?;
    let setup = a.verify_token(&token(&own_a, &own_b, 71)?)?.setup_sender(&binding(&f))?;
    let receiver = bb.verify_token(&token(&own_b, &own_a, 70)?)?.open_receiver(
        &setup.enc,
        &setup.confirmation,
        &binding(&f),
    )?;
    let mut sender = super::super::super::FullDataCipher::new(PairingRole::Initiator, setup.keys);
    let mut receiver = super::super::super::FullDataCipher::new(PairingRole::Responder, receiver);
    let packet = DataPacket::Manifest {
        manifest_hash: b(15),
        offset: U64(0),
        total: U64(1),
        bytes: SecretBase64::from_bytes(b"m"),
    };
    let (counter, ciphertext) = sender.seal(&packet.encode_secret()?)?;
    assert!(matches!(
        receiver.open(counter, &ciphertext)?,
        super::super::super::FullOpened::New(_)
    ));
    Ok(())
}
#[test]
fn pairing_full_resume_node_swapped_template_key_both_endpoints_refuse() -> TestResult {
    for swap_source in [false, true] {
        let f = fixture()?;
        let mut a = f.a.begin(&f.lease, secret(31), public(32), b(13))?;
        let mut bb = f.b.begin(&f.lease, secret(32), public(31), b(13))?;
        let mut t = template(&f.lease, 31, 32);
        if swap_source {
            t.hpke_keys.source = encode_base64url(public(91));
        } else {
            t.hpke_keys.destination = encode_base64url(public(92));
        }
        assert!(matches!(a.proof_to_sign(&t), Err(CryptoError::Pairing("WrongContext"))));
        assert!(matches!(bb.proof_to_sign(&t), Err(CryptoError::Pairing("WrongContext"))));
    }
    Ok(())
}

#[test]
fn pairing_full_control_foreign_scope_preserves_receiver_key() -> TestResult {
    use ramflux_protocol::custody::pairing::full_transfer::relay::HpkeConfirmFull;
    let f = fixture()?;
    let mut a = f.a.begin(&f.lease, secret(31), public(32), b(13))?;
    let mut bb = f.b.begin(&f.lease, secret(32), public(31), b(13))?;
    let t = template(&f.lease, 31, 32);
    let pa = a.proof_to_sign(&t)?;
    let pb = bb.proof_to_sign(&t)?;
    let local = binding(&f);
    let setup = a.verify_token(&token(&pa, &pb, 71)?)?.setup_sender(&local)?;
    let mut receiver = bb.verify_token(&token(&pb, &pa, 70)?)?;
    let control = HpkeConfirmFull {
        confirmation: encode_base64url(&setup.confirmation),
        enc: encode_base64url(setup.enc),
        epoch: t.epoch,
        kind: "hpke_confirm".into(),
        lease_id: t.lease_id,
        role: "initiator".into(),
    };
    for field in 0..3 {
        let mut foreign = control.clone();
        match field {
            0 => foreign.epoch = b(90),
            1 => foreign.lease_id = b(91),
            _ => foreign.role = "responder".into(),
        }
        assert!(matches!(
            receiver.open_control(&foreign, &local),
            Err(CryptoError::Pairing("WrongContext"))
        ));
    }
    let keys = receiver.open_control(&control, &local)?;
    assert!(receiver.open_control(&control, &local).is_err(), "HPKE key must be single-use");
    let mut sender = crate::custody::pairing::FullConfirmedChannel::new(
        PairingRole::Initiator,
        setup.keys,
        local.manifest_hash.clone(),
    )?;
    let mut recipient = crate::custody::pairing::FullConfirmedChannel::new(
        PairingRole::Responder,
        keys,
        local.manifest_hash,
    )?;
    let (counter, ready) = recipient.seal_ready()?;
    sender.open_ready(counter, &ready)?;
    Ok(())
}

#[test]
fn pairing_full_first_attempt_loss_recovers_without_new_sas() -> TestResult {
    use ramflux_protocol::custody::pairing::full_transfer::relay::HpkeConfirmFull;
    // A missed window keeps B's unused SAS half; a lost token after A sealed and a
    // failed HPKE open both force fresh own halves. No new SAS/approval is created.
    for failure in 0..3 {
        let f = fixture()?;
        let mut ak = f.a.key_owner(Some(secret(21)))?;
        let mut bk = f.b.key_owner(Some(secret(22)))?;
        let a_first = ak.next_key()?;
        if failure == 0 {
            drop(a_first);
        } else {
            let b_first = bk.next_key()?;
            let mut a = f.a.begin(&f.lease, a_first, b_first.public_key(), b(13))?;
            let mut bb = f.b.begin(&f.lease, b_first, public(21), b(13))?;
            let t = template(&f.lease, 21, 22);
            let pa = a.proof_to_sign(&t)?;
            let pb = bb.proof_to_sign(&t)?;
            let setup = a.verify_token(&token(&pa, &pb, 71)?)?.setup_sender(&binding(&f))?;
            if failure == 1 {
                drop(bb); // B's token reply was lost; its abandoned proposal is retired.
            } else {
                let mut receiver = bb.verify_token(&token(&pb, &pa, 70)?)?;
                let control = HpkeConfirmFull {
                    confirmation: encode_base64url([0; 32]),
                    enc: encode_base64url(setup.enc),
                    epoch: b(13),
                    kind: "hpke_confirm".into(),
                    lease_id: f.lease.body.lease_id.clone(),
                    role: "initiator".into(),
                };
                assert!(receiver.open_control(&control, &binding(&f)).is_err());
                // A failed authenticated-scope open destroys the private half too.
                assert!(
                    receiver.open_receiver(&setup.enc, &setup.confirmation, &binding(&f)).is_err()
                );
            }
        }
        let own_a = ak.next_key()?;
        let own_b = bk.next_key()?;
        assert_ne!(own_a.public_key(), public(21));
        let mut t = template(&f.lease, 21, 22);
        t.epoch = b(40 + failure);
        t.hpke_keys.source = encode_base64url(own_a.public_key());
        t.hpke_keys.destination = encode_base64url(own_b.public_key());
        let mut a = f.a.begin(&f.lease, own_a, own_b.public_key(), t.epoch.clone())?;
        let mut bb = f.b.begin(
            &f.lease,
            own_b,
            decode_base64url(&t.hpke_keys.source)?.as_slice().try_into()?,
            t.epoch.clone(),
        )?;
        let pa = a.proof_to_sign(&t)?;
        let pb = bb.proof_to_sign(&t)?;
        let mut local = binding(&f);
        local.epoch = t.epoch;
        let setup = a.verify_token(&token(&pa, &pb, 71)?)?.setup_sender(&local)?;
        let keys = bb.verify_token(&token(&pb, &pa, 70)?)?.open_receiver(
            &setup.enc,
            &setup.confirmation,
            &local,
        )?;
        let mut a = crate::custody::pairing::FullConfirmedChannel::resume(
            PairingRole::Initiator,
            setup.keys,
            local.manifest_hash.clone(),
        )?;
        let mut bb = crate::custody::pairing::FullConfirmedChannel::resume(
            PairingRole::Responder,
            keys,
            local.manifest_hash,
        )?;
        let (counter, ready) = bb.seal_ready()?;
        a.open_ready(counter, &ready)?;
    }
    Ok(())
}

#[test]
fn pairing_full_discovery_foreign_lease_refused_before_signer() -> TestResult {
    use ramflux_protocol::custody::pairing::full_transfer::relay::{DiscoveryKeys, FullDiscovery};
    let f = fixture()?;
    let t = template(&f.lease, 31, 32);
    let discovery = FullDiscovery {
        epoch: t.epoch.clone(),
        expires_in_ms: U64(9000),
        hpke_keys: DiscoveryKeys {
            source: t.hpke_keys.source.clone(),
            destination: Some(t.hpke_keys.destination.clone()),
        },
        kind: "full_discovery".into(),
        lease_id: f.lease.body.lease_id.clone(),
        profile: "primary_transfer_full_v1".into(),
        template: Some(t.clone()),
    };
    let mut a = f.a.begin(&f.lease, secret(31), public(32), t.epoch.clone())?;
    assert_eq!(a.discovery_proof_to_sign(&discovery)?, t);
    let mut wrong = discovery;
    wrong.lease_id = b(90);
    wrong.template.as_mut().ok_or("template")?.lease_id = wrong.lease_id.clone();
    wrong.validate()?;
    let mut a = f.a.begin(&f.lease, secret(31), public(32), t.epoch.clone())?;
    let mut signer_calls = 0;
    if a.discovery_proof_to_sign(&wrong).is_ok() {
        signer_calls += 1;
    }
    assert_eq!(signer_calls, 0, "foreign discovery reached branch signer");
    Ok(())
}

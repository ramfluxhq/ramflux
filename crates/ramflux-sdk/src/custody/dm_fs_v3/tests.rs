// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use ramflux_crypto::dm_fs_v3 as c;
use ramflux_protocol::{
    custody::{CustodyRefusal, RetryHint, RetryScope},
    dm_fs_v3 as p,
};
use serde_json::Value;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn decode(hex: &str) -> Result<Vec<u8>> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
fn raw(name: &str) -> Result<Vec<u8>> {
    let w: Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/fixtures/dm_fs_v3/wire_vectors.json"
    ))?;
    let v = w["positive"]
        .as_array()
        .ok_or("positive")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or("vector")?;
    decode(v["bytes"].as_str().ok_or("hex")?)
}
fn crypto() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/fixtures/dm_fs_v3/crypto_vectors.json"
    ))?)
}
fn fixed(v: &Value) -> Result<[u8; 32]> {
    decode(v.as_str().ok_or("hex")?)?.try_into().map_err(|_| "width".into())
}
// Existing trait, a fixture-only capability. Production DeviceBranch remains crypto-owned.
struct FixtureSigner(SigningKey);
impl c::NativePrekeySigner for FixtureSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, role: c::NativeSignatureDomain, body: &[u8]) -> [u8; 64] {
        let mut data = role.as_str().as_bytes().to_vec();
        data.push(0);
        data.extend_from_slice(body);
        self.0.sign(&data).to_bytes()
    }
}
fn signer(name: &str) -> Result<FixtureSigner> {
    let v = crypto()?;
    let v = v["signatures"]
        .as_array()
        .ok_or("signatures")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or("signer")?;
    Ok(FixtureSigner(SigningKey::from_bytes(&fixed(&v["seed"])?)))
}
#[test]
fn dm_fs_v3_sdk_builders_match_vectors() -> Result {
    let base = p::SignedNativePrekeyBase::from_bytes(&raw("SignedNativePrekeyBase")?)?;
    let owner = signer("SignedNativePrekeyBase")?;
    let mut unsigned = base.clone();
    unsigned.signature = [0; 64];
    assert_eq!(build_base(unsigned, &owner)?.to_bytes()?, raw("SignedNativePrekeyBase")?);
    let mut opk = p::SignedNativeOpk::from_bytes(&raw("SignedNativeOpk")?)?;
    opk.signature = [0; 64];
    assert_eq!(build_opk(opk, &base.branch, &owner)?.to_bytes()?, raw("SignedNativeOpk")?);
    let mut update = p::OwnerPrekeyUpdate::from_bytes(&raw("OwnerPrekeyUpdate")?)?;
    update.signature = [0; 64];
    assert_eq!(build_owner_update(update, &owner)?.to_bytes()?, raw("OwnerPrekeyUpdate")?);
    let mut request = p::NativePrekeyRequest::from_bytes(&raw("NativePrekeyRequest")?)?;
    request.signature = [0; 64];
    assert_eq!(
        build_request(request, &signer("NativePrekeyRequest")?)?.to_bytes()?,
        raw("NativePrekeyRequest")?
    );
    let snapshot = p::PrekeyPublicationSnapshot::from_bytes(&raw("PrekeyPublicationSnapshot")?)?;
    assert_eq!(build_publication_snapshot(&snapshot)?, raw("PrekeyPublicationSnapshot")?);
    let intent = p::PrekeyLeaseIntent::from_bytes(&raw("PrekeyLeaseIntent")?)?;
    let (bytes, id) = build_lease_intent(&intent)?;
    assert_eq!(bytes, raw("PrekeyLeaseIntent")?);
    let cv = crypto()?;
    let hash = cv["hashes"]
        .as_array()
        .ok_or("hashes")?
        .iter()
        .find(|v| v["name"] == "lease_operation_id")
        .ok_or("id")?;
    assert_eq!(id, fixed(&hash["digest"])?);
    verifier_contract()?;
    builder_bounds()?;
    request_status_bounds()?;
    Ok(())
}
#[test]
fn dm_fs_v3_sdk_adapter_maps_every_refusal() -> Result {
    use p::DmFsV3Refusal as P;
    let all = [
        P::NativePublicationRequiresCustody,
        P::NativeAccountRequired,
        P::PrekeyProfileInactive,
        P::PrekeyCrossHomeUnavailable,
        P::PrekeyClockUntrusted,
        P::PrekeyCapacity,
        P::PrekeyRepairRequired,
        P::PrekeyRefreshRequired,
        P::PrekeyLeaseUnavailable,
        P::BootstrapKeyUnavailable,
        P::UpdateRequired,
        P::Replay,
        P::Busy,
        P::PersistenceUnavailable,
        P::Capacity,
    ];
    for native in all {
        let sdk = DmFsV3Refusal::from(native);
        assert_eq!(sdk.as_str(), native.as_str());
        assert_eq!(P::from(sdk), native);
    }
    for (custody, native) in [
        (CustodyRefusal::UpdateRequired, P::UpdateRequired),
        (CustodyRefusal::Replay, P::Replay),
        (CustodyRefusal::Busy, P::Busy),
        (CustodyRefusal::PersistenceUnavailable, P::PersistenceUnavailable),
        (CustodyRefusal::Capacity, P::Capacity),
    ] {
        assert_eq!(DmFsV3Refusal::try_from(&custody), Ok(native.into()));
    }
    for refusal in [
        CustodyRefusal::Unsupported,
        CustodyRefusal::InvalidInput,
        CustodyRefusal::AuthorityUnavailable,
        CustodyRefusal::PrincipalIdTaken,
        CustodyRefusal::ChallengeUnknown,
        CustodyRefusal::ChallengeExpired,
        CustodyRefusal::BindingRefused,
        CustodyRefusal::SessionRequired,
        CustodyRefusal::SessionExpired,
        CustodyRefusal::AbortedRetrySafe,
        CustodyRefusal::CapacityRetryAfter { retry_after_ms: 1 },
        CustodyRefusal::IdempotencyConflict,
        CustodyRefusal::PayloadTooLarge,
    ] {
        assert_eq!(DmFsV3Refusal::try_from(&refusal), Err(refusal));
    }
    for scope in [RetryScope::NodeCapacity, RetryScope::PreAuthSource] {
        for (input, expected) in [
            (0, 1000),
            (999, 1000),
            (1000, 1000),
            (3_600_000, 3_600_000),
            (3_600_001, 3_600_000),
            (u32::MAX, 3_600_000),
        ] {
            let hint = RetryHint { scope, retry_after_ms: input };
            assert_eq!(
                DmFsV3Refusal::Busy.retry_hint(Some(hint), scope)?,
                Some(RetryHint { scope, retry_after_ms: expected })
            );
        }
    }
    assert_eq!(
        DmFsV3Refusal::Busy.retry_hint(
            Some(RetryHint::new(RetryScope::PreAuthSource, 1000)),
            RetryScope::NodeCapacity
        ),
        Err(p::DecodeError::Value)
    );
    let hint = RetryHint::new(RetryScope::NodeCapacity, 1000);
    for native in all {
        assert_eq!(DmFsV3Refusal::from(native).retry_hint(None, RetryScope::NodeCapacity)?, None);
        if native != P::Busy {
            assert_eq!(
                DmFsV3Refusal::from(native).retry_hint(Some(hint), RetryScope::NodeCapacity),
                Err(p::DecodeError::Value)
            );
        }
    }
    assert_eq!(
        DmFsV3Refusal::Busy.retry_hint(Some(hint), RetryScope::PreAuthSource),
        Err(p::DecodeError::Value)
    );
    Ok(())
}
#[test]
fn dm_fs_v3_new_apis_do_no_io() -> Result {
    // Independent literal import/call inventory, alongside execution of pure builders/verifiers.
    for source in [
        include_str!("builders.rs"),
        include_str!("verify.rs"),
        include_str!("refusal.rs"),
        include_str!("mod.rs"),
    ] {
        for forbidden in [
            "std::fs",
            "std::net",
            "tokio::",
            "rusqlite",
            "reqwest",
            "RamfluxClient",
            "SdkError",
            "BranchCredentials",
            "std::process",
            "include!",
            "unsafe",
        ] {
            assert!(!source.contains(forbidden), "unexpected runtime dependency: {forbidden}");
        }
    }
    dm_fs_v3_sdk_builders_match_vectors()?;
    let view = p::PublicPrekeyView::from_bytes(&raw("PublicPrekeyView")?)?;
    assert_eq!(
        verify_public_view(&raw("PublicPrekeyView")?, &view.authority, view.home_generation)?,
        view
    );
    let intent = p::PrekeyLeaseIntent::from_bytes(&raw("PrekeyLeaseIntent")?)?;
    let key = SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes();
    for name in ["lease_opk", "lease_spk_only"] {
        let bytes = raw(name)?;
        assert_eq!(verify_lease_result(&bytes, &intent, &key)?.to_bytes()?, bytes);
    }
    let status = p::OwnerPrekeyStatus::from_bytes(&raw("OwnerPrekeyStatus")?)?;
    let mismatched_query = p::OwnerStatusQuery::from_bytes(&raw("OwnerStatusQuery")?)?;
    assert_eq!(
        verify_owner_status(&status.to_bytes()?, &mismatched_query, &status.base_hash, &key),
        Err(c::NativePrekeyError::Binding)
    );
    let query = status_query(&status);
    assert_eq!(
        verify_owner_status(&raw("OwnerPrekeyStatus")?, &query, &status.base_hash, &key)?,
        status
    );
    Ok(())
}
#[test]
fn dm_fs_v3_sdk_handoff_contains_only_scoped_secrets() -> Result {
    fn zeroizing<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    macro_rules! no_impl {
        ($ty:ty, $trait:path) => {{
            trait AmbiguousIfImpl<A> {
                fn marker() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            struct Implemented;
            impl<T: ?Sized + $trait> AmbiguousIfImpl<Implemented> for T {}
            let _ = <$ty as AmbiguousIfImpl<_>>::marker;
        }};
    }
    no_impl!(NativeInitiatorHandoff, std::fmt::Debug);
    no_impl!(NativeInitiatorHandoff, Clone);
    no_impl!(NativeInitiatorHandoff, serde::Serialize);
    no_impl!(NativeInitiatorHandoff, serde::de::DeserializeOwned);
    no_impl!(NativeRecipientHandoff, std::fmt::Debug);
    no_impl!(NativeRecipientHandoff, Clone);
    no_impl!(NativeRecipientHandoff, serde::Serialize);
    no_impl!(NativeRecipientHandoff, serde::de::DeserializeOwned);
    for vector in crypto()?["bootstrap"].as_array().ok_or("bootstrap")? {
        let mode = vector["mode"].as_str().ok_or("mode")?;
        let lease = p::PrekeyLeaseResult::from_bytes(&raw(&format!("lease_{mode}"))?)?;
        let t = p::BootstrapTranscript::from_bytes(&raw(&format!("transcript_{mode}"))?)?;
        let key = SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes();
        let dh1 = zeroize::Zeroizing::new(fixed(&vector["dh"][0])?);
        let output = native_initiator(
            NativeInitiatorInput {
                lease: &lease,
                header: t.header,
                node_key: &key,
                agreement_dh1: &dh1,
                envelope_created_at: t.envelope_created_at,
                envelope_ttl: t.envelope_ttl,
                now: lease.issued_at,
            },
            &mut c::NativeOsRng,
        )?;
        let NativeInitiatorHandoff { public, initial_sk, ratchet_seed } = output;
        assert_eq!(initial_sk.as_ref().len(), 32);
        assert_eq!(ratchet_seed.as_ref().len(), 32);
        assert_ne!(public.transcript.header.ephemeral_key, public.transcript.header.ratchet_key);
        let bytes = public.transcript.to_bytes()?;
        for secret in [initial_sk.as_ref(), ratchet_seed.as_ref()] {
            assert!(!bytes.windows(32).any(|w| w == secret));
        }
        zeroizing(&initial_sk);
        zeroizing(&ratchet_seed);
        drop((initial_sk, ratchet_seed));
    }
    Ok(())
}

fn public_view_contract() -> Result {
    let binding = c::NativePrekeyError::Binding;
    let signature = c::NativePrekeyError::Signature;
    let view = p::PublicPrekeyView::from_bytes(&raw("PublicPrekeyView")?)?;
    let mut changed = view.clone();
    changed.home_generation += 1;
    assert_eq!(
        verify_public_view(&changed.to_bytes()?, &view.authority, view.home_generation),
        Err(binding)
    );
    for field in 0..8 {
        let mut changed = view.clone();
        mutate_branch(&mut changed.authority, field);
        assert_eq!(
            verify_public_view(&changed.to_bytes()?, &view.authority, view.home_generation),
            Err(binding),
            "authority branch field {field}"
        );

        let mut changed = view.clone();
        mutate_branch(&mut changed.base.branch, field);
        changed.base = sign_changed_branch_base(changed.base)?;
        assert_eq!(
            verify_public_view(&changed.to_bytes()?, &view.authority, view.home_generation),
            Err(binding),
            "base branch field {field}"
        );
    }
    let mut changed = view.clone();
    changed.base.signature[0] ^= 1;
    assert_eq!(
        verify_public_view(&changed.to_bytes()?, &view.authority, view.home_generation),
        Err(signature)
    );
    Ok(())
}

fn verifier_contract() -> Result {
    public_view_contract()?;
    let binding = c::NativePrekeyError::Binding;
    let signature = c::NativePrekeyError::Signature;
    let node = signer("PrekeyLeaseResult")?;
    let key = c::NativePrekeySigner::public_key(&node);
    let intent = p::PrekeyLeaseIntent::from_bytes(&raw("PrekeyLeaseIntent")?)?;
    for mode in ["opk", "spk_only"] {
        let lease = p::PrekeyLeaseResult::from_bytes(&raw(&format!("lease_{mode}"))?)?;
        for field in 0..8 {
            let mut changed = lease.clone();
            mutate_branch(&mut changed.requester, field);
            let changed = c::sign_lease_result(changed, &node)?;
            assert_eq!(
                verify_lease_result(&changed.to_bytes()?, &intent, &key),
                Err(binding),
                "requester branch field {field} ({mode})"
            );

            let mut other_intent = intent.clone();
            mutate_branch(&mut other_intent.target, field);
            let mut changed = lease.clone();
            changed.operation_id = c::lease_operation_id(&other_intent)?;
            let changed = c::sign_lease_result(changed, &node)?;
            assert_eq!(
                verify_lease_result(&changed.to_bytes()?, &other_intent, &key),
                Err(binding),
                "target branch field {field} ({mode})"
            );
        }
        let mut changed = lease.clone();
        changed.operation_id[0] ^= 1;
        let changed = c::sign_lease_result(changed, &node)?;
        assert_eq!(verify_lease_result(&changed.to_bytes()?, &intent, &key), Err(binding));
        let mut changed = lease.clone();
        changed.base.update_counter += 1;
        changed.base = build_base(changed.base, &signer("SignedNativePrekeyBase")?)?;
        let changed = c::sign_lease_result(changed, &node)?;
        assert_eq!(verify_lease_result(&changed.to_bytes()?, &intent, &key), Err(binding));
        assert_eq!(verify_lease_result(&lease.to_bytes()?, &intent, &[0; 32]), Err(signature));
    }
    let status = p::OwnerPrekeyStatus::from_bytes(&raw("OwnerPrekeyStatus")?)?;
    let query = status_query(&status);
    assert_eq!(verify_owner_status(&status.to_bytes()?, &query, &status.base_hash, &key)?, status);
    for field in 0..8 {
        let mut changed = status.clone();
        mutate_branch(&mut changed.owner, field);
        let changed = c::sign_owner_status(changed, &node)?;
        assert_eq!(
            verify_owner_status(&changed.to_bytes()?, &query, &status.base_hash, &key),
            Err(binding),
            "owner branch field {field}"
        );
    }
    let mut changed = status.clone();
    changed.base_hash[0] ^= 1;
    let changed = c::sign_owner_status(changed, &node)?;
    assert_eq!(
        verify_owner_status(&changed.to_bytes()?, &query, &status.base_hash, &key),
        Err(binding)
    );
    for slot in 0..3 {
        let mut changed = status.clone();
        match slot {
            0 => changed.entries[0].key_id[0] ^= 1,
            1 => changed.entries[0].generation += 1,
            _ => changed.entries[0].serial += 1,
        }
        let changed = c::sign_owner_status(changed, &node)?;
        assert_eq!(
            verify_owner_status(&changed.to_bytes()?, &query, &status.base_hash, &key),
            Err(binding)
        );
    }
    assert_eq!(
        verify_owner_status(&status.to_bytes()?, &query, &status.base_hash, &[0; 32]),
        Err(signature)
    );
    received_bytes_contract()
}

fn mutate_branch(branch: &mut p::QualifiedBranch, field: usize) {
    match field {
        0 => branch.account_anchor[0] ^= 1,
        1 => branch.principal_id.push('x'),
        2 => branch.device_id.push('x'),
        3 => branch.device_epoch += 1,
        4 => branch.certificate_hash[0] ^= 1,
        5 => branch.record_hash[0] ^= 1,
        6 => {
            branch.signing_key = SigningKey::from_bytes(&[0xa5; 32]).verifying_key().to_bytes();
        }
        7 => branch.agreement_key[0] ^= 1,
        _ => unreachable!("qualified branch field index"),
    }
}

fn sign_changed_branch_base(
    mut base: p::SignedNativePrekeyBase,
) -> Result<p::SignedNativePrekeyBase> {
    let owner = signer("SignedNativePrekeyBase")?;
    let signer = if base.branch.signing_key == c::NativePrekeySigner::public_key(&owner) {
        owner
    } else {
        FixtureSigner(SigningKey::from_bytes(&[0xa5; 32]))
    };
    base.signature = [0; 64];
    Ok(build_base(base, &signer)?)
}

fn received_bytes_contract() -> Result {
    let view = p::PublicPrekeyView::from_bytes(&raw("PublicPrekeyView")?)?;
    let intent = p::PrekeyLeaseIntent::from_bytes(&raw("PrekeyLeaseIntent")?)?;
    let status = p::OwnerPrekeyStatus::from_bytes(&raw("OwnerPrekeyStatus")?)?;
    let query = status_query(&status);
    let key = c::NativePrekeySigner::public_key(&signer("PrekeyLeaseResult")?);
    // Mutate the actual received bytes; encode/decode round trips cannot hide these errors.
    for (name, kind) in [
        ("PublicPrekeyView", p::WireType::PublicPrekeyView),
        ("lease_opk", p::WireType::PrekeyLeaseResult),
        ("OwnerPrekeyStatus", p::WireType::OwnerPrekeyStatus),
    ] {
        let check = |bytes: &[u8]| -> std::result::Result<(), c::NativePrekeyError> {
            match kind {
                p::WireType::PublicPrekeyView => {
                    verify_public_view(bytes, &view.authority, view.home_generation).map(|_| ())
                }
                p::WireType::PrekeyLeaseResult => {
                    verify_lease_result(bytes, &intent, &key).map(|_| ())
                }
                _ => verify_owner_status(bytes, &query, &status.base_hash, &key).map(|_| ()),
            }
        };
        let bytes = raw(name)?;
        let mut changed = bytes.clone();
        changed.push(0);
        assert_eq!(check(&changed), Err(p::DecodeError::Trailing.into()));
        let mut changed = bytes.clone();
        changed[10..14].copy_from_slice(&65u32.to_be_bytes());
        assert_eq!(check(&changed), Err(p::DecodeError::FieldCeiling.into()));
        let mut changed = bytes.clone();
        changed[5] = 2;
        assert_eq!(check(&changed), Err(p::DecodeError::Header.into()));
        let mut changed = bytes.clone();
        changed[8..10].copy_from_slice(&0xffffu16.to_be_bytes());
        assert_eq!(check(&changed), Err(p::DecodeError::Fields.into()));
        assert_eq!(check(&vec![0; kind.ceiling() + 1]), Err(p::DecodeError::TypeCeiling.into()));
    }
    Ok(())
}
fn builder_bounds() -> Result {
    let owner = signer("SignedNativePrekeyBase")?;
    let mut base = p::SignedNativePrekeyBase::from_bytes(&raw("SignedNativePrekeyBase")?)?;
    for len in [1, 256] {
        base.branch.principal_id = "x".repeat(len);
        base.branch.device_id = "y".repeat(len);
        build_base(base.clone(), &owner)?;
    }
    for invalid in [String::new(), "x".repeat(257), "bad\n".to_owned()] {
        for field in 0..2 {
            let mut changed = base.clone();
            if field == 0 {
                changed.branch.principal_id = invalid.clone();
            } else {
                changed.branch.device_id = invalid.clone();
            }
            assert!(matches!(
                build_base(changed, &owner),
                Err(c::NativePrekeyError::Decode(p::DecodeError::Value))
            ));
        }
    }
    let mut update = p::OwnerPrekeyUpdate::from_bytes(&raw("OwnerPrekeyUpdate")?)?;
    let opk = p::SignedNativeOpk::from_bytes(&raw("SignedNativeOpk")?)?;
    update.additive_opks.clear();
    for n in 0..64 {
        let mut v = opk.clone();
        v.serial = n + 1;
        v.opk_id[..8].copy_from_slice(&n.to_be_bytes());
        update.additive_opks.push(build_opk(v, &update.base.branch, &owner)?);
    }
    let retirement = p::RetirementRef::from_bytes(&raw("RetirementRef")?)?;
    update.retirements = (0..400)
        .map(|n| {
            let mut r = retirement.clone();
            r.serial = n + 1;
            r.key_id[..8].copy_from_slice(&n.to_be_bytes());
            r
        })
        .collect();
    let maximal = build_owner_update(update.clone(), &owner)?;
    let mut extra = update.clone();
    let mut opk = opk;
    opk.serial = 65;
    opk.opk_id = [65; 32];
    extra.additive_opks.push(build_opk(opk, &extra.base.branch, &owner)?);
    assert!(matches!(
        build_owner_update(extra, &owner),
        Err(c::NativePrekeyError::Decode(p::DecodeError::Count))
    ));
    let mut extra = update;
    let mut r = retirement;
    r.serial = 401;
    r.key_id = [66; 32];
    extra.retirements.push(r);
    assert!(matches!(
        build_owner_update(extra, &owner),
        Err(c::NativePrekeyError::Decode(p::DecodeError::Count))
    ));
    let snapshot = p::PrekeyPublicationSnapshot::from_bytes(&raw("PrekeyPublicationSnapshot")?)?;
    for field in 0..4 {
        let mut changed = snapshot.clone();
        match field {
            0 => changed.counter += 1,
            1 => changed.epoch += 1,
            2 => changed.generation += 1,
            _ => changed.retirement_digest[0] ^= 1,
        }
        assert_eq!(build_publication_snapshot(&changed), Err(c::NativePrekeyError::Binding));
    }
    let mut max_snapshot = snapshot;
    max_snapshot.update = maximal;
    max_snapshot.pending_retirements = max_snapshot.update.retirements.clone();
    max_snapshot.retirement_digest = c::retirement_digest(&max_snapshot.pending_retirements)?;
    build_publication_snapshot(&max_snapshot)?;
    let mut intent = p::PrekeyLeaseIntent::from_bytes(&raw("PrekeyLeaseIntent")?)?;
    for lifetime in [0, 300, 301, 600] {
        intent.expires_at = intent.issued_at + lifetime;
        build_lease_intent(&intent)?;
    }
    intent.expires_at = intent.issued_at + 601;
    assert_eq!(build_lease_intent(&intent), Err(p::DecodeError::Value.into()));
    intent.expires_at = intent.issued_at - 1;
    assert_eq!(build_lease_intent(&intent), Err(p::DecodeError::Value.into()));
    Ok(())
}

fn request_status_bounds() -> Result {
    let request = p::NativePrekeyRequest::from_bytes(&raw("NativePrekeyRequest")?)?;
    let source = signer("NativePrekeyRequest")?;
    for field in 0..3 {
        for len in [1, 256] {
            let mut changed = request.clone();
            match field {
                0 => changed.node_id = "x".repeat(len),
                1 => changed.gateway_id = "x".repeat(len),
                _ => changed.session_id = "x".repeat(len),
            }
            build_request(changed, &source)?;
        }
        for invalid in [String::new(), "x".repeat(257), "bad\n".to_owned()] {
            let expected = if invalid.len() > 256 {
                p::DecodeError::FieldCeiling
            } else {
                p::DecodeError::Value
            };
            let mut changed = request.clone();
            match field {
                0 => changed.node_id = invalid,
                1 => changed.gateway_id = invalid,
                _ => changed.session_id = invalid,
            }
            assert_eq!(build_request(changed, &source), Err(expected.into()));
        }
    }
    for lifetime in [0, 300] {
        let mut changed = request.clone();
        changed.expires_at = changed.issued_at + lifetime;
        build_request(changed, &source)?;
    }
    for expires_at in [request.issued_at - 1, request.issued_at + 301] {
        let mut changed = request.clone();
        changed.expires_at = expires_at;
        assert_eq!(build_request(changed, &source), Err(p::DecodeError::Value.into()));
    }
    let mut status = p::OwnerPrekeyStatus::from_bytes(&raw("OwnerPrekeyStatus")?)?;
    let original = status.entries[0].clone();
    let node = signer("OwnerPrekeyStatus")?;
    let key = c::NativePrekeySigner::public_key(&node);
    for count in [0, 200] {
        status.entries = (0..count)
            .map(|n| {
                let mut e = original.clone();
                e.serial = n + 1;
                e.key_id[..8].copy_from_slice(&n.to_be_bytes());
                e
            })
            .collect();
        let status = c::sign_owner_status(status.clone(), &node)?;
        let query = p::OwnerStatusQuery {
            profile: status.profile.clone(),
            owner: status.owner.clone(),
            requested_ids: status
                .entries
                .iter()
                .map(|e| p::RetirementRef {
                    generation: e.generation,
                    serial: e.serial,
                    key_id: e.key_id,
                })
                .collect(),
        };
        assert_eq!(
            verify_owner_status(&status.to_bytes()?, &query, &status.base_hash, &key)?,
            status
        );
        if count == 200 {
            let mut query = query;
            let mut extra = query.requested_ids[0].clone();
            extra.serial = 201;
            extra.key_id = [201; 32];
            query.requested_ids.push(extra);
            assert_eq!(
                verify_owner_status(&status.to_bytes()?, &query, &status.base_hash, &key),
                Err(p::DecodeError::Count.into())
            );
        }
    }
    Ok(())
}

fn status_query(status: &p::OwnerPrekeyStatus) -> p::OwnerStatusQuery {
    p::OwnerStatusQuery {
        profile: status.profile.clone(),
        owner: status.owner.clone(),
        requested_ids: status
            .entries
            .iter()
            .map(|e| p::RetirementRef {
                generation: e.generation,
                serial: e.serial,
                key_id: e.key_id,
            })
            .collect(),
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::SigningKey;
use ramflux_crypto::{
    CryptoError, DmSession, GroupMemberCommitment, GroupSenderKeyState, X25519KeyPair,
    create_device_branch, create_group_sender_key_distribution, create_prekey_bundle_with_lineage,
    create_recovery_quorum, derive_recovery_secret, franking_node_tag_preimage,
    membership_commitment_hash, public_key_base64url_from_seed, recover_secret_from_quorum,
    sign_canonical_bytes_with_seed, sign_franking_node_tag, verify_canonical_signature,
    verify_franking_node_tag, verify_prekey_bundle_with_lineage,
};
use ramflux_protocol::{decode_base64url, encode_base64url};

const ALICE_HASH: [u8; 32] = [0xa1; 32];
const BOB_HASH: [u8; 32] = [0xb2; 32];
const TEST_TRANSCRIPT_HASH: [u8; 32] = [0xc3; 32];
const ED25519_GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn signature_with_noncanonical_s(signature_base64url: &str) -> Result<String, CryptoError> {
    let mut bytes = decode_base64url(signature_base64url)?;
    let mut carry = 0_u16;
    for (offset, order_byte) in ED25519_GROUP_ORDER.iter().enumerate() {
        let index = 32 + offset;
        let sum = u16::from(bytes[index]) + u16::from(*order_byte) + carry;
        bytes[index] = u8::try_from(sum & 0xff).map_err(|_err| CryptoError::VerifyFailed)?;
        carry = sum >> 8;
    }
    if carry != 0 {
        return Err(CryptoError::VerifyFailed);
    }
    Ok(encode_base64url(&bytes))
}

#[test]
fn strict_ed25519_verification_rejects_noncanonical_signature_s() -> Result<(), CryptoError> {
    let message = b"ramflux strict ed25519 verification";
    let seed = [0x31; 32];
    let public_key = public_key_base64url_from_seed(seed);
    let signature = sign_canonical_bytes_with_seed(message, seed);
    verify_canonical_signature(message, &signature, &public_key)?;

    let noncanonical = signature_with_noncanonical_s(&signature)?;
    assert!(matches!(
        verify_canonical_signature(message, &noncanonical, &public_key),
        Err(CryptoError::VerifyFailed)
    ));
    Ok(())
}

#[test]
fn dm_committing_aead_roundtrip_rejects_key_commitment_tamper() -> Result<(), CryptoError> {
    let root = [0x11; 32];
    let mut alice = DmSession::initiator(root, ALICE_HASH, BOB_HASH, TEST_TRANSCRIPT_HASH)?
        .with_header_identity(ALICE_HASH, BOB_HASH, 7)
        .with_device_epochs(7, 7);
    let mut bob = DmSession::recipient(root, BOB_HASH, ALICE_HASH, TEST_TRANSCRIPT_HASH)?
        .with_header_identity(BOB_HASH, ALICE_HASH, 7)
        .with_device_epochs(7, 7);
    let ciphertext = alice.encrypt(b"m1.3 dm committing aead", b"ad")?;
    let plaintext = bob.decrypt(&ciphertext, b"ad")?;
    assert_eq!(plaintext, b"m1.3 dm committing aead");
    assert_eq!(
        ciphertext.header_hash,
        ramflux_protocol::header_hash_base64url(
            ramflux_protocol::HeaderKind::DmMessage,
            &[
                ramflux_protocol::HeaderField::string(1, alice.session_id.clone()),
                ramflux_protocol::HeaderField::bytes32(2, ALICE_HASH),
                ramflux_protocol::HeaderField::bytes32(3, BOB_HASH),
                ramflux_protocol::HeaderField::bytes32(4, [0_u8; 32]),
                ramflux_protocol::HeaderField::u64(5, 0),
                ramflux_protocol::HeaderField::u64(6, 0),
                ramflux_protocol::HeaderField::u64(7, 7),
                ramflux_protocol::HeaderField::string(8, format!("{}:0", alice.session_id)),
            ],
        )?
    );

    let mut tampered = ciphertext.clone();
    tampered.key_commitment = "tampered".to_owned();
    let err = bob.decrypt(&tampered, b"ad");
    assert!(matches!(err, Err(CryptoError::AeadFailed | CryptoError::KeyCommitmentMismatch)));
    Ok(())
}

#[test]
fn dm_committing_aead_rejects_franking_commitment_field_tamper() -> Result<(), CryptoError> {
    let root = [0x11; 32];
    let mut alice = DmSession::initiator(root, ALICE_HASH, BOB_HASH, TEST_TRANSCRIPT_HASH)?;
    let mut bob = DmSession::recipient(root, BOB_HASH, ALICE_HASH, TEST_TRANSCRIPT_HASH)?;
    let mut ciphertext = alice.encrypt(b"m1.3 dm franking field", b"ad")?;
    ciphertext.franking_commitment = "tampered-franking-commitment".to_owned();

    assert!(matches!(bob.decrypt(&ciphertext, b"ad"), Err(CryptoError::CommitmentMismatch)));
    Ok(())
}

#[test]
fn dm_out_of_order_and_max_skip_are_enforced() -> Result<(), CryptoError> {
    let root = [0x22; 32];
    let mut alice = DmSession::initiator(root, ALICE_HASH, BOB_HASH, TEST_TRANSCRIPT_HASH)?;
    let mut bob = DmSession::recipient(root, BOB_HASH, ALICE_HASH, TEST_TRANSCRIPT_HASH)?;
    let first = alice.encrypt(b"first", b"")?;
    let second = alice.encrypt(b"second", b"")?;
    assert_eq!(bob.decrypt(&second, b"")?, b"second");
    assert_eq!(bob.decrypt(&first, b"")?, b"first");

    let mut constrained = DmSession::recipient(root, BOB_HASH, ALICE_HASH, TEST_TRANSCRIPT_HASH)?;
    constrained.max_skip = 0;
    let too_far = constrained.decrypt(&second, b"");
    assert!(matches!(too_far, Err(CryptoError::MaxSkipExceeded)));
    Ok(())
}

#[test]
fn dm_with_ratchet_bootstrap_roundtrips_bidirectionally() -> Result<(), CryptoError> {
    let root = [0x24; 32];
    let alice_initial_ratchet = X25519KeyPair::from_seed([0x25; 32]);
    let bob_initial_ratchet = X25519KeyPair::from_seed([0x26; 32]);
    let mut alice = DmSession::initiator_with_remote_ratchet(
        root,
        ALICE_HASH,
        BOB_HASH,
        TEST_TRANSCRIPT_HASH,
        &alice_initial_ratchet,
        bob_initial_ratchet.public,
    )?;
    let mut bob = DmSession::recipient_with_local_ratchet(
        root,
        BOB_HASH,
        ALICE_HASH,
        TEST_TRANSCRIPT_HASH,
        &bob_initial_ratchet,
    )?;

    let alice_first = alice.encrypt(b"alice first with ratchet", b"ratchet-ad")?;
    let alice_second = alice.encrypt(b"alice second with ratchet", b"ratchet-ad")?;
    let alice_third = alice.encrypt(b"alice third with ratchet", b"ratchet-ad")?;
    assert_eq!(bob.decrypt(&alice_first, b"ratchet-ad")?, b"alice first with ratchet");
    assert_eq!(bob.decrypt(&alice_second, b"ratchet-ad")?, b"alice second with ratchet");
    assert_eq!(bob.decrypt(&alice_third, b"ratchet-ad")?, b"alice third with ratchet");
    assert_ne!(bob.ratchet_public_key(), Some(bob_initial_ratchet.public));

    let bob_first = bob.encrypt(b"bob first with ratchet", b"ratchet-ad")?;
    let bob_second = bob.encrypt(b"bob second with ratchet", b"ratchet-ad")?;
    let bob_third = bob.encrypt(b"bob third with ratchet", b"ratchet-ad")?;
    assert_ne!(bob_first.ratchet_public_key, Some(bob_initial_ratchet.public));
    assert_eq!(alice.decrypt(&bob_first, b"ratchet-ad")?, b"bob first with ratchet");
    assert_eq!(alice.decrypt(&bob_second, b"ratchet-ad")?, b"bob second with ratchet");
    assert_eq!(alice.decrypt(&bob_third, b"ratchet-ad")?, b"bob third with ratchet");
    Ok(())
}

#[test]
fn group_sender_key_roundtrip_removed_member_cannot_decrypt() -> Result<(), CryptoError> {
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let members = vec![
        GroupMemberCommitment {
            member_device_id_hash: [0xa1; 32],
            member_role: "member".to_owned(),
            member_device_epoch: 1,
        },
        GroupMemberCommitment {
            member_device_id_hash: [0xb2; 32],
            member_role: "member".to_owned(),
            member_device_epoch: 1,
        },
    ];
    let membership = membership_commitment_hash([0x44; 32], 2, 3, &members, [0x55; 32], "sender-1");
    let distribution = create_group_sender_key_distribution(
        [0x44; 32],
        2,
        3,
        [0xa1; 32],
        "sender-1".to_owned(),
        [0x66; 32],
        signing_key.verifying_key().to_bytes(),
        membership,
    );
    let mut sender = GroupSenderKeyState::from_distribution(distribution.clone());
    let mut receiver = GroupSenderKeyState::from_distribution(distribution);
    let ciphertext = sender.encrypt(b"group plaintext", b"group-ad", &signing_key)?;
    assert_eq!(receiver.decrypt(&ciphertext, b"group-ad", &membership)?, b"group plaintext");

    let removed_membership =
        membership_commitment_hash([0x44; 32], 2, 4, &members[..1], [0x55; 32], "sender-2");
    let removed = receiver.decrypt(&ciphertext, b"group-ad", &removed_membership);
    assert!(matches!(removed, Err(CryptoError::MembershipCommitmentMismatch)));
    Ok(())
}

#[test]
fn group_sender_key_rejects_franking_commitment_field_tamper() -> Result<(), CryptoError> {
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let members = vec![GroupMemberCommitment {
        member_device_id_hash: [0xa1; 32],
        member_role: "member".to_owned(),
        member_device_epoch: 1,
    }];
    let membership = membership_commitment_hash([0x44; 32], 2, 3, &members, [0x55; 32], "sender-1");
    let distribution = create_group_sender_key_distribution(
        [0x44; 32],
        2,
        3,
        [0xa1; 32],
        "sender-1".to_owned(),
        [0x66; 32],
        signing_key.verifying_key().to_bytes(),
        membership,
    );
    let mut sender = GroupSenderKeyState::from_distribution(distribution.clone());
    let mut receiver = GroupSenderKeyState::from_distribution(distribution);
    let mut ciphertext = sender.encrypt(b"group franking field", b"group-ad", &signing_key)?;
    ciphertext.franking_commitment = "tampered-franking-commitment".to_owned();

    assert!(matches!(
        receiver.decrypt(&ciphertext, b"group-ad", &membership),
        Err(CryptoError::CommitmentMismatch)
    ));
    Ok(())
}

#[test]
fn argon2_recovery_and_two_of_three_quorum_work() -> Result<(), CryptoError> {
    let secret = derive_recovery_secret(b"correct horse battery staple", b"ramflux-salt-0001")?;
    let shares = create_recovery_quorum(*secret.expose(), 2, 3)?;
    assert_eq!(recover_secret_from_quorum(&shares[..2])?, *secret.expose());
    assert_eq!(
        recover_secret_from_quorum(&[shares[0].clone(), shares[2].clone()])?,
        *secret.expose()
    );
    let insufficient = recover_secret_from_quorum(&shares[..1]);
    assert!(matches!(insufficient, Err(CryptoError::RecoveryQuorumInsufficient)));
    Ok(())
}

#[test]
fn x3dh_prekey_bundle_requires_device_and_lineage_signatures() -> Result<(), CryptoError> {
    let device = create_device_branch("principal", "device-a", 9, [0x77; 32]);
    let lineage_key = SigningKey::from_bytes(&[0x88; 32]);
    let identity = X25519KeyPair::from_seed([0x12; 32]);
    let signed_prekey = X25519KeyPair::from_seed([0x13; 32]);
    let bundle = create_prekey_bundle_with_lineage(
        &device,
        &lineage_key,
        &identity,
        "spk-1",
        &signed_prekey,
        Some("otk-1".to_owned()),
        Some([0x14; 32]),
    )?;
    verify_prekey_bundle_with_lineage(
        &device.signing_key.verifying_key(),
        &lineage_key.verifying_key(),
        &bundle,
    )?;
    let wrong_lineage = SigningKey::from_bytes(&[0x89; 32]);
    let rejected = verify_prekey_bundle_with_lineage(
        &device.signing_key.verifying_key(),
        &wrong_lineage.verifying_key(),
        &bundle,
    );
    assert!(matches!(rejected, Err(CryptoError::VerifyFailed)));
    Ok(())
}

#[test]
fn franking_node_tag_is_ed25519_signature() -> Result<(), CryptoError> {
    let node_key = SigningKey::from_bytes(&[0x99; 32]);
    let fixture_key = SigningKey::from_bytes(&[0x42; 32]);
    let preimage = franking_node_tag_preimage(
        "node-a",
        "env-a",
        "msg-a",
        &[0xa1; 32],
        "commitment",
        "ciphertext-hash",
        1_760_000_000_001,
    );
    let signature = sign_franking_node_tag(
        "node-a",
        "env-a",
        "msg-a",
        &[0xa1; 32],
        "commitment",
        "ciphertext-hash",
        1_760_000_000_001,
        &node_key,
    );
    verify_franking_node_tag(&preimage, &signature, &node_key.verifying_key())?;
    let fixture_signature = sign_franking_node_tag(
        "node-a",
        "env-a",
        "msg-a",
        &[0xa1; 32],
        "commitment",
        "ciphertext-hash",
        1_760_000_000_001,
        &fixture_key,
    );
    assert!(matches!(
        verify_franking_node_tag(&preimage, &fixture_signature, &node_key.verifying_key()),
        Err(CryptoError::VerifyFailed)
    ));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn m_p0_2_kat_vectors_are_stable() -> Result<(), CryptoError> {
    let alice_identity = X25519KeyPair::from_seed([0x01; 32]);
    let alice_ephemeral = X25519KeyPair::from_seed([0x02; 32]);
    let alice_hash = [0xa1; 32];
    let bob_hash = [0xb2; 32];
    let bob_branch = create_device_branch("bob", "bob-device", 3, [0x03; 32]);
    let bob_identity = X25519KeyPair::from_seed([0x04; 32]);
    let bob_signed_prekey = X25519KeyPair::from_seed([0x05; 32]);
    let bob_one_time_prekey = X25519KeyPair::from_seed([0x06; 32]);
    let bundle = ramflux_crypto::create_prekey_bundle(
        &bob_branch,
        &bob_identity,
        "spk-kat",
        &bob_signed_prekey,
        Some("opk-kat".to_owned()),
        Some(bob_one_time_prekey.public),
    )?;
    let bundle_bytes = serde_json::to_vec(&bundle).map_err(|_err| CryptoError::VerifyFailed)?;
    let bundle_hash =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::X3DH_PREKEY_BUNDLE, &bundle_bytes);
    let initiator = ramflux_crypto::x3dh_initiator(&ramflux_crypto::X3dhInitiatorInput {
        initiator_identity: &alice_identity,
        initiator_ephemeral: &alice_ephemeral,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bob_hash,
        recipient_bundle: &bundle,
        associated_data: b"kat-ad",
        prekey_bundle_hash: &bundle_hash,
        initial_ratchet_public: alice_ephemeral.public,
    })?;
    let recipient = ramflux_crypto::x3dh_recipient(&ramflux_crypto::X3dhRecipientInput {
        recipient_identity: &bob_identity,
        recipient_signed_prekey: &bob_signed_prekey,
        recipient_one_time_prekey: Some(&bob_one_time_prekey),
        initiator_identity_public: alice_identity.public,
        initiator_ephemeral_public: alice_ephemeral.public,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bob_hash,
        recipient_signed_prekey_id: "spk-kat",
        recipient_one_time_prekey_id: Some("opk-kat"),
        associated_data: b"kat-ad",
        prekey_bundle_hash: &bundle_hash,
        initial_ratchet_public: alice_ephemeral.public,
    })?;
    assert_eq!(initiator, recipient);
    assert_eq!(
        hex::encode(initiator.bootstrap_transcript_hash),
        "e62aa7c2d27e54013816d240d1109dda9720876ac9f9ed4848a84dfeaef93d27"
    );
    let mut alice = DmSession::initiator(
        initiator.root_seed,
        alice_hash,
        bob_hash,
        initiator.bootstrap_transcript_hash,
    )?;
    let mut bob = DmSession::recipient(
        recipient.root_seed,
        bob_hash,
        alice_hash,
        recipient.bootstrap_transcript_hash,
    )?;
    let dm = alice.encrypt(b"kat-dm", b"kat-ad")?;
    let dm_plain = bob.decrypt(&dm, b"kat-ad")?;
    assert_eq!(dm_plain, b"kat-dm");
    assert_eq!(dm.session_id, "wyrW-6t266V1NodQX7ab3FdjQC390qOn5ZV00qb_dpk");
    assert_eq!(dm.header_hash, "0FQOnIf_0dKlxDDyYyJSVcYZOK4zAJ7KKcn1Eu8Codk");
    assert_eq!(dm.key_commitment, "lK_ai6JlBoR9cciFyAhlvi3bd1UZ4Lhzr_ac31lZSjg");
    assert_eq!(dm.franking_commitment, "GUFVRwTRsiM5TfnsvCpJbRQJJgYQKb7EtkkIzEjx-Pk");
    assert_eq!(dm.ciphertext_hash, "BL_UUTdmMMYbRLD8Gtgxu1M298jkCwC8ffG_EliCqso");

    let mut skipped_alice = DmSession::initiator(
        initiator.root_seed,
        alice_hash,
        bob_hash,
        initiator.bootstrap_transcript_hash,
    )?;
    let mut skipped_bob = DmSession::recipient(
        recipient.root_seed,
        bob_hash,
        alice_hash,
        recipient.bootstrap_transcript_hash,
    )?;
    let skipped_first = skipped_alice.encrypt(b"kat-skip-0", b"kat-skip-ad")?;
    let skipped_second = skipped_alice.encrypt(b"kat-skip-1", b"kat-skip-ad")?;
    assert_eq!(skipped_bob.decrypt(&skipped_second, b"kat-skip-ad")?, b"kat-skip-1");
    assert_eq!(skipped_bob.decrypt(&skipped_first, b"kat-skip-ad")?, b"kat-skip-0");
    assert_eq!(skipped_first.header_hash, "0FQOnIf_0dKlxDDyYyJSVcYZOK4zAJ7KKcn1Eu8Codk");
    assert_eq!(skipped_second.header_hash, "GP68vVLJf2X1KfXvXxVpUx9lXuoH-wzij9RRavCkwTE");
    assert_eq!(skipped_second.key_commitment, "CfA79qPnCn42CUWwxF6SCUcyGl6qI3h9WKs8YOshxac");

    let signing_key = SigningKey::from_bytes(&[0x07; 32]);
    let membership = membership_commitment_hash(
        [0x08; 32],
        9,
        10,
        &[GroupMemberCommitment {
            member_device_id_hash: [0x09; 32],
            member_role: "member".to_owned(),
            member_device_epoch: 11,
        }],
        [0x0a; 32],
        "kat-sender",
    );
    let distribution = create_group_sender_key_distribution(
        [0x08; 32],
        9,
        10,
        [0x09; 32],
        "kat-sender".to_owned(),
        [0x0b; 32],
        signing_key.verifying_key().to_bytes(),
        membership,
    );
    let mut group_sender = GroupSenderKeyState::from_distribution(distribution.clone());
    let mut group_receiver = GroupSenderKeyState::from_distribution(distribution);
    let group = group_sender.encrypt(b"kat-group", b"group-ad", &signing_key)?;
    assert_eq!(group_receiver.decrypt(&group, b"group-ad", &membership)?, b"kat-group");
    assert_eq!(group.header_hash, "IoDlQTV7M0QhAK-A3jzTSs_eBNkCPrppBwactq4a-QE");
    assert_eq!(group.key_commitment, "6x7DddNJHUohU10oxDDHnpvBqwlnJkf4Cp5KlFqK4VI");
    assert_eq!(group.franking_commitment, "auIKXiaCOn2sqowctDZ6_Epsy5Z313t8wEzQmg2U2Do");
    assert_eq!(group.ciphertext_hash, "7Y9OypoZc_17IuT1LO8krJdpjy5rzdja2VR1YlL78BE");

    let node_key = SigningKey::from_bytes(&[0x0c; 32]);
    let node_tag = sign_franking_node_tag(
        "kat-node",
        "kat-env",
        &dm.message_event_id,
        &dm.sender_device_id_hash,
        &dm.commitment,
        &dm.ciphertext_hash,
        1_760_000_123,
        &node_key,
    );
    assert_eq!(
        node_tag,
        "9WULyqMe2LfoiHj8lrZe5nOMiFxwAv0g67vghJ7vrXJvjrD0r4_9pBmPAp3glnyu6wYmKVXuj1YkclyyBjZ3AA"
    );
    let mut tampered = dm.clone();
    tampered.commitment = "tampered".to_owned();
    let mut tamper_bob = DmSession::recipient(
        recipient.root_seed,
        bob_hash,
        alice_hash,
        recipient.bootstrap_transcript_hash,
    )?;
    assert!(matches!(
        tamper_bob.decrypt(&tampered, b"kat-ad"),
        Err(CryptoError::CommitmentMismatch)
    ));

    Ok(())
}

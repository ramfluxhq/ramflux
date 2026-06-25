// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    DeviceBranch, IdentityRoot, RecoveryQuorumMemberKind, RecoverySecret, RecoveryShare,
    X3dhOutput, X25519KeyPair, create_device_branch, create_identity_root,
};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn long_lived_secret_types_implement_zeroize_on_drop() {
    assert_zeroize_on_drop::<IdentityRoot>();
    assert_zeroize_on_drop::<DeviceBranch>();
    assert_zeroize_on_drop::<X25519KeyPair>();
    assert_zeroize_on_drop::<X3dhOutput>();
    assert_zeroize_on_drop::<RecoveryShare>();
    assert_zeroize_on_drop::<RecoverySecret>();
}

#[test]
fn identity_and_device_signing_keys_zeroize_explicitly() {
    let mut root = create_identity_root("principal", [0x11; 32]);
    assert_eq!(root.signing_key.to_bytes(), [0x11; 32]);
    root.zeroize();
    assert_eq!(root.signing_key.to_bytes(), [0_u8; 32]);
    assert_eq!(root.principal_id, "principal");

    let mut branch = create_device_branch("principal", "device", 7, [0x22; 32]);
    assert_eq!(branch.signing_key.to_bytes(), [0x22; 32]);
    branch.zeroize();
    assert_eq!(branch.signing_key.to_bytes(), [0_u8; 32]);
    assert_eq!(branch.device_id, "device");
    assert_eq!(branch.device_epoch, 7);
}

#[test]
fn x25519_keypair_zeroizes_secret_but_keeps_public_metadata() {
    let mut keypair = X25519KeyPair::from_seed([0x33; 32]);
    let public_before = keypair.public;
    assert_eq!(keypair.secret.to_bytes(), [0x33; 32]);
    keypair.zeroize();
    assert_eq!(keypair.secret.to_bytes(), [0_u8; 32]);
    assert_eq!(keypair.public, public_before);
}

#[test]
fn x3dh_and_recovery_secret_material_zeroizes_explicitly() {
    let mut output = X3dhOutput {
        root_seed: [0x44; 32],
        associated_secret: [0x45; 32],
        bootstrap_transcript_hash: [0x46; 32],
    };
    output.zeroize();
    assert_eq!(output.root_seed, [0_u8; 32]);
    assert_eq!(output.associated_secret, [0_u8; 32]);
    assert_eq!(output.bootstrap_transcript_hash, [0_u8; 32]);

    let mut share = RecoveryShare {
        share_id: 2,
        threshold: 2,
        total: 3,
        member_kind: Some(RecoveryQuorumMemberKind::GuardianShare),
        value: [0x55; 32],
    };
    share.zeroize();
    assert_eq!(share.share_id, 2);
    assert_eq!(share.threshold, 2);
    assert_eq!(share.total, 3);
    assert_eq!(share.member_kind, Some(RecoveryQuorumMemberKind::GuardianShare));
    assert_eq!(share.value, [0_u8; 32]);

    let mut secret = RecoverySecret::new([0x66; 32]);
    secret.zeroize();
    assert_eq!(*secret.expose(), [0_u8; 32]);
}

#[test]
fn long_lived_secret_debug_output_is_redacted() {
    let root = create_identity_root("principal", [0x77; 32]);
    let branch = create_device_branch("principal", "device", 1, [0x78; 32]);
    let x25519 = X25519KeyPair::from_seed([0x79; 32]);
    let x3dh = X3dhOutput {
        root_seed: [0x7a; 32],
        associated_secret: [0x7b; 32],
        bootstrap_transcript_hash: [0x7c; 32],
    };
    let share = RecoveryShare {
        share_id: 3,
        threshold: 2,
        total: 3,
        member_kind: Some(RecoveryQuorumMemberKind::HardwareTokenShare),
        value: [0x7d; 32],
    };
    let recovery = RecoverySecret::new([0x7e; 32]);

    for debug in [
        format!("{root:?}"),
        format!("{branch:?}"),
        format!("{x25519:?}"),
        format!("{x3dh:?}"),
        format!("{share:?}"),
        format!("{recovery:?}"),
    ] {
        assert!(debug.contains("redacted"), "{debug}");
        assert!(!debug.contains("119, 119"), "{debug}");
        assert!(!debug.contains("120, 120"), "{debug}");
        assert!(!debug.contains("121, 121"), "{debug}");
        assert!(!debug.contains("122, 122"), "{debug}");
        assert!(!debug.contains("123, 123"), "{debug}");
        assert!(!debug.contains("124, 124"), "{debug}");
        assert!(!debug.contains("125, 125"), "{debug}");
        assert!(!debug.contains("126, 126"), "{debug}");
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    DeviceTarget, KeySlotBinding, KeySlotError, KeySlotParties, open_file_key, wrap_file_key,
};
use x25519_dalek::{PublicKey, StaticSecret};

fn secret(seed: u8) -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::from([seed; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

fn binding() -> KeySlotBinding {
    KeySlotBinding {
        object_id: [1; 32],
        relay_hash: [2; 32],
        account_anchor: "anchor".into(),
        device_id: "device".into(),
        device_epoch: 3,
        grant_id: [4; 32],
        reference_id: [5; 32],
    }
}

fn target() -> DeviceTarget {
    DeviceTarget { account_anchor: "anchor".into(), device_id: "device".into(), device_epoch: 3 }
}

fn parties(device: &DeviceTarget) -> KeySlotParties<'_> {
    KeySlotParties { caller: device, slot_recipient: device, grant_grantee: device }
}

#[test]
fn format_one_opens_only_for_the_bound_recipient() -> Result<(), KeySlotError> {
    let (secret, public) = secret(9);
    let file_key = [8; 32];
    let wrapped = wrap_file_key(&file_key, &public, &binding())?;
    let device = target();
    let opened = open_file_key(1, &wrapped, &secret.to_bytes(), &binding(), &parties(&device))?;
    assert_eq!(opened.as_ref(), &file_key);
    assert_eq!(
        open_file_key(2, &wrapped, &secret.to_bytes(), &binding(), &parties(&device)),
        Err(KeySlotError::Format)
    );
    let mut other = target();
    other.device_epoch = 4;
    let mismatch =
        KeySlotParties { caller: &device, slot_recipient: &device, grant_grantee: &other };
    assert_eq!(
        open_file_key(1, &wrapped, &secret.to_bytes(), &binding(), &mismatch),
        Err(KeySlotError::Grantee)
    );
    Ok(())
}

#[test]
fn substituted_associated_data_does_not_open() -> Result<(), KeySlotError> {
    let (secret, public) = secret(11);
    let wrapped = wrap_file_key(&[8; 32], &public, &binding())?;
    let mut cases = Vec::new();
    let mut object = binding();
    object.object_id[0] ^= 1;
    cases.push(object);
    let mut relay = binding();
    relay.relay_hash[0] ^= 1;
    cases.push(relay);
    let mut anchor = binding();
    anchor.account_anchor.push('x');
    cases.push(anchor);
    let mut device = binding();
    device.device_id.push('x');
    cases.push(device);
    let mut epoch = binding();
    epoch.device_epoch = 9;
    cases.push(epoch);
    let mut grant = binding();
    grant.grant_id[0] ^= 1;
    cases.push(grant);
    let mut reference = binding();
    reference.reference_id[0] ^= 1;
    cases.push(reference);
    for case in cases {
        let caller = DeviceTarget {
            account_anchor: case.account_anchor.clone(),
            device_id: case.device_id.clone(),
            device_epoch: case.device_epoch,
        };
        assert_eq!(
            open_file_key(1, &wrapped, &secret.to_bytes(), &case, &parties(&caller)),
            Err(KeySlotError::Authentication)
        );
    }
    Ok(())
}

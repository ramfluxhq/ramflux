// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_crypto::custody::{
    GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, create_genesis, verify_record,
};
use ramflux_protocol::{PrincipalKind, custody::DeviceRef, encode_base64url};
use zeroize::Zeroizing;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_000;

fn native(
    seed: u8,
    manager: Option<DeviceRef>,
) -> TestResult<(SelfSigningKey, custody::Envelope<custody::DeviceSet>)> {
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[seed; 32])?)?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([seed + 1; 32]));
    let branch =
        ramflux_crypto::create_device_branch("reach.example", "primary", 1, [seed + 2; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([seed + 3; 32]);
    let record = create_genesis(
        &master,
        &primary,
        &branch,
        &agreement,
        GenesisInput {
            principal_kind: if manager.is_some() {
                PrincipalKind::HeadlessAi
            } else {
                PrincipalKind::Human
            },
            display_name: "Reach authority".into(),
            issued_at: NOW,
            master_cert_id: encode_base64url([seed + 4; 32]),
            branch_cert_id: encode_base64url([seed + 5; 32]),
            external_human_primary: manager,
        },
    )?;
    Ok((primary, record))
}

#[test]
fn cr_current_custodian_advance_fences_unchanged_recipient_head() -> TestResult {
    let (primary, human_record) = native(30, None)?;
    let human = verify_record(&human_record, NOW, None, None)?;
    let (_, agent_record) =
        native(40, Some(human_record.body.master_certificate.body.primary_device_ref.clone()))?;
    let original = verify_record(&agent_record, NOW, None, Some(&human))?;
    let recipient = custody::object_hash(&agent_record)?;
    let original_manager = custodian_head(&original)?;
    require_binding(&original, &recipient, original_manager.as_deref())?;
    assert!(
        require_binding(&original, &recipient, None).is_err(),
        "legacy missing context stays pending"
    );

    let mut next = human_record.body.clone();
    next.device_set_epoch += 1;
    next.previous_record_hash = Some(custody::object_hash(&human_record)?);
    next.issued_at = NOW + 1;
    next.profile.display_name = "Advanced human".into();
    let next = primary.sign_record(next)?;
    let current_human = verify_record(&next, NOW + 1, None, None)?;
    let current = verify_record(&agent_record, NOW + 1, None, Some(&current_human))?;
    assert_eq!(custody::object_hash(current.envelope())?, recipient);
    assert_ne!(custodian_head(&current)?, original_manager);
    assert!(require_binding(&current, &recipient, original_manager.as_deref()).is_err());
    require_binding(&current, &recipient, custodian_head(&current)?.as_deref())?;
    // The old native tuple remains valid at its original time without becoming current authority.
    let historical = verify_record(&agent_record, NOW, None, Some(&human))?;
    require_binding(&historical, &recipient, original_manager.as_deref())?;
    assert_eq!(custodian_head(&human)?, None);
    require_binding(&human, &custody::object_hash(&human_record)?, None)?;
    Ok(())
}

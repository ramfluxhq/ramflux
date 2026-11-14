// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real independently vaulted sibling reconciliation cannot promote a historical signer.
use super::*;
use crate::client::native_test_support::TestResult;
use crate::contact_reach::group_test_support::{roster_fixture, verified_records};
#[tokio::test]
async fn cr_provenance_historical_primary_revocation_never_reactivates_grants() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let (owner, mut phone, _) = roster_fixture().await?;
        let before = phone.client.group_reach_mirror()?.ok_or("original reach mirror")?;
        let original_pool: RetainedProofs = phone.client.account_db()?.load_actor_state(POOL_KEY)?.ok_or("retained original proof pool")?;
        let sibling = phone.enroll_sibling("historical-reach-sibling", "second").await?;
        let now = crate::custody::network_now()?;
        let mut native = sibling.manifest.custody.as_ref().ok_or("sibling native manifest")?.as_ref().clone();
        let current = ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
        let primary = phone.vault.primary_for_public_key(&current.envelope().body.master_certificate.body.self_signing_public_key)?;
        native.publication.record = primary.revoke_device(&current, "primary", now)?;
        native.devices.retain(|device| device.device_ref.device_id != "primary");
        sibling.client.observe_custody_manifest(&native, &before.root, now)?;
        // An authenticated original sibling may supply exact original historical bytes. This
        // fixture transfers that data inside the real encrypted account DB, with no current pin.
        sibling.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            sibling.client.account_db()?.persist_actor_state(POOL_KEY, &original_pool)?;
            Ok(())
        })?;
        let historical = verified_records(&sibling, &before.home_head_hash, before.records.clone(), now)?;
        sibling.client.install_reach_state(historical)?;
        let saved = sibling.client.group_reach_mirror()?.ok_or("historical sibling mirror")?;
        assert!(saved.positive_pending, "historically valid grants cannot bypass revocation of the original approving primary");
        assert_eq!(saved.records, before.records, "restrictive reconciliation retains every exact original object rather than replacing it with current authority");
        let current = sibling.client.current_custody_authority(&before.root, now)?.ok_or("new current authority")?;
        let grant = saved.records.iter().find_map(|record| match record { wire::StateRecord::Grant { update, .. } => Some(update), _ => None }).ok_or("original group grant")?;
        let reference = original_pool.signers.iter().find(|reference| custody::framed_hash(wire::OPERATION_HASH_DOMAIN, grant).is_ok_and(|hash| reference.object_hash == hash)).ok_or("original grant signer")?;
        let proof = original_pool.authorities.iter().find(|proof| proof.proof_hash == reference.proof_hash).ok_or("original grant proof")?;
        ramflux_crypto::contact_reach::verify_historical_admission(grant, proof)?;
        assert!(ramflux_crypto::contact_reach::verify_retained_admission(grant, &current, now).is_err(), "the same old signature must fail independent current management reconciliation");
        assert!(matches!(sibling.client.conversation_reach(owner.client.owned_device_identity()?.root_commitment(), "peer.example", "roster-thread", now), Err(SdkError::InboundPending(_))), "historical evidence cannot expose positive conversation permissions");
        Ok(())
    }).await?
}

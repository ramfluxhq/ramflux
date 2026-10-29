// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retire individually expired directory leases before applying the private OPK pool bound.
use super::*;

const LEASE_GRACE_SECONDS: i64 = 30 * 24 * 60 * 60;
impl RamfluxClient {
    pub(super) fn erase_expired_prekey_leases(
        &self,
        device_id: &str,
        response: &SdkPrekeyResponse,
        now: i64,
    ) -> Result<bool, SdkError> {
        if response.one_time_prekey_leases.is_empty() {
            return Ok(false);
        }
        let device = self.local_device_identity(device_id)?;
        if response.device_id != device_id
            || response.principal_commitment != device.root_commitment()
        {
            return Err(SdkError::LocalBus("prekey lease acknowledgement owner mismatch".into()));
        }
        let mut state = self.load_x3dh_private_state(&device)?;
        let previous_len = state.one_time_prekeys.len();
        state.one_time_prekeys.retain(|key| {
            !matches!(response.one_time_prekey_leases.get(&key.id),
                Some(ramflux_protocol::OneTimePrekeyLease::LeasedAt(at))
                if *at >= 0 && now.saturating_sub(*at) > LEASE_GRACE_SECONDS)
        });
        if state.one_time_prekeys.len() == previous_len {
            return Ok(false);
        }
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            self.persist_owned_private_prekey(&device, &state)?;
            db.persist_actor_state("secrets/retired", &true)?;
            Ok(())
        })?;
        let _ = db.checkpoint_retired_secrets_if_committed()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_protocol::OneTimePrekeyLease::{LeasedAt, Unleased};
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn account(name: &str, seed: u8) -> Result<(tempfile::TempDir, RamfluxClient), SdkError> {
        let path = tempfile::tempdir()?;
        let mut client = RamfluxClient::new();
        client.create_identity_root(name, [seed; 32]);
        client.create_device_branch(name, name, 1, [seed + 1; 32]);
        client.open_account_index(path.path())?;
        client.create_account(name, name)?;
        client.unlock_account(name, b"lease-expiry-test")?;
        Ok((path, client))
    }
    fn acknowledgement(
        client: &RamfluxClient,
        bundle: &ramflux_crypto::PrekeyBundle,
    ) -> Result<SdkPrekeyResponse, SdkError> {
        Ok(SdkPrekeyResponse {
            device_id: bundle.device_id.clone(),
            principal_commitment: client.owned_device_identity()?.root_commitment().into(),
            bundle: Some(ramflux_crypto::signed_prekey_only_bundle(bundle)),
            target_delivery_id: None,
            one_time_prekey_exhausted: true,
            available_one_time_prekeys: 0,
            one_time_prekey_leases: bundle
                .one_time_prekey_ids
                .iter()
                .map(|id| (id.clone(), Unleased))
                .collect(),
        })
    }
    #[test]
    fn two_hundred_expired_unused_leases_are_erased_before_replenishment_and_reopen() -> TestResult
    {
        let (path, client) = account("bob", 11)?;
        let now = now_unix_timestamp();
        let bundle = client.create_prekey_bundle_with_pool_size("bob", [12; 32], now, 200)?;
        let mut response = acknowledgement(&client, &bundle)?;
        for status in response.one_time_prekey_leases.values_mut() {
            *status = LeasedAt(now - 31 * 86400);
        }
        let db = client.account_db()?;
        let checkpoints = db.retired_secret_checkpoint_count();
        assert!(client.directory_requests_prekey_replenishment("bob", &response)?);
        assert!(
            client
                .load_x3dh_private_state(&client.owned_device_identity()?)?
                .one_time_prekeys
                .is_empty()
        );
        assert!(db.secure_delete_enabled()?);
        assert!(db.retired_secret_checkpoint_count() > checkpoints);
        let fresh = client.replenish_one_time_prekeys("bob", [12; 32], 0)?;
        assert_eq!(fresh.one_time_prekey_ids.len(), 8);
        assert!(
            fresh.one_time_prekey_ids.iter().all(|id| !bundle.one_time_prekey_ids.contains(id))
        );
        drop(client);
        let mut reopened = RamfluxClient::new();
        reopened.create_identity_root("bob", [11; 32]);
        reopened.create_device_branch("bob", "bob", 1, [12; 32]);
        reopened.open_account_index(path.path())?;
        reopened.unlock_account("bob", b"lease-expiry-test")?;
        let saved = reopened.load_x3dh_private_state(&reopened.owned_device_identity()?)?;
        assert_eq!(saved.one_time_prekeys.len(), 8);
        assert!(
            saved.one_time_prekeys.iter().all(|key| !bundle.one_time_prekey_ids.contains(&key.id))
        );
        Ok(())
    }
    #[test]
    fn recent_unleased_missing_and_exact_grace_keys_survive_individual_expiry() -> TestResult {
        let (_path, client) = account("bob", 21)?;
        let now = now_unix_timestamp();
        let bundle = client.create_and_store_prekey_bundle_at("bob", [22; 32], now)?;
        let ids = &bundle.one_time_prekey_ids;
        let mut response = acknowledgement(&client, &bundle)?;
        response.one_time_prekey_leases.insert(ids[0].clone(), LeasedAt(now - 31 * 86400));
        response.one_time_prekey_leases.insert(ids[1].clone(), LeasedAt(now - 29 * 86400));
        response.one_time_prekey_leases.insert(ids[2].clone(), Unleased);
        response.one_time_prekey_leases.remove(&ids[3]);
        response.one_time_prekey_leases.insert(ids[4].clone(), LeasedAt(now - 30 * 86400));
        let mut wrong_owner = response.clone();
        wrong_owner.principal_commitment = "foreign".into();
        assert!(client.erase_expired_prekey_leases("bob", &wrong_owner, now).is_err());
        assert!(client.erase_expired_prekey_leases("bob", &response, now)?);
        let state = client.load_x3dh_private_state(&client.owned_device_identity()?)?;
        assert_eq!(state.one_time_prekeys.len(), 7);
        assert!(!state.one_time_prekeys.iter().any(|key| key.id == ids[0]));
        assert!(ids[1..].iter().all(|id| state.one_time_prekeys.iter().any(|key| &key.id == id)));
        assert!(!client.erase_expired_prekey_leases("bob", &response, now)?);
        Ok(())
    }
    #[test]
    fn captured_bootstrap_cannot_use_an_expired_lease_after_private_key_erasure() -> TestResult {
        let (_receiver_path, receiver) = account("bob", 31)?;
        let (_sender_path, sender) = account("alice", 41)?;
        let now = now_unix_timestamp();
        let bundle = receiver.create_and_store_prekey_bundle_at("bob", [32; 32], now)?;
        sender.create_and_store_prekey_bundle_at("alice", [42; 32], now)?;
        let mut leased = ramflux_crypto::signed_prekey_only_bundle(&bundle);
        leased.one_time_prekey_id = Some(bundle.one_time_prekey_ids[0].clone());
        leased.one_time_prekey = Some(bundle.one_time_prekey_x25519_public[0]);
        leased.one_time_prekey_signature = Some(bundle.one_time_prekey_signatures[0].clone());
        let message = GatewayDirectMessage {
            conversation_id: "expired-lease".into(),
            message_id: "first".into(),
            envelope_id: "first".into(),
            source_principal_id: "alice".into(),
            sender_id: "alice".into(),
            recipient_device_id: Some("bob".into()),
            recipient_principal_commitment: Some(
                receiver.owned_device_identity()?.root_commitment().into(),
            ),
            target_delivery_id: "bob".into(),
            encrypted_body: vec![],
            created_at: now,
            ttl: 3600,
        };
        let (mut sending, header) =
            sender.create_send_dm_session_from_bundle(&message, "bob", leased, "alice")?;
        let header = header.ok_or("header")?;
        let aad = crate::dm::dm_associated_data("expired-lease");
        let captured = sending.encrypt(b"captured", aad)?;
        let mut receiving = receiver.create_recv_dm_session_with_aad(&header, aad)?;
        assert_eq!(receiving.decrypt(&captured, aad)?, b"captured");
        drop(receiving);
        let mut response = acknowledgement(&receiver, &bundle)?;
        response
            .one_time_prekey_leases
            .insert(bundle.one_time_prekey_ids[0].clone(), LeasedAt(now - 31 * 86400));
        assert!(receiver.erase_expired_prekey_leases("bob", &response, now)?);
        assert!(receiver.create_recv_dm_session_with_aad(&header, aad).is_err());
        Ok(())
    }
}

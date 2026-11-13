// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable event sequence and hybrid logical clock; recipient fan-out reuses the identity.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

pub(crate) const HLC_MAX_SKEW_MS: u64 = 120_000;
const MAX_PHYSICAL_MS: u64 = (1 << 48) - 1;

#[derive(Serialize, Deserialize)]
struct Counter {
    conversation_id: String,
    author: g::QualifiedDevice,
    sequence: u64,
}

fn refused(reason: &str) -> SdkError {
    SdkError::LocalBus(format!("message identity: {reason}"))
}
fn tick(physical: u64, logical: u64) -> Result<u64, SdkError> {
    let (physical, logical) = if logical > u64::from(u16::MAX) {
        (physical.checked_add(1).ok_or_else(|| refused("clock exhausted"))?, 0)
    } else {
        (physical, logical)
    };
    if physical > MAX_PHYSICAL_MS {
        return Err(refused("clock exhausted"));
    }
    Ok((physical << 16) | logical)
}

impl RamfluxClient {
    /// Derive an ordinary DM scope from this account and a verified peer device root.
    /// Names, device rotations, primary transfer and home location do not enter the id.
    /// # Errors
    /// Refuses unavailable/revoked peer authority, malformed anchors and the same root.
    pub fn generated_direct_conversation_id(
        &self,
        peer: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<String, SdkError> {
        self.trusted_device(crate::client::identity_authority::HeadUse::NewAuthorization, peer)?;
        g::dm_scope::derive(&self.own_account_anchor()?, peer.root_commitment())
            .map_err(|_| refused("invalid ordinary DM root pair"))
    }
    fn generated_hlc_key(&self) -> Result<String, SdkError> {
        Ok(format!("message-identity/hlc/{}", self.owned_device_identity()?.storage_key()))
    }

    /// Allocate once in the same transaction as the logical event's prepared/outbox row.
    pub(crate) fn allocate_generated_identity(
        &self,
        conversation: &str,
        now_ms: u64,
        own_only: bool,
    ) -> Result<g::EventIdentity, SdkError> {
        self.account_db()?.write_transaction(|| {
            self.allocate_generated_identity_in(conversation, now_ms, own_only)
        })
    }

    fn allocate_generated_identity_in(
        &self,
        conversation: &str,
        now_ms: u64,
        own_only: bool,
    ) -> Result<g::EventIdentity, SdkError> {
        self.require_backup_outbound_ready()?;
        let source = self.owned_device_identity()?;
        let author = g::QualifiedDevice {
            account_anchor: source.root_commitment().into(),
            device_id: source.device_id().into(),
            device_epoch: self
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .device_epoch,
        };
        let key = format!(
            "message-identity/counter/{}",
            ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&(
                &author,
                conversation,
                own_only
            ))?,)
        );
        let db = self.account_db()?;
        let sequence = db
            .load_actor_state::<Counter>(&key)?
            .map_or(0, |counter| counter.sequence)
            .checked_add(1)
            .ok_or_else(|| refused("sequence exhausted"))?;
        if sequence >= (1 << 63) {
            return Err(refused("sequence namespace exhausted"));
        }
        let wire_sequence = if own_only { sequence | (1 << 63) } else { sequence };
        let clock_key = self.generated_hlc_key()?;
        let stored = db.load_actor_state::<u64>(&clock_key)?.unwrap_or(0);
        let physical = (stored >> 16).max(now_ms);
        let logical = if physical == stored >> 16 { (stored & 0xffff) + 1 } else { 0 };
        let hlc = tick(physical, logical)?;
        let id = g::identity::derive(&author, conversation, wire_sequence)
            .map_err(|_| refused("incomplete source or conversation"))?;
        db.persist_actor_state(
            &key,
            &Counter { conversation_id: conversation.into(), author: author.clone(), sequence },
        )?;
        db.admit_actor_counter_floor(&clock_key, hlc, ramflux_storage::FloorPolicy::Refuse)?;
        Ok(g::EventIdentity {
            id: id.to_vec(),
            conversation_id: conversation.into(),
            author: Some(author),
            device_sequence: wire_sequence,
            hlc,
            ..Default::default()
        })
    }

    pub(crate) fn merge_generated_clock(&self, remote: u64, now_ms: u64) -> Result<(), SdkError> {
        if remote >> 16 > now_ms.saturating_add(HLC_MAX_SKEW_MS) {
            return Ok(());
        }
        let db = self.account_db()?;
        let key = self.generated_hlc_key()?;
        let stored = db.load_actor_state::<u64>(&key)?.unwrap_or(0);
        let physical = now_ms.max(stored >> 16).max(remote >> 16);
        let logical = match (physical == stored >> 16, physical == remote >> 16) {
            (true, true) => (stored & 0xffff).max(remote & 0xffff) + 1,
            (true, false) => (stored & 0xffff) + 1,
            (false, true) => (remote & 0xffff) + 1,
            (false, false) => 0,
        };
        db.admit_actor_counter_floor(
            &key,
            tick(physical, logical)?,
            ramflux_storage::FloorPolicy::Refuse,
        )?;
        Ok(())
    }
}

pub(crate) fn order_hlc(signed: u64, receive_ms: u64) -> u64 {
    signed.min((receive_ms.saturating_add(HLC_MAX_SKEW_MS).min(MAX_PHYSICAL_MS) << 16) | 0xffff)
}

pub(crate) fn now_ms() -> u64 {
    #[cfg(test)]
    if let Some(seconds) = crate::time::test_clock::frozen() {
        return u64::try_from(seconds).unwrap_or(0).saturating_mul(1000);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::own_device_sync::tests::client_with_account;

    #[test]
    fn device_sequence_is_durable_per_conversation_and_private_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, mut client) =
            client_with_account("generated-counter", "principal_sync", "local")?;
        let first = client
            .account_db()?
            .write_transaction(|| client.allocate_generated_identity("c", 1000, false))?;
        assert_eq!(first.device_sequence, 1);
        let private = client
            .account_db()?
            .write_transaction(|| client.allocate_generated_identity("c", 1000, true))?;
        assert_eq!(private.device_sequence, (1 << 63) | 1);
        let rolled_back: Result<(), SdkError> = client.account_db()?.write_transaction(|| {
            client.allocate_generated_identity("c", 1000, false)?;
            Err(SdkError::LocalBus("cancel before outbox commit".into()))
        });
        assert!(rolled_back.is_err());
        client.active_account_db = None;
        client.unlock_account("acct", b"own-device-sync-test")?;
        let second = client
            .account_db()?
            .write_transaction(|| client.allocate_generated_identity("c", 1000, false))?;
        assert_eq!(second.device_sequence, 2);
        assert_ne!(first.id, second.id);
        assert_eq!(
            client
                .account_db()?
                .write_transaction(|| client.allocate_generated_identity("other", 1000, false))?
                .device_sequence,
            1
        );
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn hlc_orders_across_authors_and_clamps_future_values() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, client) = client_with_account("generated-clock", "principal_sync", "local")?;
        let first = client
            .account_db()?
            .write_transaction(|| client.allocate_generated_identity("c", 1000, false))?;
        let future = 1_000_000_u64 << 16;
        client.account_db()?.write_transaction(|| client.merge_generated_clock(future, 1000))?;
        let next = client
            .account_db()?
            .write_transaction(|| client.allocate_generated_identity("c", 1000, false))?;
        assert_eq!(next.hlc, first.hlc + 1);
        assert_eq!(order_hlc(future, 1000), ((1000 + HLC_MAX_SKEW_MS) << 16) | 0xffff);
        let remote = (2000 << 16) | 7;
        client.account_db()?.write_transaction(|| client.merge_generated_clock(remote, 1000))?;
        let next = client
            .account_db()?
            .write_transaction(|| client.allocate_generated_identity("c", 1000, false))?;
        assert_eq!(next.hlc, remote + 2);
        assert!(tick(MAX_PHYSICAL_MS, 0x1_0000).is_err());
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

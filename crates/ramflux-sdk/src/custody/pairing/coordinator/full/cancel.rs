// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immediate root-owner fence, independent of the async actor mutex.
use crate::SdkError;
use ramflux_storage::FullStageIoCancel;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub(crate) struct FullRuntimeCancel {
    stopped: AtomicBool,
    stage: Mutex<Option<FullStageIoCancel>>,
}
impl FullRuntimeCancel {
    pub(crate) fn require_live(&self) -> Result<(), SdkError> {
        if self.stopped.load(Ordering::Acquire) {
            Err(SdkError::PairingCode("Retired"))
        } else {
            Ok(())
        }
    }
    pub(crate) fn register_stage(&self, stage: FullStageIoCancel) -> Result<(), SdkError> {
        let mut slot = self.stage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = self.require_live() {
            stage.cancel();
            return Err(error);
        }
        if let Some(old) = slot.replace(stage) {
            old.cancel();
        }
        Ok(())
    }
    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(stage) =
            self.stage.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
        {
            stage.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::SdkError;
    use crate::custody::pairing::{
        PairingActor, PairingConfig, PairingIdentity, install_actor, remove_actor,
    };
    use ramflux_node_core::pairing_relay::{
        PairingRelayConfig, PairingRelayStore, TestPairingClock,
    };
    use ramflux_protocol::custody::DeviceRef;
    use ramflux_protocol::custody::pairing::{
        context_v3::{DataSelectionV3, FullAccountData, TransferProfile},
        local_dto::FullTransferBegin,
    };
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn pairing_full_remove_actor_fences_new_work_without_waiting_for_actor_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let now = crate::custody::network_now()?;
        let store = Arc::new(Mutex::new(PairingRelayStore::new(PairingRelayConfig {
            clock: TestPairingClock::new(now),
            node_seed: [7; 32],
            public_origin: "https://relay.example:443".into(),
        })?));
        let actor = PairingActor::new(
            PairingIdentity {
                account_id: "primary".into(),
                local_ref: DeviceRef {
                    account_anchor: ramflux_protocol::encode_base64url([1; 32]),
                    device_id: "primary".into(),
                    device_epoch: 1,
                },
                master_public_key: None,
                base_record_hash: ramflux_protocol::encode_base64url([2; 32]),
                base_epoch: 1,
                is_primary: true,
            },
            None,
            Arc::new(crate::custody::pairing::tests::MemoryRelay { store }),
            PairingConfig { enabled: true, extra_root_ca_pem: None },
        );
        install_actor(root.path(), "primary".into(), actor)?;
        let entry = super::super::super::registry::find(root.path(), "primary")?;
        let mut actor = entry.actor.lock().await;
        // Removal must fence an already-held callback, without waiting for this actor loan.
        remove_actor(root.path(), "primary")?;
        let refused = actor
            .begin_full(FullTransferBegin {
                schema: "ramflux.pairing.TransferBegin.v3".into(),
                version: 3,
                recipient_mode: "new".into(),
                destination_ref: None,
                capabilities: vec!["message".into()],
                lease_not_before: now,
                lease_expires_at: now + 604_800,
                data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
                transfer_profile: TransferProfile::FullAccountDataV1,
                display_name: "Source".into(),
            })
            .await;
        assert!(
            matches!(refused, Err(SdkError::PairingCode("Retired"))),
            "an already-loaned actor passed the removed-owner fence"
        );
        assert!(matches!(entry.require_live(), Err(SdkError::PairingCode("Retired"))));
        Ok(())
    }
}

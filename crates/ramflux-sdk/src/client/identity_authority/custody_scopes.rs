// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary feature permissions recheck each native branch's certified operation scope.
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;
#[derive(Clone, Copy)]
pub(crate) enum NativeOperation {
    Call,
    Group,
    Sync,
}
impl NativeOperation {
    const fn scope(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Group => "group",
            Self::Sync => "sync",
        }
    }
}
impl RamfluxClient {
    pub(crate) fn require_native_sync(
        &self,
        root: &str,
        sender: &str,
        receiver: &str,
    ) -> Result<(), SdkError> {
        for device in [sender, receiver] {
            self.require_native_operation(
                &self.device_identity_for_root(root, device)?,
                NativeOperation::Sync,
            )?;
        }
        Ok(())
    }
    pub(crate) fn require_native_operation(
        &self,
        device: &RootQualifiedDeviceRef,
        operation: NativeOperation,
    ) -> Result<(), SdkError> {
        let now = crate::custody::network_now()?;
        let Some(current) = self.current_custody_authority(device.root_commitment(), now)? else {
            if self.custody_mode_observed(device.root_commitment())? {
                return Err(SdkError::InboundPending(
                    "native operation authority unavailable".into(),
                ));
            }
            return Ok(());
        };
        self.require_cached_root_authority(device)?;
        let entry = current
            .envelope()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == device.device_id())
            .ok_or_else(|| super::invalid("native operation device absent"))?;
        current.authorize(
            &ramflux_protocol::custody::DeviceRef {
                account_anchor: device.root_commitment().into(),
                device_id: device.device_id().into(),
                device_epoch: entry.device_epoch,
            },
            operation.scope(),
            now,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};
    #[tokio::test]
    async fn native_feature_scopes_cannot_be_replaced_by_message_permission() -> TestResult {
        let fixture = Fixture::new("native-feature-scopes").await?;
        let identity = fixture.client.owned_device_identity()?;
        let mut manifest = fixture.manifest.clone();
        let primary = fixture.vault.primary_for_public_key(
            &manifest
                .custody
                .as_ref()
                .ok_or("native")?
                .publication
                .record
                .body
                .master_certificate
                .body
                .self_signing_public_key,
        )?;
        for operation in [NativeOperation::Call, NativeOperation::Group, NativeOperation::Sync] {
            fixture.client.require_native_operation(&identity, operation)?;
            let native = manifest.custody.as_mut().ok_or("native")?;
            let mut body = native.publication.record.body.clone();
            body.previous_record_hash =
                Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
            body.device_set_epoch += 1;
            let mut certificate =
                body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body.clone();
            certificate.capabilities.retain(|scope| scope != operation.scope());
            certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
            body.devices[0].branch_certificate = Some(primary.certify_branch(certificate)?);
            native.publication.record = primary.sign_record(body)?;
            manifest = crate::prekey::SdkDeviceManifestResponse::from_native((**native).clone())?;
            fixture.client.persist_fetched_identity_directory(&manifest)?;
            fixture.client.require_current_device_authorization(&identity)?;
            assert!(fixture.client.require_native_operation(&identity, operation).is_err());
            match operation {
                NativeOperation::Call => assert!(fixture.client.call_local_endpoint().is_err()),
                NativeOperation::Group => {
                    assert!(
                        fixture
                            .client
                            .create_group("denied-group", identity.storage_key())
                            .is_err()
                    );
                    assert!(fixture.client.group_state("denied-group").is_err());
                }
                NativeOperation::Sync => {}
            }
        }
        Ok(())
    }
}

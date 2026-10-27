// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public owned-account provenance, independent of access to a primary signing secret.
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;

impl RamfluxClient {
    pub(crate) fn own_account_anchor(&self) -> Result<String, SdkError> {
        if let Some(account) = &self.born_v3_account {
            return Ok(account.record().body.account_anchor.clone());
        }
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key()))
    }

    pub(crate) fn own_master_public_key(&self) -> Result<String, SdkError> {
        if let Some(account) = &self.born_v3_account {
            return Ok(account.record().body.master_certificate.body.master_public_key.clone());
        }
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes()))
    }

    pub(crate) fn own_custody_device(
        &self,
        device: &str,
    ) -> Result<Option<RootQualifiedDeviceRef>, SdkError> {
        self.born_v3_account
            .as_ref()
            .map(|account| {
                RootQualifiedDeviceRef::from_custody_record(account.verified(), device)
                    .map_err(SdkError::from)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::tests::{Root, TestVault, create};

    #[test]
    fn custody_provenance_needs_no_master_signer_and_rejects_unknown_devices()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new()?;
        let account = create(&root.0, "ordinary", &TestVault::default(), 100)?;
        let expected_anchor = account.record().body.account_anchor.clone();
        let expected_master =
            account.record().body.master_certificate.body.master_public_key.clone();
        let mut client = RamfluxClient::new();
        client.load_born_v3_account(&root.0, "ordinary", 100)?;
        assert!(client.identity_root.is_none());
        assert_eq!(client.own_account_anchor()?, expected_anchor);
        assert_eq!(client.own_master_public_key()?, expected_master);
        assert_eq!(client.contact_own_commitment()?, expected_anchor);
        assert_eq!(client.surface_local_root_commitment()?, expected_anchor);
        let device = client.own_custody_device("primary")?.ok_or("missing device")?;
        assert_eq!(device.root_commitment(), expected_anchor);
        assert!(client.own_custody_device("unknown").is_err());
        assert!(client.owned_account_device_identity("other~primary").is_err());
        Ok(())
    }
    #[test]
    fn native_data_unlock_survives_restart_without_primary_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new()?;
        let now = crate::custody::network_now()?;
        let account = {
            let vault = TestVault::default();
            create(&root.0, "data-only", &vault, now)?
        };
        let anchor = account.record().body.account_anchor.clone();
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        assert!(client.unlock_account("data-only", b"not-yet-sealed").is_err());
        client.seal_born_account_data("data-only", b"correct-passphrase")?;
        client.unlock_account("data-only", b"correct-passphrase")?;
        assert!(client.identity_root.is_none());
        assert!(client.device_branch.is_none());
        assert_eq!(client.own_account_anchor()?, anchor);
        client.append_event("retained", "test.data", b"retained data")?;
        drop(client);
        let mut reopened = RamfluxClient::new();
        reopened.open_account_index(&root.0)?;
        assert!(reopened.unlock_account("data-only", b"wrong-passphrase").is_err());
        reopened.unlock_account("data-only", b"correct-passphrase")?;
        assert_eq!(reopened.own_account_anchor()?, anchor);
        assert_eq!(reopened.event_body("retained")?, Some(b"retained data".to_vec()));
        assert!(reopened.identity_root.is_none());
        assert!(reopened.device_branch.is_none());
        Ok(())
    }
}

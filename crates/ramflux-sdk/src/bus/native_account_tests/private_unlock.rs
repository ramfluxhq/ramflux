// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual local socket -> binary input -> ordinary account actor across lock/restart.
#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::custody::pairing::{
        CredentialOutcome, LocalCredentialProvider, SecretUtf8,
        private_credential::PairingBusClient,
    };
    use ramflux_protocol::custody::pairing::local_dto::CredentialRequest;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Input {
        calls: AtomicUsize,
        refuse: bool,
    }
    impl LocalCredentialProvider for Input {
        fn provide(
            &self,
            request: &CredentialRequest,
        ) -> std::result::Result<CredentialOutcome, crate::SdkError> {
            assert_eq!(
                request.local_account_id, "private-native",
                "test: private native unlock credential refusal or account lifecycle changed"
            );
            assert_eq!(request.action, "unlock", "ordinary unlock requested the recovery phrase");
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.refuse {
                return Ok(CredentialOutcome::Refused);
            }
            Ok(CredentialOutcome::Provided {
                passphrase: SecretUtf8::from_bytes(b"native-private-data-canary")?,
                confirmation: None,
            })
        }
    }
    #[tokio::test]
    async fn pairing_private_bus_unlock_uses_native_actor_after_restart() -> Result {
        crate::bus::credentials::contract_tests::deadline(async {
        let root = tempfile::tempdir()?;
        let now = crate::custody::network_now()?;
        let mut ceremony = CreationCeremony::begin(root.path(), input("private-native"), now)?;
        let phrase = ceremony.show_once()?;
        let positions = ceremony.hidden_challenge()?;
        let born = ceremony.confirm_with_passphrase(
            &words(&phrase, positions)?,
            &TestVault::default(),
            now,
            b"native-private-data-canary",
        )?;
        let anchor = born.record().body.account_anchor.clone();
        drop((born, phrase));
        let socket = root.path().join("private.sock");
        for _ in 0..2 {
            let (stop, receiver) = watch::channel(false);
            let flow = async {
                let _stop = Stop(stop);
                let mut ordinary = connect(&socket).await?;
                let refusal = Arc::new(Input { calls: AtomicUsize::new(0), refuse: true });
                let mut rejected = PairingBusClient::connect(&socket, refusal.clone()).await?;
                assert!(
                    rejected
                        .request(
                            Some("private-native".into()),
                            "account",
                            "account.unlock",
                            json!({})
                        )
                        .await
                        .is_err(), "test: private native unlock credential refusal or account lifecycle changed"
                );
                assert_eq!(refusal.calls.load(Ordering::Relaxed), 1, "test: private native unlock credential refusal or account lifecycle changed");
                let listed = ordinary.request(None, "account", "account.list", json!({})).await?;
                assert_eq!(listed["account_details"][0]["state"], "locked", "test: private native unlock credential refusal or account lifecycle changed");
                let input = Arc::new(Input { calls: AtomicUsize::new(0), refuse: false });
                let mut private = PairingBusClient::connect(&socket, input.clone()).await?;
                let result = private
                    .request(Some("private-native".into()), "account", "account.unlock", json!({}))
                    .await?;
                assert_eq!(result["state"], "unlocked", "test: private native unlock credential refusal or account lifecycle changed");
                assert_eq!(input.calls.load(Ordering::Relaxed), 1, "test: private native unlock credential refusal or account lifecycle changed");
                let status = ordinary
                    .request(Some("private-native".into()), "account", "account.status", json!({}))
                    .await?;
                assert_eq!(status["principal_commitment"], anchor, "test: private native unlock credential refusal or account lifecycle changed");
                assert_eq!(status["state"], "unlocked", "test: private native unlock credential refusal or account lifecycle changed");
                ordinary
                    .request(Some("private-native".into()), "account", "account.lock", json!({}))
                    .await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (server, result) = tokio::join!(
                crate::serve_local_bus_until(LocalBusConfig::new(&socket, root.path()), receiver),
                flow
            );
            server?;
            result?;
        }
        assert!(!root.path().join("local_bus_accounts/private-native.json").exists(), "test: private native unlock credential refusal or account lifecycle changed");
        Ok(())
    })
    .await
    }
}

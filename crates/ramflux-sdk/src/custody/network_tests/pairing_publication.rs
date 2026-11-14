// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real TLS successor publication binds proof to the exact candidate, using original branch possession.
#[cfg(test)]
mod tests {
    use super::super::*;
    struct Server(Option<tokio::task::JoinHandle<Result>>);
    impl Drop for Server {
        fn drop(&mut self) {
            if let Some(server) = self.0.take() {
                server.abort();
            }
        }
    }
    #[tokio::test]
    async fn pairing_native_publication_proof_uses_exact_candidate_record_over_tls()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await
    }
    async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = ramflux_test_support::TestPath::new()?;
        let root = Root(temporary.child("node"));
        std::fs::create_dir(&root.0)?;
        let (address, ca, server) = start_server_with_connections(&root, false, 1)
            .await
            .map_err(|error| error.to_string())?;
        let mut server = Server(Some(server));
        let account_root = temporary.child("source");
        std::fs::create_dir(&account_root)?;
        let vault = Arc::new(crate::custody::tests::TestVault::default());
        let account = crate::custody::tests::create(
            &account_root,
            "source",
            vault.as_ref(),
            super::super::super::network::now()?,
        )?;
        let mut client = crate::RamfluxClient::new();
        client.open_account_index(&account_root)?;
        client.seal_new_account_data(
            "source",
            &account.record().body.account_anchor,
            b"native-publication-password",
        )?;
        client.unlock_account("source", b"native-publication-password")?;
        let config = CustodyNetworkConfig {
            pairing_admission: None,
            account_root,
            account_id: "source".into(),
            device_id: "primary".into(),
            gateway_address: address,
            server_name: "localhost".into(),
            ca_certificate: ca,
            node_id: "node".into(),
            node_public_key: ramflux_crypto::fixture_public_key_base64url(),
            audience: "node".into(),
            binding_mode: BindingMode::DirectExporter,
            allow_no_channel_binding: false,
            timeout: Duration::from_secs(5),
        };
        let mut connection = CustodyConnection::connect_for_proof(config, vault.clone()).await?;
        let old = connection.account().record().clone();
        let mut body = old.body.clone();
        let (range, revision) = decode_epoch(body.device_set_epoch)?;
        body.device_set_epoch = encode_epoch(range, revision + 1)?;
        body.previous_record_hash = Some(object_hash(&old)?);
        body.profile.display_name = "Published through real TLS".into();
        let key = account.group_primary(vault.as_ref())?;
        let candidate = Publication { record: key.sign_record(body)?, compacted_ids: None };
        drop(key);
        assert_ne!(
            object_hash(&candidate.record)?,
            object_hash(&old)?,
            "test: TLS publication did not exercise a successor record"
        );
        let result = connection
            .prove(CustodyProofAction::Publish { publication: Box::new(candidate.clone()) })
            .await?;
        let CustodyServerFrame::Published { record_hash } = result else {
            return Err(
                format!("test: actual TLS candidate publication refused: {result:?}").into()
            );
        };
        assert_eq!(
            record_hash,
            object_hash(&candidate.record)?,
            "test: actual native acknowledgement named another publication"
        );
        drop(connection);
        server
            .0
            .take()
            .ok_or("test: TLS server missing")?
            .await?
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

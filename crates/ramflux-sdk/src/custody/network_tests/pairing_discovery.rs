// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public receiving-node discovery uses real TLS and preserves independent pins.
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
    async fn pairing_public_node_discovery_uses_pinned_tls_without_account_or_session()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            let temporary = ramflux_test_support::TestPath::new()?;
            let root = Root(temporary.child("node"));
            std::fs::create_dir(&root.0)?;
            let (address, ca, server) =
                start_server(&root).await.map_err(|error| error.to_string())?;
            let mut server = Server(Some(server));
            let config = CustodyNetworkConfig {
                pairing_admission: None,
                account_root: root.0.to_path_buf(),
                account_id: "never-created".into(),
                device_id: "unreserved".into(),
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
            let first = CustodyConnection::discover_pairing_node(config.clone()).await?;
            let mut substituted = config.clone();
            substituted.node_public_key = ramflux_protocol::encode_base64url([99; 32]);
            assert!(
                CustodyConnection::discover_pairing_node(substituted).await.is_err(),
                "test: public node discovery trusted a TLS peer with a substituted native pin"
            );
            let next = CustodyConnection::discover_pairing_node(config).await?;
            assert_eq!(
                first.hash(),
                next.hash(),
                "test: rejected identity query rewrote durable node pins"
            );
            assert!(
                !root.0.join("custody_accounts").exists(),
                "test: public discovery created an account or vault owner"
            );
            server
                .0
                .take()
                .ok_or("test: missing TLS server")?
                .await?
                .map_err(|error| error.to_string())?;
            Ok(())
        }))
        .await
    }
}

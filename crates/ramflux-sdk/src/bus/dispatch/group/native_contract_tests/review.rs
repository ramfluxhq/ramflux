// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Request-scoped pending and unrelated-retry classification regressions.
use super::*;

async fn unrelated_case(direct: bool, peer_fresh: bool) -> TestResult {
    let (alice, bob, group_entry) = renamed_group_fixture().await?;
    let primary = alice
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native")?
        .group_primary(alice.vault.as_ref())?;
    alice.client.shared_group_create_with_primary(
        "unrelated",
        "unrelated-thread",
        None,
        &alice.config.target_delivery_id,
        Some(&primary),
    )?;
    alice.client.establish_friend_link(
        "contact",
        &alice.manifest.principal_commitment.clone(),
        &bob.manifest.principal_commitment,
    )?;
    let entry = if direct {
        routed_entry(&alice, &bob, "blocked-dm", 1, crate::client::routed::Route::direct())?
    } else {
        group_entry
    };
    let (address, directory) =
        crate::bus::dispatch::surface_transport::fixture::directory(&alice.root.0, BTreeMap::new())
            .await?;
    let mut config = alice.config;
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "test-gateway".into();
    config.ca_cert = alice.root.0.join("ca.pem");
    let mut account = LocalBusAccountState::disconnected(
        alice.client,
        config,
        alice.manifest.principal_commitment.clone(),
    );
    *account.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    if peer_fresh {
        account.client.persist_fetched_identity_directory(&bob.manifest)?;
    } else {
        account.client.persist_fetched_identity_directory(&alice.manifest)?;
    }
    let key = account.client.inbox_admission_key(&entry)?;
    install_gateway(&mut account, vec![entry]);
    let at = now_unix_timestamp() + 60;
    crate::bus::sync_driver::run_at(&mut account, at).await?;
    assert!(account.client.account_db()?.has_inbox_retry(&key)?);
    assert_eq!(
        crate::bus::couriers::head_refresh::inbound::blocked_roots(&account, "group")?.is_empty(),
        direct || !peer_fresh,
        "only a decoded group route can hold its own group RPC",
    );
    for method in ["group.read", "group.receive"] {
        let frame = LocalBusFrame::request(
            method,
            Some("owner".into()),
            "ramflux.sdk.v1",
            method,
            json!({"group_id":"unrelated", "conversation_id":"unrelated-thread", "limit":32}),
        );
        assert!(
            crate::bus::account_runtime::head_refresh::stale_roots(&account, &frame)?.is_empty(),
            "the command gate must not wait on another conversation"
        );
        let started = std::time::Instant::now();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            dispatch_group_receive_request(&frame, &mut account),
        )
        .await??;
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(response.response_body["decrypted_messages"], json!([]));
        assert!(account.client.account_db()?.has_inbox_retry(&key)?);
        assert!(!account.client.account_db()?.inbox_retry_ready(&key, at + 1)?);
    }
    account.connection.take().ok_or("connection")?.stop().await;
    directory.abort();
    Ok(())
}

#[tokio::test]
async fn unavailable_contact_directory_does_not_block_unrelated_group_reads() -> TestResult {
    for direct in [true, false] {
        for peer_fresh in [false, true] {
            Box::pin(unrelated_case(direct, peer_fresh)).await?;
        }
    }
    Ok(())
}

pub(super) async fn assert_duplicate_after_refresh(
    account: &mut LocalBusAccountState,
    entry: GatewayInboxEntry,
    count: usize,
    at: i64,
    key: &str,
) -> TestResult {
    account.connection.take().ok_or("connection")?.stop().await;
    let mut duplicate = entry;
    duplicate.inbox_seq = count as u64 + 1;
    install_gateway(account, vec![duplicate]);
    crate::bus::sync_driver::run_at(account, at + 1).await?;
    assert_eq!(
        account.client.direct_messages("thread")?.len(),
        count,
        "duplicate gateway redelivery after refresh must not apply twice"
    );
    assert!(!account.client.account_db()?.has_inbox_retry(key)?);
    assert_eq!(account.pending_deliveries.len(), count);
    Ok(())
}

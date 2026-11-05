// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fenced refresh regressions over native authority and managed live sessions.
use super::*;
use crate::bus::connection_manager::tests::fixture;
use crate::client::identity_authority::HeadUse;
use crate::client::native_test_support::{Fixture, TestResult};
use std::time::Duration;

struct Authority {
    manifest: SdkDeviceManifestResponse,
    root: crate::custody::tests::Root,
}
async fn account()
-> TestResult<(LocalBusAccountState, Authority, crate::bus::connection_manager::tests::SessionIo)> {
    let native = Fixture::new("refresh-account").await?;
    *native.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    let mut account = LocalBusAccountState::disconnected(
        native.client,
        native.config,
        native.manifest.principal_commitment.clone(),
    );
    let (handle, io) = fixture().await?;
    account.connection = Some(handle);
    account.head_refresh.enqueue(account.principal_commitment.clone());
    Ok((account, Authority { manifest: native.manifest, root: native.root }, io))
}
fn fence(account: &LocalBusAccountState) -> TestResult<Fence> {
    let connection = account.connection.as_ref().ok_or("connection")?;
    let snapshot = connection.snapshot();
    Ok(Fence { generation: snapshot.generation, session_id: snapshot.session_id.ok_or("session")? })
}
fn fresh(account: &LocalBusAccountState, native: &Authority) -> TestResult<bool> {
    Ok(account
        .client
        .require_fresh_custody_head(
            HeadUse::NewAuthorization,
            &native.manifest.principal_commitment,
            &native.manifest.custody.as_ref().ok_or("custody")?.publication.record,
        )
        .is_ok())
}

#[tokio::test]
async fn refresh_does_not_extend_freshness_with_stale_fetch_time() -> TestResult {
    let (mut account, native, _io) = account().await?;
    let requested = fence(&account)?;
    let plan = prepare(&mut account, requested)?.ok_or("plan")?;
    let root = &native.manifest.principal_commitment;
    let old = Instant::now().checked_sub(Duration::from_secs(301)).ok_or("clock")?;
    assert!(!apply(&mut account, &plan, root, old, Ok(native.manifest.clone()))?);
    assert!(!fresh(&account, &native)?, "old fetched_after must not renew authority");
    assert!(account.head_refresh.pending.contains(root));
    assert!(apply(&mut account, &plan, root, Instant::now(), Ok(native.manifest.clone()))?);
    assert!(fresh(&account, &native)?);
    assert!(!account.head_refresh.pending.contains(root));
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}

#[tokio::test]
async fn old_generation_result_is_not_applied() -> TestResult {
    let (mut account, native, _old_io) = account().await?;
    let requested = fence(&account)?;
    let plan = prepare(&mut account, requested)?.ok_or("plan")?;
    let (replacement, _new_io) = fixture().await?;
    let old = account.connection.replace(replacement).ok_or("old connection")?;
    // Account and membership remain present; only the live generation changes.
    assert_ne!(fence(&account)?.generation, plan.fence.generation);
    assert_eq!(
        fence(&account)?.session_id,
        plan.fence.session_id,
        "same scripted session ID isolates generation fence"
    );
    assert!(!apply(
        &mut account,
        &plan,
        &native.manifest.principal_commitment,
        Instant::now(),
        Ok(native.manifest.clone())
    )?);
    assert!(!fresh(&account, &native)?, "old generation must not update the account");
    assert!(account.head_refresh.pending.contains(&native.manifest.principal_commitment));
    old.stop().await;
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}

#[tokio::test]
async fn refresh_stops_on_lock() -> TestResult {
    let (mut account, native, _io) = account().await?;
    let handle = account.connection.as_ref().ok_or("connection")?.clone();
    // A TCP peer accepts the fetch but holds its TLS handshake indefinitely.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let certified = rcgen::generate_simple_self_signed(vec!["refresh.test".into()])?;
    let ca = native.root.0.join("refresh-ca.pem");
    std::fs::write(&ca, certified.cert.pem())?;
    account.gateway_config = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: listener.local_addr()?,
        server_name: "refresh.test".into(),
        ca_cert: ca,
        principal_id: "refresh".into(),
        device_id: "primary".into(),
        target_delivery_id: "refresh".into(),
        prekey_http_url: None,
    });
    let context = handle.test_context();
    let (writer, mut work) = mpsc::channel(2);
    let task = tokio::spawn(pass(context, writer));
    let AccountWork::Directory(message) = work.recv().await.ok_or("prepare work")? else {
        return Err("wrong work".into());
    };
    let super::super::directory::DirectoryWork::HeadRefresh(message) = *message else {
        return Err("wrong directory work".into());
    };
    apply_work(&mut account, message);
    let (_socket, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await??;
    assert!(account.head_refresh.active.upgrade().is_some(), "fetch is in flight");
    handle.request_stop(crate::bus::connection_manager::DisconnectReason::Lock);
    tokio::time::timeout(Duration::from_secs(1), task).await???;
    assert!(!fresh(&account, &native)?);
    assert!(account.head_refresh.active.upgrade().is_none());
    assert!(work.try_recv().is_err(), "cancelled pass must send no apply");
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}

#[tokio::test]
async fn refresh_rejects_wrong_root_removed_membership_and_failed_fetch() -> TestResult {
    let (mut account, native, _io) = account().await?;
    let peer = Fixture::new("refresh-peer").await?;
    let root = &peer.manifest.principal_commitment;
    account.client.establish_friend_link("refresh-link", &account.principal_commitment, root)?;
    assert!(account.head_refresh.enqueue(root.clone()));
    let requested = fence(&account)?;
    let plan = prepare(&mut account, requested.clone())?.ok_or("plan")?;
    assert!(prepare(&mut account, requested)?.is_none(), "one pass per account");
    let mut wrong = peer.manifest.clone();
    wrong.principal_commitment = "wrong-root".into();
    assert!(apply(&mut account, &plan, root, Instant::now(), Ok(wrong)).is_err());
    assert!(
        apply(
            &mut account,
            &plan,
            root,
            Instant::now(),
            Err(SdkError::InboundPending("404".into()))
        )
        .is_err()
    );
    assert!(!fresh(&account, &native)?);
    account.client.remove_friend_link("refresh-link", "me")?;
    assert!(!eligible_roots(&account)?.contains(root));
    assert!(!apply(&mut account, &plan, root, Instant::now(), Ok(peer.manifest.clone()))?);
    assert!(
        account
            .client
            .account_db()?
            .load_actor_state::<SdkDeviceManifestResponse>(&format!(
                "identity/manifest-root/{root}"
            ))?
            .is_none()
    );
    drop(plan);
    assert!(account.head_refresh.active.upgrade().is_none());
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}

#[test]
fn pending_refresh_is_bounded_and_deduplicated() {
    let mut state = RefreshState::default();
    for index in 0..MAX_PENDING {
        assert!(state.enqueue(format!("root-{index}")));
    }
    assert!(state.enqueue("root-0".into()));
    assert!(!state.enqueue("overflow".into()));
    assert_eq!(state.pending.len(), MAX_PENDING);
}

#[tokio::test]
async fn eligibility_storage_reads_are_independent_of_pending_root_count() -> TestResult {
    let native = Fixture::new("eligibility-reads").await?;
    let primary = native
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native")?
        .group_primary(native.vault.as_ref())?;
    for index in 0..4 {
        native.client.shared_group_create_with_primary(
            &format!("group-{index}"),
            &format!("thread-{index}"),
            None,
            &native.config.target_delivery_id,
            Some(&primary),
        )?;
    }
    for index in 0..32 {
        native.client.establish_friend_link(
            &format!("link-{index}"),
            &native.manifest.principal_commitment,
            &format!("peer-{index}"),
        )?;
    }
    let mut account = LocalBusAccountState::disconnected(
        native.client,
        native.config,
        native.manifest.principal_commitment,
    );
    let (handle, _io) = fixture().await?;
    account.connection = Some(handle);
    let requested = fence(&account)?;
    let own = account.principal_commitment.clone();
    account.head_refresh.enqueue(own.clone());
    let probe = account.client.account_db()?.observe_sql_work();
    let plan = prepare(&mut account, requested.clone())?.ok_or("small plan")?;
    let small = probe.snapshot().read_statements;
    assert!(small > 0, "counter must observe real roster reads");
    assert!(small <= 2 + 5 * 4, "one contact load and linear group reads: {small}");
    drop(plan);
    for index in 0..MAX_PENDING - 1 {
        assert!(account.head_refresh.enqueue(format!("absent-{index:04}")));
    }
    assert_eq!(account.head_refresh.pending.len(), MAX_PENDING);
    let before = probe.snapshot().read_statements;
    let plan = prepare(&mut account, requested)?.ok_or("large plan")?;
    let large = probe.snapshot().read_statements - before;
    assert_eq!(large, small, "pending roots must not multiply storage reads");
    assert_eq!(plan.roots, vec![own.clone()]);
    assert_eq!(account.head_refresh.pending.len(), 1, "ineligible roots removed");
    let before = probe.snapshot().read_statements;
    assert!(
        apply(
            &mut account,
            &plan,
            &own,
            Instant::now(),
            Err(SdkError::InboundPending("404".into()))
        )
        .is_err()
    );
    assert_eq!(
        probe.snapshot().read_statements - before,
        small,
        "Apply must rebuild one current eligibility set per writer turn"
    );
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}

#[tokio::test]
async fn verified_legacy_authority_does_not_remain_pending() -> TestResult {
    let (mut account, _native, _io) = account().await?;
    let manifest = crate::client::identity_authority::test_support::remote_manifest(
        "legacy", "device", [99; 32],
    )?;
    let root = manifest.principal_commitment.clone();
    assert!(manifest.custody.is_none());
    account.client.establish_friend_link("legacy-link", &account.principal_commitment, &root)?;
    account.head_refresh.enqueue(root.clone());
    let requested = fence(&account)?;
    let plan = prepare(&mut account, requested)?.ok_or("plan")?;
    assert!(apply(&mut account, &plan, &root, Instant::now(), Ok(manifest))?);
    assert!(!account.head_refresh.pending.contains(&root));
    assert!(account.head_refresh.pending.contains(&account.principal_commitment));
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}

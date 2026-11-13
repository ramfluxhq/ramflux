// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cleanup must inspect data only after recovering an interrupted registration.
use super::*;
use crate::send_authority::{
    AuthorityPhase, AuthorityRecord, AuthorityScope, LocalAuthorityResource, LocalAuthorityRow,
    SendAuthorityError,
};
use crate::test_support::notification_authority::NativeScenario;
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
#[derive(Clone, Copy)]
enum Cleanup {
    Ownerless,
    Orphan,
    Expired,
}

fn interrupt_registration(store: &NotifyRedbStore, target: &str, cleanup: Cleanup) -> TestResult {
    let tx = store.db.begin_write()?;
    let mut rows = Vec::new();
    for (key, definition) in
        [("routes", NOTIFY_ROUTE_TABLE), ("owner", OWNERS), ("marks", HIGH_WATER)]
    {
        let table = tx.open_table(definition)?;
        let value =
            table.get(target)?.map(|value| ramflux_protocol::encode_base64url(value.value()));
        rows.push(LocalAuthorityRow { key: key.into(), value });
    }
    let fence = tx.open_table(FENCES)?.get(target)?.map(|value| value.value());
    rows.push(LocalAuthorityRow {
        key: "fence".into(),
        value: fence
            .map(|value| {
                ramflux_protocol::canonical_json_bytes(&value)
                    .map(ramflux_protocol::encode_base64url)
            })
            .transpose()?,
    });
    rows.sort_by(|left, right| left.key.cmp(&right.key));
    match cleanup {
        Cleanup::Ownerless => {
            tx.open_table(OWNERS)?.remove(target)?;
        }
        Cleanup::Orphan => {
            tx.open_table(NOTIFY_ROUTE_TABLE)?.remove(target)?;
        }
        Cleanup::Expired => {
            let mut table = tx.open_table(NOTIFY_ROUTE_TABLE)?;
            let bytes = table.get(target)?.ok_or("test: original route")?.value().to_vec();
            let mut values = routes::open(&store.route_key, target, &bytes)?;
            for value in &mut values {
                value.expires_at = 1;
            }
            table.insert(target, routes::seal(&store.route_key, target, &values)?.as_slice())?;
        }
    }
    tx.commit()?;
    let scope = AuthorityScope::TargetRoutes { target_delivery_id: target.into() };
    let record = AuthorityRecord::LocalRows {
        version: 1,
        resource: LocalAuthorityResource::TargetRoutes,
        scope_key: target.into(),
        rows,
    };
    let result: Result<(), NodeCoreError> =
        store.send_authority.local_change(&scope, &record, |_| {
            Err(SendAuthorityError::Storage("test: interrupted registration".into()).into())
        });
    assert!(
        matches!(&result, Err(NodeCoreError::SendAuthority(SendAuthorityError::Storage(message))) if message == "test: interrupted registration"),
        "fixture failed to interrupt the real local mutation after its durable fence: {result:?}"
    );
    assert_eq!(
        store.send_authority.state(&scope)?.phase,
        AuthorityPhase::Closing,
        "fixture did not leave an actual recoverable registration"
    );
    Ok(())
}

#[test]
fn cleanup_resumes_registration_before_testing_owner_route_or_expiry() -> TestResult {
    for cleanup in [Cleanup::Ownerless, Cleanup::Orphan, Cleanup::Expired] {
        let temp = tempfile::TempDir::new()?;
        let scenario = NativeScenario::new(temp.path())?;
        let (_, target, prepared) = scenario.prepared()?;
        interrupt_registration(&scenario.notify, &target.target, cleanup)?;
        match cleanup {
            Cleanup::Ownerless => scenario.notify.reject_ownerless_routes()?,
            Cleanup::Orphan => scenario.notify.prune_route_owners()?,
            Cleanup::Expired => assert_eq!(
                scenario.notify.prune_expired_routes(crate::now_unix_seconds())?,
                0,
                "expiry cleanup discarded the recovered renewed route"
            ),
        }
        assert_eq!(
            scenario.notify.load_notify_routes(&target.target)?,
            vec![prepared.route.clone()],
            "cleanup changed the registration restored by the actual recovery transaction"
        );
        let mut issued = false;
        scenario.notify.issue_provider_push(&prepared, || {
            issued = true;
            Ok(())
        })?;
        assert!(issued, "cleanup removed recovered owner authority before native provider handoff");
    }
    Ok(())
}

#[test]
fn expiry_cleanup_pages_past_unexpired_routes_with_a_bounded_scan() -> TestResult {
    const PAGE: usize = 128;
    let temp = tempfile::TempDir::new()?;
    let store = NotifyRedbStore::open(temp.path().join("notify.redb"))?;
    let identity = crate::test_support::notification_authority::NOTIFY.to_owned();
    store.send_authority.configure_local_writer(identity.clone())?;
    store.send_authority.configure_origins(1, &[identity])?;
    let now = crate::now_unix_seconds();
    let tx = store.db.begin_write()?;
    {
        let mut table = tx.open_table(NOTIFY_ROUTE_TABLE)?;
        for index in 0..=PAGE {
            let target = format!("page-{index:03}");
            let route = DevicePushRoute {
                device_delivery_id: target.clone(),
                provider: PushProviderKind::Apns,
                credential_id: None,
                token: "fixture-token".into(),
                endpoint: "https://localhost:1/push".into(),
                webpush_p256dh: None,
                webpush_auth: None,
                registered_at: 1,
                expires_at: if index == PAGE { 1 } else { now + 3600 },
                route_generation: 1,
            };
            table.insert(
                target.as_str(),
                routes::seal(&store.route_key, &target, &[route])?.as_slice(),
            )?;
        }
    }
    tx.commit()?;
    assert_eq!(
        store.prune_expired_routes(now)?,
        0,
        "expiry cleanup exceeded its first 128-key page"
    );
    assert_eq!(
        store.prune_expired_routes(now)?,
        1,
        "unexpired first-page routes starved the next expired key"
    );
    assert!(
        store.load_notify_routes("page-128")?.is_empty(),
        "expired second-page data survived cleanup"
    );
    assert_eq!(
        store.load_notify_routes("page-000")?.len(),
        1,
        "bounded cleanup removed an unexpired route"
    );
    Ok(())
}

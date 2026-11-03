// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Migration possession keeps the direct listener's authenticated capacity fence.
use super::*;

#[test]
fn migration_direct_grant_respects_listener_capacity_revocation_and_one_use_scope() -> Result {
    let path = temp_store_path("migration-direct-admission")?;
    let store = RouterRedbStore::open_with_wal(&path, path.with_extension("wal"))?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let (driver, _) = super::super::registered_direct_driver(&router, &store)?;
    let service = service(&driver, &store)?;
    let control = request(&driver, false)?;
    let action = CustodyProofAction::HomeMigration {
        purpose: MigrationPurpose::Read,
        control_hash: ramflux_protocol::home_migration::message_hash(&control.control)?,
        publication: Box::new(Publication {
            record: driver.publication.record.clone(),
            compacted_ids: None,
        }),
    };
    let pool =
        crate::CustodyIngressLimiter::with_pools(1, 1, 4, std::time::Duration::from_secs(300));
    let wall =
        pool.acquire("192.0.2.1".parse()?, None, std::time::Instant::now()).ok_or("wall permit")?;
    assert!(wall.mark_authenticated("wall"));
    let permit = pool
        .acquire("198.51.100.1".parse()?, None, std::time::Instant::now())
        .ok_or("migration permit")?;
    let context = crate::CustodyTlsContext {
        connection_id: &driver.connection,
        remote_ip: "198.51.100.1",
        mode: BindingMode::DirectExporter,
        exporter: Some([5; 32]),
    };
    let prove = || -> Result<CustodyClientFrame> {
        let response = service.tls(
            &router,
            &store,
            CustodyClientFrame::Challenge {
                device_ref: driver.reference.clone(),
                action: action.clone(),
            },
            context,
            NOW,
        );
        let CustodyServerFrame::Challenge { challenge } = response else {
            return Err(format!("migration challenge: {response:?}").into());
        };
        Ok(CustodyClientFrame::Prove {
            action: action.clone(),
            proof: Box::new(driver.proof(&challenge)?),
        })
    };
    assert_eq!(
        service.tls_with_permit(&router, &store, prove()?, context, (NOW, Some(&permit))),
        CustodyServerFrame::Refused { code: CustodyRefusal::Busy, capacity: None },
    );
    drop(wall);
    let response =
        service.tls_with_permit(&router, &store, prove()?, context, (NOW, Some(&permit)));
    let CustodyServerFrame::SessionEstablished { session } = response else {
        return Err(format!("migration grant after capacity release: {response:?}").into());
    };
    // The successful grant releases H, but still cannot open an ordinary inbox.
    let spare = pool
        .acquire("203.0.113.1".parse()?, None, std::time::Instant::now())
        .ok_or("migration grant did not release H")?;
    drop(spare);
    let send = |action: CustodySessionAction| -> Result<CustodyServerFrame> {
        let request = signed_request(
            &driver,
            &session,
            &action,
            &ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        )?;
        Ok(service.tls_with_permit(
            &router,
            &store,
            CustodyClientFrame::Request {
                session_id: session.session_id.clone(),
                request: Box::new(request),
                action,
            },
            context,
            (NOW, Some(&permit)),
        ))
    };
    assert_eq!(
        send(CustodySessionAction::Inbox { after_seq: 0, limit: 1 })?,
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused, capacity: None },
    );
    let status = CustodySessionAction::HomeMigration { request: Box::new(control) };
    assert_ne!(
        send(status.clone())?,
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused, capacity: None }
    );
    assert_eq!(
        send(status)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::SessionRequired, capacity: None }
    );
    let queued = prove()?;
    permit.revoke();
    assert_eq!(
        service.tls_with_permit(&router, &store, queued, context, (NOW, Some(&permit))),
        CustodyServerFrame::Refused { code: CustodyRefusal::Busy, capacity: None },
    );
    Ok(())
}

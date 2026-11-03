// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise the actual final admission transaction after a daily budget becomes exhausted.
use super::*;
use crate::tests::custody_sessions::Driver;
use ramflux_protocol::custody::{CapacityHint, CapacityScope};

#[test]
fn custody_daily_failure_never_promotes_a_listener_to_authenticated()
-> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let path = std::env::temp_dir().join(format!(
        "custody-final-admission-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    {
        let store = crate::RouterRedbStore::open_without_wal(&path)?;
        let router = crate::RouterCore::new();
        store.save_router(&router)?;
        let refused = Driver::new("final-refused", 170)?;
        let service = CustodyService::new(refused.node.clone(), false, &store, now)?;
        let action = refused.publish();
        let challenge = refused.challenge(&service, &router, &store, action.clone())?;
        let proof = refused.proof(&challenge)?;
        let authority =
            router.verify_custody_possession_authority(&refused.publication, now, false)?;
        let source = "192.0.2.1".parse()?;
        // Model the durable budget filling after the early pre-check. The function under
        // test must preserve the failure through the real permit transaction.
        store.check_custody_new_principal_budget(source, now)?;
        for index in 0..8 {
            let admitted = Driver::new(&format!("final-admitted-{index}"), 150 + index)?;
            router.publish_custody_record_from(&admitted.publication, now, &store, source)?;
        }
        let pool = crate::CustodyIngressLimiter::with_pools(
            1,
            Some(1),
            1,
            std::time::Duration::from_secs(300),
        );
        let permit = pool.acquire(source, None, std::time::Instant::now())?;
        let scope = Scope {
            router: &router,
            store: &store,
            peer: "ramflux-gateway",
            now,
            tick: std::time::Instant::now(),
            origin: &Origin::Proxy,
            permit: Some(&permit),
        };
        let response = service.finish_proof(
            scope,
            ProofAttempt {
                action,
                proof: Box::new(proof),
                receipt: None,
                connection_id: refused.connection.clone(),
            },
            Possession {
                publication: &refused.publication,
                authority: &authority,
                holder: refused.connection.clone(),
                source,
            },
        )?;
        assert_eq!(
            response,
            CustodyServerFrame::Refused {
                code: CustodyRefusal::Capacity,
                capacity: Some(CapacityHint {
                    scope: CapacityScope::PrefixDaily,
                    resets_at_unix: (now / 86_400 + 1) * 86_400
                }),
                retry: None,
            }
        );
        assert!(router.custody_record(&refused.reference.account_anchor, now)?.is_none());
        assert!(
            matches!(
                permit.try_grant("actual-principal", || Ok::<_, CustodyRefusal>(())),
                Ok(Ok(()))
            ),
            "a refused frame must not have authenticated its principal"
        );
    }
    std::fs::remove_file(path)?;
    Ok(())
}

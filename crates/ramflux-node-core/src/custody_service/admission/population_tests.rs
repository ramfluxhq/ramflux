// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed proofs, durable publication/prekey commits and sessions under injected time.
use super::*;
use crate::tests::custody_sessions::Driver;
use ramflux_crypto::custody::{branch_exporter_hash, sign_proxy_acceptance};
use ramflux_protocol::custody::RetryScope;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_760_000_000;
struct Scenario {
    router: crate::RouterCore,
    store: crate::RouterRedbStore,
    service: CustodyService,
    source: &'static str,
    started: std::time::Instant,
    offset: u64,
    issued: usize,
    windows: usize,
    fast: bool,
}
impl Scenario {
    fn new(
        path: &std::path::Path,
        source: &'static str,
        fast: bool,
        drivers: &[Driver],
    ) -> Result<Self> {
        let store = crate::RouterRedbStore::open_without_wal(path)?;
        let router = crate::RouterCore::new();
        store.save_router(&router)?;
        // Known principals isolate admission from unchanged durable new-principal quotas.
        for (n, driver) in drivers.iter().enumerate() {
            router.publish_custody_record_from(
                &driver.publication,
                NOW + u64::try_from(n / 16)? * 60,
                &store,
                format!("198.18.{n}.1").parse()?,
            )?;
        }
        let settings = if fast {
            crate::CustodyIssuanceSettings::new(128, 128, 1024)?
        } else {
            crate::CustodyIssuanceSettings::default()
        };
        let service = CustodyService::with_issuance_settings(
            drivers[0].node.clone(),
            false,
            &store,
            NOW + 60,
            settings,
        )?;
        Ok(Self {
            router,
            store,
            service,
            source,
            started: std::time::Instant::now(),
            offset: 0,
            issued: 0,
            windows: 1,
            fast,
        })
    }
    fn scope<'a>(&'a self, permit: &'a crate::CustodyIngressPermit) -> Scope<'a> {
        Scope {
            router: &self.router,
            store: &self.store,
            peer: "ramflux-gateway",
            now: NOW + 60 + self.offset / 1000,
            tick: self.started + std::time::Duration::from_millis(self.offset),
            origin: &Origin::Proxy,
            permit: Some(permit),
        }
    }
    fn challenge(
        &mut self,
        driver: &Driver,
        action: &CustodyProofAction,
        permit: &crate::CustodyIngressPermit,
    ) -> Result<ramflux_protocol::custody::BranchChallenge> {
        loop {
            let request = CustodyMeshRequest::Challenge {
                device_ref: driver.reference.clone(),
                action: action.clone(),
                binding_mode: BindingMode::HomeRelayReceipt,
                client_source: self.source.into(),
                connection_id: driver.connection.clone(),
            };
            match self.service.dispatch_at(request, self.scope(permit))? {
                CustodyServerFrame::Challenge { challenge } => {
                    self.issued += 1;
                    return Ok(challenge);
                }
                CustodyServerFrame::Refused {
                    code: CustodyRefusal::Busy,
                    capacity: None,
                    retry: Some(retry),
                } => {
                    assert!(!self.fast);
                    assert_eq!(self.issued % 16, 0, "only issuance windows can refuse");
                    assert_eq!(retry.scope, RetryScope::PreAuthSource);
                    assert!((1000..=60_000).contains(&retry.retry_after_ms));
                    self.offset += u64::from(retry.retry_after_ms);
                    self.windows += 1;
                }
                other => return Err(format!("challenge {}: {other:?}", self.issued).into()),
            }
        }
    }
    fn prove(
        &mut self,
        driver: &Driver,
        action: CustodyProofAction,
        permit: &crate::CustodyIngressPermit,
    ) -> Result<CustodyServerFrame> {
        let challenge = self.challenge(driver, &action, permit)?;
        let proof = driver.proof(&challenge)?;
        let receipt = sign_proxy_acceptance(
            &driver.proxy,
            &driver.node,
            &proof,
            &branch_exporter_hash(&[5; 32]),
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            NOW + 60 + self.offset / 1000,
        )?;
        Ok(self.service.dispatch_at(
            CustodyMeshRequest::Prove {
                action,
                proof: Box::new(proof),
                receipt: Some(Box::new(receipt)),
                connection_id: driver.connection.clone(),
            },
            self.scope(permit),
        )?)
    }
}
#[test]
fn twenty_accounts_same_ip_become_live_within_issuance_windows() -> Result {
    for fast in [false, true] {
        for source in ["192.0.2.1", "2001:db8:1:2::1"] {
            let path = std::env::temp_dir().join(format!(
                "custody-population-{}.redb",
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
            ));
            {
                let drivers = (0..20)
                    .map(|n| Driver::new(&format!("known-{n}"), 20 + n))
                    .collect::<Result<Vec<_>>>()?;
                let mut scenario = Scenario::new(&path, source, fast, &drivers)?;
                let limiter = crate::CustodyIngressLimiter::new(256);
                let mut held = Vec::new();
                for (n, driver) in drivers.iter().enumerate() {
                    let permit =
                        limiter.acquire(source.parse()?, None, std::time::Instant::now())?;
                    for (step, action) in [
                        driver.publish(),
                        CustodyProofAction::Register {
                            prekey_bundle: driver.bundle(20 + u8::try_from(n)?)?,
                        },
                        CustodyProofAction::OpenSession,
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let response = scenario.prove(driver, action, &permit)?;
                        assert!(
                            match step {
                                0 => matches!(response, CustodyServerFrame::Published { .. }),
                                1 => matches!(response, CustodyServerFrame::Registered { .. }),
                                _ => matches!(
                                    response,
                                    CustodyServerFrame::SessionEstablished { .. }
                                ),
                            },
                            "account={n} step={step} {response:?}"
                        );
                    }
                    held.push(permit);
                }
                assert_eq!(scenario.issued, 60);
                assert_eq!(scenario.windows, if fast { 1 } else { 4 });
                assert!(held.iter().all(|p| !p.is_revoked()));
                let mut holds = limiter.grant_lock_hold_times();
                holds.sort();
                assert_eq!(holds.len(), 120);
                assert!(holds[holds.len() * 99 / 100] <= std::time::Duration::from_millis(1));
                eprintln!(
                    "grant reserve/commit lock samples={} p99_us={} fast={fast} family={}",
                    holds.len(),
                    holds[(holds.len() * 99 / 100).min(holds.len() - 1)].as_micros(),
                    if source.contains(':') { "ipv6" } else { "ipv4" }
                );
            }
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}
#[test]
fn durable_grant_callback_does_not_require_a_network_runtime() -> Result {
    // Compile-time contract: the actual callback yields a concrete frame/error, never a Future.
    fn synchronous_callback(
        _: fn(
            &CustodyService,
            Scope<'_>,
            ProofAttempt,
            Possession<'_>,
        ) -> std::result::Result<CustodyServerFrame, super::super::ProofFailure>,
    ) {
    }
    synchronous_callback(CustodyService::finish_admitted_proof);
    assert!(tokio::runtime::Handle::try_current().is_err());
    // Exercise actual signed proofs and durable commits with no runtime/network driver present.
    twenty_accounts_same_ip_become_live_within_issuance_windows()
}

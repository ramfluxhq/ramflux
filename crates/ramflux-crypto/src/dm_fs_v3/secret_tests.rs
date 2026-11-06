// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::recipient_tests::{Case, Result, rejected, vectors};
use super::*;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    future::{Future, pending},
    task::{Context, Poll, Waker},
};
use zeroize::Zeroizing;
struct Observation {
    fail: Option<&'static str>,
    wipes: BTreeMap<&'static str, usize>,
}
thread_local! {static OBS:RefCell<Option<Observation>>=const {RefCell::new(None)};}
pub(super) fn observe(slot: &'static str, bytes: &[u8]) {
    assert!(bytes.iter().all(|b| *b == 0), "recipient buffer not erased: {slot}");
    OBS.with(|obs| {
        if let Some(obs) = obs.borrow_mut().as_mut() {
            *obs.wipes.entry(slot).or_insert(0) += 1;
        }
    });
}
pub(super) fn checkpoint(stage: &'static str) -> std::result::Result<(), NativeBootstrapError> {
    if OBS.with(|obs| obs.borrow().as_ref().is_some_and(|obs| obs.fail == Some(stage))) {
        Err(NativeHkdfError::Injected.into())
    } else {
        Ok(())
    }
}
fn capture(
    fail: Option<&'static str>,
    run: impl FnOnce() -> Result,
) -> Result<BTreeMap<&'static str, usize>> {
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            OBS.with(|obs| {
                obs.replace(None);
            });
        }
    }
    OBS.with(|obs| {
        assert!(obs.borrow().is_none());
        obs.replace(Some(Observation { fail, wipes: BTreeMap::new() }));
    });
    let scope = Scope;
    run()?;
    let observed = OBS.with(RefCell::take).ok_or("recipient observer")?.wipes;
    drop(scope);
    Ok(observed)
}
// Independent inventory of owners that exist at each return point.
fn expected(stage: &str, opk: bool) -> BTreeMap<&'static str, usize> {
    let mut map = BTreeMap::new();
    if stage == "validated" {
        return map;
    }
    map.insert("recipient_spk_seed", 1);
    if stage == "spk" {
        return map;
    }
    map.insert("recipient_dh1", 1);
    if stage == "dh1" {
        return map;
    }
    map.insert("recipient_dh3", 1);
    if stage == "dh3" {
        return map;
    }
    if opk {
        map.insert("recipient_opk_seed", 1);
        if stage == "opk" {
            return map;
        }
        map.insert("recipient_dh4", 1);
    }
    if stage != "dh4" {
        map.insert("recipient_ikm", 1);
    }
    map
}
#[test]
fn dm_fs_v3_secret_buffers_erased_on_every_exit() -> Result {
    let v = vectors()?;
    for v in v["bootstrap"].as_array().ok_or("bootstrap")? {
        let c = Case::new(v)?;
        let opk = c.lease.opk.is_some();
        let length = if opk { 160 } else { 128 };
        let info = ramflux_protocol::domain::DM_FS_V3_X3DH_ROOT.len() + 32;
        let spk_before = *c.spk;
        let opk_before = *c.opk;
        let dh2_before = *c.dh2;
        for stage in ["validated", "spk", "dh1", "dh3", "opk", "dh4", "ikm", "derived"] {
            if stage == "opk" && !opk {
                continue;
            }
            let observed = if stage == "derived" {
                let mut observed = None;
                super::hkdf_tests::native_cleanup_contract(length, info, 1, || {
                    observed = Some(capture(Some(stage), || {
                        rejected(c.input(), NativeHkdfError::Injected.into(), stage);
                        Ok(())
                    })?);
                    Ok(())
                })?;
                observed.ok_or("derived observations")?
            } else {
                capture(Some(stage), || {
                    rejected(c.input(), NativeHkdfError::Injected.into(), stage);
                    Ok(())
                })?
            };
            assert_eq!(observed, expected(stage, opk), "exit {stage}");
        }
        // Success and cancellation after synchronous derivation both drop actual SK.
        for cancel in [false, true] {
            super::hkdf_tests::native_cleanup_contract(length, info, 1, || {
                let observed = capture(None, || {
                    if cancel {
                        let mut operation = Box::pin(async {
                            let output = native_recipient(c.input())?;
                            pending::<()>().await;
                            drop(output);
                            Ok::<(), NativeBootstrapError>(())
                        });
                        let mut context = Context::from_waker(Waker::noop());
                        assert!(matches!(operation.as_mut().poll(&mut context), Poll::Pending));
                        drop(operation);
                    } else {
                        drop(native_recipient(c.input())?);
                    }
                    Ok(())
                })?;
                assert_eq!(observed, expected("derived", opk));
                Ok(())
            })?;
        }
        real_failure_cleanup(&c, opk)?;
        assert!(
            *c.spk == spk_before && *c.opk == opk_before && *c.dh2 == dh2_before,
            "borrowed provider material changed"
        );
    }
    Ok(())
}

fn real_failure_cleanup(c: &Case, opk: bool) -> Result {
    // Real failures, including ones after transient DH/seed allocation.
    let wrong = Zeroizing::new([42; 32]);
    let observed = capture(None, || {
        let mut input = c.input();
        input.spk.seed = &wrong;
        rejected(input, NativePrekeyError::Binding.into(), "SPK mismatch cleanup");
        Ok(())
    })?;
    assert_eq!(observed, expected("spk", opk));
    let zero = Zeroizing::new([0; 32]);
    let observed = capture(None, || {
        let mut input = c.input();
        input.agreement_dh2 = &zero;
        rejected(input, NativeBootstrapError::NonContributory, "zero DH2 cleanup");
        Ok(())
    })?;
    assert!(observed.is_empty());
    let mut t = c.t.clone();
    t.header.ephemeral_key = [0; 32];
    let observed = capture(None, || {
        let mut input = c.input();
        input.transcript = &t;
        input.received_header = &t.header;
        rejected(input, NativeBootstrapError::NonContributory, "zero DH3 cleanup");
        Ok(())
    })?;
    assert_eq!(observed, expected("dh3", false));
    let (lease, t) = super::recipient_tests::signed_source_peer(c, [0; 32])?;
    let observed = capture(None, || {
        let mut input = c.input();
        input.lease = &lease;
        input.transcript = &t;
        input.received_header = &t.header;
        rejected(input, NativeBootstrapError::NonContributory, "zero DH1 cleanup");
        Ok(())
    })?;
    assert_eq!(observed, expected("dh1", false));
    if opk {
        let observed = capture(None, || {
            let mut input = c.input();
            input.opk.as_mut().ok_or("OPK")?.seed = &wrong;
            rejected(input, NativePrekeyError::Binding.into(), "OPK mismatch cleanup");
            Ok(())
        })?;
        assert_eq!(observed, expected("opk", true));
    }
    Ok(())
}

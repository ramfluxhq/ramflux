// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual SDK account owners over the existing TLS front and Fedwire pairing routes.
use super::*;
use ramflux_sdk::{
    RamfluxClient,
    custody::{self, pairing::*},
};
#[path = "native_devices/device.rs"]
mod device;
#[path = "native_devices/node.rs"]
mod node;
#[path = "native_devices/vault.rs"]
mod vault;

#[tokio::test]
async fn pairing_tls_fedwire_enrollment_activates_independent_native_sdk_stores() -> TestResult {
    deadline(Box::pin(async {
        let mut wire = Continuity::open()?;
        let node = Arc::new(node::Access::new(&wire.node));
        let (primary, mut a) =
            device::Device::create(node.clone(), "sdk-phone-a", true, &wire.config)?;
        let (recipient, mut b) =
            device::Device::create(node.clone(), "sdk-phone-b", false, &wire.config)?;
        wire.primary = primary;
        wire.recipient = recipient;
        assert_ne!(a.root.path(), b.root.path(), "test: TLS SDK clients share a data root");
        assert!(!Arc::ptr_eq(&a.vault, &b.vault), "test: TLS SDK clients share a credential vault");
        Box::pin(enroll_native(&mut wire)).await?;
        a.admit(&node).await?;
        b.admit(&node).await?;
        assert_eq!(
            a.vault.primary_entries()?,
            1,
            "test: enrollment removed approving phone management"
        );
        assert_eq!(
            b.vault.primary_entries()?,
            0,
            "test: enrollment copied primary authority to recipient"
        );
        let source = custody::load_account(a.root.path(), &a.id, wall()?)?;
        let target = custody::load_account(b.root.path(), &b.id, wall()?)?;
        assert_eq!(
            source.record(),
            target.record(),
            "test: independently activated SDK roots disagree on native head"
        );
        let (ak, _, ar) = a.vault.local_branch(source.record())?;
        let (bk, _, br) = b.vault.local_branch(target.record())?;
        assert_ne!(ar, br, "test: enrolled phone reused primary's branch reference");
        assert_ne!(
            ak.signing_key.verifying_key(),
            bk.signing_key.verifying_key(),
            "test: enrolled phone reused source signing key"
        );
        wire.primary.lock().await?;
        wire.recipient.lock().await?;
        Ok(())
    }))
    .await
}

async fn begin_native(wire: &mut Continuity) -> TestResult<(String, u64)> {
    let mut request = begin_body()?;
    request.capabilities = vec!["group".into(), "message".into(), "register".into(), "sync".into()];
    request.lease_expires_at = request.lease_not_before + 604_800;
    let begun = begin_result(wire.primary.begin(request).await?)?;
    let operation = begun.operation_id.clone();
    let generation = begun.generation;
    wire.recipient
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: begun.invite_token,
            display_name: "Paired phone".into(),
        })
        .await?;
    drive_sas(wire, &operation, generation).await?;
    Ok((operation, generation))
}
async fn deadline(work: impl std::future::Future<Output = TestResult>) -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(120), work)
        .await
        .map_err(|_| "test: real TLS/Fedwire SDK enrollment exceeded deadline")?
}

async fn enroll_native(wire: &mut Continuity) -> TestResult {
    let (operation, generation) = Box::pin(begin_native(wire)).await?;
    for actor in [&mut wire.primary, &mut wire.recipient] {
        wire.clock.advance_ms(1001);
        actor.confirm(&confirm_ok(actor, &operation)?).await?;
    }
    for _ in 0..24 {
        drive_once(wire).await?;
        if wire.primary.displayed_proposal().is_ok() {
            break;
        }
    }
    let approval = approve_ok(&wire.primary, &operation)?;
    wire.clock.advance_ms(1001);
    wire.primary.approve(&approval).await?;
    let mut complete = false;
    for _ in 0..32 {
        drive_once(wire).await?;
        if phase(&mut wire.primary, &operation, generation).await? == "completed"
            && phase(&mut wire.recipient, &operation, generation).await? == "completed"
        {
            complete = true;
            break;
        }
    }
    assert!(complete, "test: TLS/Fedwire enrollment did not reach both durable completions");
    Ok(())
}

#[path = "native_devices/handoff.rs"]
mod handoff;

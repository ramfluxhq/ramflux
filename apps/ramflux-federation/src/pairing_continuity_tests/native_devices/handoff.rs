// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Supported-source full handoff over the actual TLS front and Fedwire native relay.
use super::*;
use ramflux_protocol::custody::pairing::{
    context_v3::{DataSelectionV3, FullAccountData, TransferProfile},
    local_dto::{FullStatus, FullStatusStage, FullTailStatus, FullTransferBegin, Prepare},
};
#[path = "handoff/driver.rs"]
mod driver;
struct Fixture {
    wire: Continuity,
    a: device::Device,
    b: device::Device,
    source: PairingLocalWriterService,
    target: PairingLocalWriterService,
    operation: String,
}
#[tokio::test]
async fn pairing_tls_fedwire_full_handoff_retires_only_old_primary() -> TestResult {
    deadline(Box::pin(run())).await
}
async fn run() -> TestResult {
    let mut fixture = Box::pin(Fixture::open())
        .await
        .map_err(|error| format!("test: TLS full fixture: {error}"))?;
    let original = [fixture.branch(true)?, fixture.branch(false)?];
    let wrapping = ramflux_storage::AccountIndex::open(fixture.b.root.path())?
        .load_wrapped_db_key(&fixture.b.id)?;
    Box::pin(fixture.begin()).await.map_err(|error| format!("test: TLS full begin: {error}"))?;
    Box::pin(fixture.data()).await.map_err(|error| format!("test: TLS full data: {error}"))?;
    Box::pin(fixture.publish())
        .await
        .map_err(|error| format!("test: TLS full publish: {error}"))?;
    Box::pin(fixture.merge()).await.map_err(|error| format!("test: TLS full merge: {error}"))?;
    for (primary, expected) in [true, false].into_iter().zip(original) {
        assert_eq!(
            fixture.branch(primary)?,
            expected,
            "test: TLS full handoff replaced an independently held branch"
        );
    }
    assert_eq!(
        ramflux_storage::AccountIndex::open(fixture.b.root.path())?
            .load_wrapped_db_key(&fixture.b.id)?,
        wrapping,
        "test: TLS handoff replaced existing B's original password wrapping"
    );
    assert_eq!(fixture.a.vault.primary_entries()?, 0, "test: old primary key survived retirement");
    assert_eq!(fixture.b.vault.primary_entries()?, 1, "test: B did not retain its own primary key");
    for device in [&fixture.a, &fixture.b] {
        assert!(
            ordinary_session_admitted(&device.client, &device.id)?,
            "test: positively installed TLS branch remained fenced"
        );
    }
    let a = custody::load_account(fixture.a.root.path(), &fixture.a.id, wall()?)?;
    let b = custody::load_account(fixture.b.root.path(), &fixture.b.id, wall()?)?;
    assert_eq!(a.record(), b.record(), "test: TLS handoff endpoints disagree on native head");
    assert_eq!(a.record().body.devices.len(), 2, "test: handoff removed a surviving device");
    let (_, _, recipient) = fixture.b.vault.local_branch(b.record())?;
    assert_eq!(
        b.record().body.master_certificate.body.primary_device_ref,
        recipient,
        "test: native authority did not promote the original B branch"
    );
    fixture.wire.primary.lock().await?;
    fixture.wire.recipient.lock().await?;
    Ok(())
}
impl Fixture {
    async fn open() -> TestResult<Self> {
        let mut wire = Continuity::open()?;
        let node = Arc::new(node::Access::new(&wire.node));
        let (primary, mut a) =
            device::Device::create(node.clone(), "full-phone-a", true, &wire.config)?;
        let (recipient, mut b) =
            device::Device::create(node.clone(), "full-phone-b", false, &wire.config)?;
        wire.primary = primary;
        wire.recipient = recipient;
        Box::pin(enroll_native(&mut wire)).await?;
        *b.credential.0.lock().map_err(|_| "test: B attended phrase provider")? =
            Some(a.phrase.as_ref().ok_or("test: original human recovery phrase")?.clone());
        let (primary, source) = a
            .full_frontend(node.clone(), &wire.config, true)
            .map_err(|error| format!("test: TLS source frontend: {error}"))?;
        let (recipient, target) = b
            .full_frontend(node, &wire.config, false)
            .map_err(|error| format!("test: TLS B frontend: {error}"))?;
        wire.primary = primary;
        wire.recipient = recipient;
        Ok(Self { wire, a, b, source, target, operation: String::new() })
    }
    fn branch(&self, primary: bool) -> TestResult<([u8; 32], [u8; 32], DeviceRef)> {
        let device = if primary { &self.a } else { &self.b };
        let native = custody::load_account(device.root.path(), &device.id, wall()?)?;
        let (branch, dh, reference) = device.vault.local_branch(native.record())?;
        Ok((branch.signing_key.verifying_key().to_bytes(), dh.public, reference))
    }
    async fn begin(&mut self) -> TestResult {
        let (_, _, destination) = self.branch(false)?;
        let native = custody::load_account(self.b.root.path(), &self.b.id, wall()?)?;
        let certificate = native
            .record()
            .body
            .devices
            .iter()
            .find(|device| device.device_id == destination.device_id)
            .and_then(|device| device.branch_certificate.as_ref())
            .ok_or("test: original B certificate")?;
        let request = FullTransferBegin {
            schema: "ramflux.pairing.TransferBegin.v3".into(),
            version: 3,
            recipient_mode: "existing".into(),
            destination_ref: Some(destination),
            capabilities: certificate.body.capabilities.clone(),
            lease_not_before: certificate.body.not_before,
            lease_expires_at: certificate.body.expires_at,
            data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
            transfer_profile: TransferProfile::FullAccountDataV1,
            display_name: "Phone source".into(),
        };
        let reply = driver::drive(
            Box::pin(self.wire.primary.begin_full(request)),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        let Outcome::Begin { value } = reply.outcome else {
            return Err("test: TLS full invitation missing".into());
        };
        self.operation.clone_from(&value.operation_id);
        driver::drive(
            Box::pin(self.wire.recipient.join(Join {
                schema: "ramflux.pairing.Join.v2".into(),
                version: 2,
                token: value.invite_token,
                display_name: "Existing phone".into(),
            })),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        for _ in 0..32 {
            self.step().await?;
            if self.wire.primary.displayed_transcript().is_ok()
                && self.wire.recipient.displayed_transcript().is_ok()
            {
                break;
            }
        }
        let transcript = self.wire.primary.displayed_transcript()?;
        assert_eq!(
            transcript,
            self.wire.recipient.displayed_transcript()?,
            "test: TLS full SAS disagreement"
        );
        for actor in [&mut self.wire.primary, &mut self.wire.recipient] {
            self.wire.clock.advance_ms(1001);
            let request = Confirm {
                schema: "ramflux.pairing.Confirm.v2".into(),
                version: 2,
                operation_id: self.operation.clone(),
                generation: actor.actor_generation(),
                transcript_hash: transcript.clone(),
                r#match: true,
            };
            driver::drive(
                Box::pin(actor.confirm(&request)),
                &mut self.source,
                &self.a.client,
                &mut self.target,
                &self.b.client,
            )
            .await?;
        }
        Ok(())
    }
}

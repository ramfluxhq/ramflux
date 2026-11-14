// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! External SDK driver: own writers, attended credentials and real native relay permits.
use super::{
    ResultOf,
    device::Device,
    node::{Node, now},
};
use ramflux_protocol::custody::pairing::{
    context_v3::{DataSelectionV3, FullAccountData, TransferProfile},
    local_dto::*,
};
use ramflux_sdk::{
    SdkError,
    custody::pairing::{PairingLocalWriterService, ordinary_session_admitted},
};
use std::{future::Future, sync::Arc};

pub struct Fixture {
    pub a: Device,
    pub b: Device,
    pub c: Device,
    pub source: PairingLocalWriterService,
    pub target: PairingLocalWriterService,
    pub node: Arc<Node>,
    pub operation: String,
}
async fn drive<T>(
    work: impl Future<Output = Result<T, SdkError>>,
    a: &mut PairingLocalWriterService,
    ac: &ramflux_sdk::RamfluxClient,
    b: &mut PairingLocalWriterService,
    bc: &ramflux_sdk::RamfluxClient,
) -> Result<T, SdkError> {
    let first = a.work_signal();
    let second = b.work_signal();
    tokio::pin!(work);
    loop {
        tokio::select! {
            result = &mut work => return result,
            () = first.notified() => { a.try_apply_client(ac)?; },
            () = second.notified() => { b.try_apply_client(bc)?; },
        }
    }
}
impl Fixture {
    pub async fn open() -> ResultOf<Self> {
        let node = Node::open()?;
        let mut a = Box::pin(Device::fresh_primary(node.clone(), "phone-a")).await?;
        let mut b = Box::pin(Device::create(node.clone(), "phone-b", false)).await?;
        let mut c = Box::pin(Device::create(node.clone(), "web-c", false)).await?;
        Box::pin(super::ceremony::enroll(&mut a, &mut b, &node)).await?;
        Box::pin(super::ceremony::enroll(&mut a, &mut c, &node)).await?;
        // A human supplies A's original phrase to B's independent local provider.
        *b.credential.0.lock().map_err(|_| "test: B credential owner")? =
            Some(a.phrase.as_ref().ok_or("test: source phrase")?.clone());
        let source = a.prepare_frontend(&node, true)?;
        let target = b.prepare_frontend(&node, false)?;
        c.admit_client(&node).await?;
        for (left, right) in [(&a, &b), (&a, &c), (&b, &c)] {
            assert_ne!(left.root.path(), right.root.path(), "test: SDK roots overlap");
            assert!(!Arc::ptr_eq(&left.vault, &right.vault), "test: SDK vault owners overlap");
        }
        a.with_db(|db| {
            Ok(db.seed_full_transfer_object_veto_for_test("source-veto", "source-manifest", 3)?)
        })?;
        b.with_db(|db| {
            Ok(db.seed_full_transfer_object_veto_for_test("target-veto", "target-manifest", 7)?)
        })?;
        Ok(Self { a, b, c, source, target, node, operation: String::new() })
    }
    pub async fn begin(&mut self) -> ResultOf<()> {
        let (_, _, destination) = self.b.endpoint.branch()?;
        let request = FullTransferBegin {
            schema: "ramflux.pairing.TransferBegin.v3".into(),
            version: 3,
            recipient_mode: "existing".into(),
            destination_ref: Some(destination),
            capabilities: vec!["group".into(), "message".into(), "register".into(), "sync".into()],
            lease_not_before: now()?,
            lease_expires_at: now()? + 604_800,
            data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
            transfer_profile: TransferProfile::FullAccountDataV1,
            display_name: "Source phone".into(),
        };
        let begun = drive(
            Box::pin(self.a.actor.begin_full(request)),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        let Outcome::Begin { value } = begun.outcome else {
            return Err("test: missing full invitation".into());
        };
        self.operation.clone_from(&value.operation_id);
        drive(
            Box::pin(self.b.actor.join(Join {
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
            if self.a.actor.displayed_transcript().is_ok()
                && self.b.actor.displayed_transcript().is_ok()
            {
                break;
            }
        }
        let transcript = self.a.actor.displayed_transcript()?;
        assert_eq!(
            transcript,
            self.b.actor.displayed_transcript()?,
            "test: independent SAS mismatch"
        );
        for actor in [&mut self.a.actor, &mut self.b.actor] {
            self.node.clock.advance_ms(1001);
            let request = Confirm {
                schema: "ramflux.pairing.Confirm.v2".into(),
                version: 2,
                operation_id: self.operation.clone(),
                generation: actor.actor_generation(),
                transcript_hash: transcript.clone(),
                r#match: true,
            };
            drive(
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
    pub async fn step(&mut self) -> ResultOf<()> {
        self.a.service_data()?;
        self.b.service_data()?;
        for actor in [&mut self.a.actor, &mut self.b.actor] {
            if !actor.full_data_worker_owns_relay() {
                self.node.clock.advance_ms(1001);
            }
            drive(
                Box::pin(actor.sync_relay()),
                &mut self.source,
                &self.a.client,
                &mut self.target,
                &self.b.client,
            )
            .await?;
        }
        // sync_relay may just have published epoch_ready. Start that foreground
        // transition before waiting on the other peer's already-running DATA job.
        self.a.service_data()?;
        self.b.service_data()?;
        // A peer still on the SAS relay must be pumped before either DATA worker is awaited.
        if self.a.actor.full_data_worker_owns_relay()
            && self.b.actor.full_data_worker_owns_relay()
            && (self.a.actor.has_pending_full_local_work()
                || self.b.actor.has_pending_full_local_work())
        {
            let a = self.a.actor.local_work_signal();
            let b = self.b.actor.local_work_signal();
            let source = self.source.work_signal();
            let target = self.target.work_signal();
            tokio::select! {
                () = a.notified() => {}, () = b.notified() => {},
                () = source.notified() => { self.source.try_apply_client(&self.a.client)?; },
                () = target.notified() => { self.target.try_apply_client(&self.b.client)?; },
            }
        }
        Ok(())
    }
    pub async fn status(&mut self, primary: bool) -> ResultOf<Option<FullStatus>> {
        let actor = if primary { &mut self.a.actor } else { &mut self.b.actor };
        let request = StatusRequest {
            schema: "ramflux.pairing.StatusRequest.v2".into(),
            version: 2,
            operation_id: self.operation.clone(),
            generation: actor.actor_generation(),
        };
        let result = drive(
            Box::pin(actor.transfer_status(&request)),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        Ok(if let Outcome::FullStatus { value } = result.outcome { Some(*value) } else { None })
    }
    pub async fn data(&mut self) -> ResultOf<()> {
        for iteration in 0..1024 {
            self.step().await?;
            if matches!(iteration, 2 | 8 | 16) {
                self.b.with_db(|db| {
                    Ok(db.seed_full_transfer_object_veto_for_test(
                        &format!("concurrent-{iteration}"),
                        "concurrent-manifest",
                        13,
                    )?)
                })?;
            }
            let a = self.status(true).await?;
            let b = self.status(false).await?;
            if iteration >= 16
                && a.is_some_and(|value| value.stage == FullStatusStage::AwaitingPrepare)
                && b.is_some_and(|value| value.stage == FullStatusStage::AwaitingPrepare)
            {
                return Ok(());
            }
        }
        Err("test: external full driver did not finish durable duplex".into())
    }
    async fn affirm_source_if_displayed(&mut self) -> ResultOf<()> {
        if self.a.actor.affirmed_full_source_preservation().is_ok() {
            return Ok(());
        }
        let Ok(candidate) = self.a.actor.displayed_proposal() else { return Ok(()) };
        let affirm = TransferAffirm {
            schema: "ramflux.pairing.TransferAffirm.v2".into(),
            version: 2,
            operation_id: self.operation.clone(),
            generation: self.a.actor.actor_generation(),
            transcript_hash: self.a.actor.displayed_transcript()?,
            new_record_hash: candidate,
            approved: true,
        };
        drive(
            Box::pin(self.a.actor.affirm_full_transfer(&affirm)),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        self.a.service_data()?;
        Ok(())
    }
    pub async fn publish(&mut self) -> ResultOf<()> {
        let original = self.b.selected_path()?;
        let request = Prepare {
            schema: "ramflux.pairing.Prepare.v2".into(),
            version: 2,
            operation_id: self.operation.clone(),
            generation: self.b.actor.actor_generation(),
            transcript_hash: self.b.actor.displayed_transcript()?,
        };
        drive(
            Box::pin(self.b.actor.prepare_full_transfer(&request)),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        for _ in 0..1024 {
            self.a
                .service_data()
                .map_err(|error| format!("test: publication source service: {error}"))?;
            self.b
                .service_data()
                .map_err(|error| format!("test: publication target service: {error}"))?;
            for actor in [&mut self.b.actor, &mut self.a.actor] {
                self.node.clock.advance_ms(1001);
                drive(
                    Box::pin(actor.poll_full_management_control()),
                    &mut self.source,
                    &self.a.client,
                    &mut self.target,
                    &self.b.client,
                )
                .await?;
            }
            self.affirm_source_if_displayed().await?;
            drive(
                Box::pin(self.a.actor.advance_full_source_publication()),
                &mut self.source,
                &self.a.client,
                &mut self.target,
                &self.b.client,
            )
            .await?;
            self.b
                .actor
                .service_linked_installation(&mut self.b.client, &mut self.target)
                .map_err(|error| format!("test: own G3 frontend handback: {error}"))?;
            if self.b.selected_path()? != original
                && ordinary_session_admitted(&self.b.client, &self.b.id)?
                && self.b.vault.primary_entries()? == 1
            {
                return Ok(());
            }
        }
        Err("test: actual node publication did not install B's own generation".into())
    }
}

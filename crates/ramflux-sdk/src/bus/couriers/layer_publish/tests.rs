// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Layer-declaration publication: lease scope, crash cuts, recovery order, backoff and the
//! held-Publish barrier. Every test has a deadline.
use super::*;
use crate::bus::connection_manager::AccountWork;
use crate::client::native_test_support::{Fixture, TestResult};
use crate::time::FixedClock;
use ramflux_protocol::custody::{LayerDeclaration, SignedLayerDeclaration};
use std::future::Future;

/// The shared 120-second component watchdog; no per-test timing sites of our own.
async fn within<T>(future: impl Future<Output = TestResult<T>>) -> TestResult<T> {
    crate::client::native_test_support::watchdog::within(future)
        .await
        .map_err(|_| "test: deadline exceeded")?
}

struct Keep {
    _root: crate::custody::tests::Root,
    _vault: Arc<crate::custody::tests::TestVault>,
}

/// A live primary account with no declaration, ready for the courier's Prepare.
async fn live_primary(id: &str) -> TestResult<(LocalBusAccountState, Keep)> {
    let mut fixture = Fixture::new(id).await?;
    let now = crate::custody::network_now()?;
    let account_id = fixture.client.account_db()?.local_account_id.clone();
    crate::custody::tests::mark_live(&fixture.root.0, &account_id, now)?;
    fixture.client.initialize_born_v3_branch("primary", fixture.vault.clone()).await?;
    let anchor = fixture.manifest.principal_commitment.clone();
    let Fixture { client, vault, config, root, .. } = fixture;
    Ok((
        LocalBusAccountState::disconnected(client, config, anchor),
        Keep { _root: root, _vault: vault },
    ))
}

/// Crash cut 1: the candidate is durable as `prepared` and nothing was submitted.
fn stage_prepared(account: &mut LocalBusAccountState) -> TestResult<ramflux_storage::HeadRow> {
    let config = account.gateway_config.custody.clone().ok_or("test: custody config")?;
    let record_issued =
        account.client.born_v3_account.as_deref().ok_or("test: native")?.record().body.issued_at;
    let issued_at = custody::network_now()?.max(record_issued + 1);
    let validity = DeclarationValidity { issued_at, expires_at: issued_at + 3 * 3_600 };
    let operation = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let write = layer_write(account, &config, operation, validity)?;
    Ok(custody::pairing::publication::stage_prepared_head(
        account.client.account_db()?,
        &config.account_root,
        config.vault.as_ref(),
        &write,
    )?)
}

fn local_declaration(account: &LocalBusAccountState) -> Option<SignedLayerDeclaration> {
    let born = account.client.born_v3_account.as_deref()?;
    born.record()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == "primary")?
        .message_layer
        .clone()
}

fn head_state(account: &LocalBusAccountState) -> TestResult<Option<(String, String)>> {
    Ok(account.client.account_db()?.pairing_head()?.map(|head| (head.kind, head.state)))
}

fn signed(max_layer: u32, issued_at: u64, expires_at: u64) -> SignedLayerDeclaration {
    SignedLayerDeclaration {
        declaration: LayerDeclaration {
            device: ramflux_protocol::custody::DeviceRef {
                account_anchor: String::new(),
                device_id: "primary".into(),
                device_epoch: 1,
            },
            max_layer,
            declaration_sequence: 1,
            issued_at,
            expires_at,
        },
        branch_signature: String::new(),
    }
}

#[test]
fn renewal_is_due_when_absent_below_layer_four_expired_or_half_elapsed() {
    let current = signed(MAX_MESSAGE_LAYER, 1_000, 1_000 + 86_400);
    assert!(renewal_due(None, 1_000), "no declaration must be due");
    assert!(
        renewal_due(Some(&signed(MAX_MESSAGE_LAYER - 1, 1_000, 1_000 + 86_400)), 1_001),
        "a lower layer must be due"
    );
    assert!(!renewal_due(Some(&current), 1_000 + 43_199), "before half of the window is fresh");
    assert!(renewal_due(Some(&current), 1_000 + 43_200), "at half of the window is due");
    assert!(renewal_due(Some(&current), 1_000 + 86_400), "an expired declaration is due");
    let short = signed(MAX_MESSAGE_LAYER, 1_000, 1_000 + 7_200);
    assert!(!renewal_due(Some(&short), 1_000 + 3_599), "half of the ACTUAL signed validity");
    assert!(renewal_due(Some(&short), 1_000 + 3_600), "half of the ACTUAL signed validity");
}

#[test]
fn backoff_doubles_to_a_ceiling_and_clears_on_success() {
    let mut state = LayerPublishState::default();
    assert!(!state.backing_off(), "a fresh state must not back off");
    state.failed();
    assert!(state.backing_off(), "a failure must back off");
    for _ in 0..12 {
        state.failed();
    }
    let until = state.retry_after.expect("test: retry deadline set");
    assert!(
        until <= Instant::now() + BACKOFF_MAX + BACKOFF_MAX / 5 + Duration::from_secs(1),
        "backoff must stay at the ceiling plus bounded jitter"
    );
    state.succeeded();
    assert!(!state.backing_off(), "success must clear the backoff");
}

#[tokio::test]
async fn prepare_uses_one_leased_scope_and_resumes_the_same_candidate() -> TestResult {
    within(async {
        let (mut account, _keep) = live_primary("layer-prepare").await?;
        let plan = prepare(&mut account)?.ok_or("test: first plan")?;
        assert_eq!(
            head_state(&account)?,
            Some(("layer_update".into(), "submitted".into())),
            "the candidate must be durable and marked submitted before any network work"
        );
        let declaration = plan
            .publication
            .record
            .body
            .devices
            .iter()
            .find(|device| device.device_id == "primary")
            .and_then(|device| device.message_layer.as_ref())
            .ok_or("test: candidate declaration")?;
        assert_eq!(declaration.declaration.max_layer, MAX_MESSAGE_LAYER);
        assert_eq!(declaration.declaration.declaration_sequence, 1);
        // The signing barrier was released: a second lease is available at once.
        let born = account.client.born_v3_account.as_deref().ok_or("test: native account")?;
        let config = account.gateway_config.custody.clone().ok_or("test: custody config")?;
        drop(born.group_primary(config.vault.as_ref())?);
        // Crash after the submitted commit: recovery resubmits the very same bytes.
        let again = prepare(&mut account)?.ok_or("test: resumed plan")?;
        assert_eq!(again.expected, plan.expected, "a resume must not mint a second candidate");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn apply_installs_retires_and_renews_at_half_the_signed_validity() -> TestResult {
    within(async {
        let (mut account, _keep) = live_primary("layer-apply").await?;
        let plan = prepare(&mut account)?.ok_or("test: first plan")?;
        let acknowledged = plan.expected.clone();
        apply(&mut account, &plan, acknowledged)?;
        assert_eq!(head_state(&account)?, None, "the journal row must be retired");
        let first = local_declaration(&account).ok_or("test: installed declaration")?;
        assert_eq!(first.declaration.max_layer, MAX_MESSAGE_LAYER);
        let view = status_view(
            account.client.born_v3_account.as_deref().ok_or("test: native account")?,
            custody::network_now()?,
            None,
        );
        assert_eq!(view["state"], "fresh", "status must show the installed declaration");
        assert!(prepare(&mut account)?.is_none(), "a fresh declaration must not renew");
        let half = first.declaration.issued_at
            + (first.declaration.expires_at - first.declaration.issued_at) / 2;
        let _clock = FixedClock::set(i64::try_from(half)?);
        let renewal = prepare(&mut account)?.ok_or("test: renewal plan")?;
        let renewed = renewal
            .publication
            .record
            .body
            .devices
            .iter()
            .find(|device| device.device_id == "primary")
            .and_then(|device| device.message_layer.as_ref())
            .ok_or("test: renewed declaration")?;
        assert_eq!(renewed.declaration.declaration_sequence, 2, "renewal needs a higher sequence");
        assert_eq!(renewed.declaration.issued_at, half, "renewal is signed at the due instant");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn acknowledged_cut_is_settled_before_the_due_check_and_never_blocks_revoke() -> TestResult {
    within(async {
        let (mut account, _keep) = live_primary("layer-cut").await?;
        let plan = prepare(&mut account)?.ok_or("test: first plan")?;
        let submitted = account.client.account_db()?.pairing_head()?.ok_or("test: row")?;
        apply(&mut account, &plan, plan.expected.clone())?;
        // Crash cut between installation and retirement: fresh declaration + acknowledged row.
        let mut acknowledged = submitted.clone();
        acknowledged.state = "acknowledged".into();
        acknowledged.ack = Some(ramflux_protocol::canonical_json_bytes(&serde_json::json!({
            "record_hash": submitted.candidate_hash,
            "device_set_epoch": plan.publication.record.body.device_set_epoch,
        }))?);
        account.client.account_db()?.commit_pairing_head(&acknowledged)?;
        assert!(local_declaration(&account).is_some(), "the declaration is already live");
        // Another head writer meets the pending row: it is settled, not Busy.
        settle_for_other_writer(&mut account)?;
        assert_eq!(head_state(&account)?, None, "the acknowledged layer row must be retired");
        // The same cut seen by the courier: recovery runs before the not-due early return.
        account.client.account_db()?.commit_pairing_head(&acknowledged)?;
        assert!(prepare(&mut account)?.is_none(), "a fresh declaration needs no new plan");
        assert_eq!(head_state(&account)?, None, "recovery must precede the due check");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn prepared_is_discarded_atomically_and_submitted_is_never_discarded() -> TestResult {
    within(async {
        let (mut account, _keep) = live_primary("layer-discard").await?;
        let prepared = stage_prepared(&mut account)?;
        assert_eq!(head_state(&account)?, Some(("layer_update".into(), "prepared".into())));
        // A stale hash or operation never matches the atomic recheck.
        assert!(
            !account
                .client
                .account_db()?
                .discard_prepared_layer_head(&prepared.operation_id, "x")?,
            "a different candidate hash must not discard"
        );
        settle_for_other_writer(&mut account)?;
        assert_eq!(head_state(&account)?, None, "a never-submitted candidate is discarded");
        // A submitted head may exist at the node: another writer must not discard it.
        let _plan = prepare(&mut account)?.ok_or("test: plan after discard")?;
        settle_for_other_writer(&mut account)?;
        assert_eq!(head_state(&account)?, Some(("layer_update".into(), "submitted".into())));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn expired_prepared_candidate_is_rebuilt_not_resubmitted() -> TestResult {
    within(async {
        let (mut account, _keep) = live_primary("layer-expired").await?;
        let prepared = stage_prepared(&mut account)?;
        let candidate = custody::pairing::publication::decode_head_candidate(&prepared.candidate)?;
        let declaration = candidate.record.body.devices[0]
            .message_layer
            .as_ref()
            .ok_or("test: declaration")?
            .declaration
            .expires_at;
        let _clock = FixedClock::set(i64::try_from(declaration + 1)?);
        assert!(prepare(&mut account)?.is_none(), "an expired unsent candidate is discarded");
        assert_eq!(head_state(&account)?, None, "the expired candidate row must be gone");
        Ok(())
    })
    .await
}

/// A scripted writer actor: it serves courier checkpoints exactly like the account actor does.
fn actor(mut account: LocalBusAccountState) -> (Writer, tokio::task::JoinHandle<()>) {
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<AccountWork>(8);
    let task = tokio::task::spawn_local(async move {
        while let Some(work) = receiver.recv().await {
            if let AccountWork::Courier(checkpoint) = work {
                checkpoint.apply(&mut account);
            }
        }
    });
    (Writer::new(sender, 1), task)
}

#[tokio::test]
async fn held_publish_leaves_the_actor_free_and_cancel_loses_nothing() -> TestResult {
    let local = tokio::task::LocalSet::new();
    within(local.run_until(async {
        let (account, _keep) = live_primary("layer-barrier").await?;
        let (writer, actor_task) = actor(account);
        let started = Arc::new(tokio::sync::Notify::new());
        let held = {
            let (writer, started) = (writer.clone(), Arc::clone(&started));
            tokio::spawn(async move {
                pass_with(writer, move |_input| async move {
                    started.notify_one();
                    std::future::pending::<Result<String, SdkError>>().await
                })
                .await
            })
        };
        started.notified().await;
        // Floor-send stand-in: an ordinary writer step completes while Publish is held.
        // A blocked actor would hang here until the watchdog fails the test.
        let state = writer
            .apply(|account| head_state(account).map_err(|_| SdkError::NetworkingPending))
            .await?;
        assert_eq!(state, Some(("layer_update".into(), "submitted".into())));
        // No signing lease or lock is held across the await.
        writer
            .apply(|account| {
                let born =
                    account.client.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
                let vault = account
                    .gateway_config
                    .custody
                    .clone()
                    .ok_or(SdkError::NetworkingPending)?
                    .vault;
                // A lock held across the await would answer Busy here.
                drop(born.group_primary(vault.as_ref())?);
                Ok(())
            })
            .await?;
        // Lock/Stop: the courier is dropped at its await; the submitted row survives.
        held.abort();
        let _ = held.await;
        let resumed = writer
            .apply(|account| {
                let plan = prepare(account)?.ok_or(SdkError::NetworkingPending)?;
                Ok(plan.expected.clone())
            })
            .await?;
        let finished = pass_with(writer.clone(), |input| async move {
            Ok(object_hash(&input.publication.record)?)
        })
        .await?;
        assert!(finished, "the resumed candidate must complete");
        let (after, expected) = writer
            .apply(move |account| {
                Ok((head_state(account).map_err(|_| SdkError::NetworkingPending)?, resumed))
            })
            .await?;
        assert_eq!(after, None, "the resumed head must be retired");
        assert!(!expected.is_empty(), "the resumed candidate hash must exist");
        actor_task.abort();
        Ok(())
    }))
    .await
}

/// A crash at every durable step of the local installation (pending marker, authority file,
/// authority-durable marker, DB adoption) must not lock the account out: unlock repairs the exact
/// acknowledged installation before admission. Real filesystem and real encrypted store.
#[tokio::test]
async fn crash_inside_local_installation_recovers_on_unlock() -> TestResult {
    within(async {
        for step in 1..=4_u8 {
            let (mut account, _keep) = live_primary(&format!("layer-cut-{step}")).await?;
            let config = account.gateway_config.custody.clone().ok_or("test: custody config")?;
            let id = account.client.account_db()?.local_account_id.clone();
            let plan = prepare(&mut account)?.ok_or("test: plan")?;
            custody::pairing::activate::CUT.with(|cell| cell.set(step));
            let crashed = apply(&mut account, &plan, plan.expected.clone());
            assert!(
                matches!(crashed, Err(SdkError::PairingCode("InjectedCut"))),
                "step {step}: the injected cut must stop the installation: {crashed:?}"
            );
            drop(account);
            // Process restart: a new client over the same files.
            let mut client = crate::RamfluxClient::new();
            client.open_account_index(&config.account_root)?;
            client.unlock_account(&id, b"native fixture data passphrase")?;
            assert!(
                !custody::pairing::recipient::ordinary_session_admitted(&client, &id)?,
                "step {step}: the pending marker must hold admission until repaired"
            );
            repair_on_unlock(&mut client, &config.account_root, &id, config.vault.as_ref())?;
            assert!(
                custody::pairing::recipient::ordinary_session_admitted(&client, &id)?,
                "step {step}: unlock repair must restore admission"
            );
            assert!(client.account_db()?.pairing_head()?.is_none(), "step {step}: row retired");
            let installed = client
                .born_v3_account
                .as_deref()
                .and_then(|born| born.record().body.devices.first())
                .and_then(|device| device.message_layer.as_ref());
            assert!(installed.is_some(), "step {step}: the new declaration must be installed");
        }
        Ok(())
    })
    .await
}

/// The discard is serialized with the publication locks: a competing holder of the authority
/// lock makes it refuse (Busy after its own bounded wait) and the row stays.
#[tokio::test]
async fn discard_waits_for_the_publication_lock_and_never_removes_a_submitted_row() -> TestResult {
    within(async {
        let (mut account, _keep) = live_primary("layer-discard-lock").await?;
        let config = account.gateway_config.custody.clone().ok_or("test: custody config")?;
        let id = account.client.account_db()?.local_account_id.clone();
        let prepared = stage_prepared(&mut account)?;
        let holder = custody::pairing::activate::authority_lock(&config.account_root, &id)?;
        let blocked = custody::pairing::publication::discard_prepared_layer(
            account.client.account_db()?,
            &config.account_root,
            &id,
            &prepared.operation_id,
            &prepared.candidate_hash,
        );
        assert!(
            matches!(blocked, Err(SdkError::PairingCode("Busy"))),
            "a competing lock holder must serialize the discard: {blocked:?}"
        );
        assert_eq!(head_state(&account)?, Some(("layer_update".into(), "prepared".into())));
        drop(holder);
        assert!(
            custody::pairing::publication::discard_prepared_layer(
                account.client.account_db()?,
                &config.account_root,
                &id,
                &prepared.operation_id,
                &prepared.candidate_hash,
            )?,
            "with the lock free the never-submitted row is discarded"
        );
        // Submission re-reads the row under one lock scope: a submitted row is never discarded.
        let _plan = prepare(&mut account)?.ok_or("test: plan")?;
        let submitted = account.client.account_db()?.pairing_head()?.ok_or("test: row")?;
        assert!(
            !custody::pairing::publication::discard_prepared_layer(
                account.client.account_db()?,
                &config.account_root,
                &id,
                &submitted.operation_id,
                &submitted.candidate_hash,
            )?,
            "a submitted row must never be discarded"
        );
        Ok(())
    })
    .await
}

/// L1: the certificate cutoff is a typed, visible failure, not only a log line.
#[tokio::test]
async fn certificate_cutoff_is_reported_as_a_typed_status_error() -> TestResult {
    within(async {
        let (mut account, _keep) = live_primary("layer-cutoff").await?;
        let born = account.client.born_v3_account.as_deref().ok_or("test: native")?;
        let expiry = born.record().body.devices[0]
            .branch_certificate
            .as_ref()
            .ok_or("test: certificate")?
            .body
            .expires_at;
        let _clock = FixedClock::set(i64::try_from(expiry - 3_600)?);
        assert!(prepare(&mut account)?.is_none(), "a certificate near expiry must not publish");
        let stored = account
            .client
            .account_db()?
            .load_actor_state::<Option<String>>(LAST_ERROR_KEY)?
            .flatten();
        assert_eq!(
            stored.as_deref(),
            Some("LayerRenewalBlocked"),
            "the cutoff must be retained as a typed failure"
        );
        let view = status_view(
            account.client.born_v3_account.as_deref().ok_or("test: native")?,
            custody::network_now()?,
            stored.as_deref(),
        );
        assert_eq!(view["last_error_code"], "LayerRenewalBlocked", "status must carry the code");
        Ok(())
    })
    .await
}

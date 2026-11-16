// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publication of the primary device's own layer-4 message-layer declaration.
//!
//! One courier pass is Writer Prepare (sync, short, no network) -> off-actor Publish (bounded
//! deadline, no lock, no database handle, no key) -> Writer Apply (conditional on the session).
//! Sends never wait on it: the actor is only held for Prepare and Apply.
use crate::bus::connection_manager::SessionContext;
use crate::bus::couriers::writer::Writer;
use crate::bus::dispatch::device::native_revoke::{NativeAck, observe_published, with_db};
use crate::bus::state::LocalBusAccountState;
use crate::custody::{
    self, CustodyConnection, DeclarationValidity,
    pairing::{HeadKind, HeadWrite, PairingNative, ProofPairingNative, PublishedHead},
};
use crate::{GatewaySessionConfig, SdkError};
use ramflux_protocol::custody::{
    MAX_MESSAGE_LAYER, Publication, SignedLayerDeclaration, object_hash,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) const COURIER: &str = "layer-publish";
/// Longest validity the node and verifiers accept for one declaration.
const MAX_VALIDITY_SECONDS: u64 = 24 * 60 * 60;
/// A certificate that leaves less than this cannot carry a useful declaration.
const MIN_REMAINING_SECONDS: u64 = 2 * 60 * 60;
const PUBLISH_DEADLINE: Duration = Duration::from_secs(30);
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);

/// Per-account retry scheduling. Lives on the writer; never crosses an await.
#[derive(Default)]
pub(crate) struct LayerPublishState {
    retry_after: Option<Instant>,
    failures: u32,
}

impl LayerPublishState {
    fn backing_off(&self) -> bool {
        self.retry_after.is_some_and(|until| until > Instant::now())
    }
    fn failed(&mut self) {
        self.failures = self.failures.saturating_add(1);
        let shift = self.failures.saturating_sub(1).min(5);
        let base = BACKOFF_BASE.saturating_mul(1 << shift).min(BACKOFF_MAX);
        let jitter = ramflux_crypto::random_32()
            .ok()
            .map_or(0, |bytes| u64::from(bytes[0]) * base.as_secs() / 1280);
        self.retry_after = Some(Instant::now() + base + Duration::from_secs(jitter));
    }
    fn succeeded(&mut self) {
        self.failures = 0;
        self.retry_after = None;
    }
}

/// `rf status` view of the local device's declaration, derived from the verified record.
/// Codes only; no key material.
#[must_use]
pub(crate) fn status_view(account: &custody::BornAccount, now: u64) -> serde_json::Value {
    let declaration = account
        .local_device_id()
        .ok()
        .and_then(|local| {
            account.record().body.devices.iter().find(|device| device.device_id == local)
        })
        .and_then(|device| device.message_layer.as_ref());
    let state = match declaration {
        None => "absent",
        Some(signed) if now >= signed.declaration.expires_at => "expired",
        Some(_) if renewal_due(declaration, now) => "renewing",
        Some(_) => "fresh",
    };
    serde_json::json!({
        "state": state,
        "max_layer": declaration.map(|signed| signed.declaration.max_layer),
        "expires_at": declaration.map(|signed| signed.declaration.expires_at),
    })
}

fn error_code(error: &SdkError) -> &'static str {
    match error {
        SdkError::PairingCode(code) => code,
        SdkError::NetworkingPending => "NetworkingPending",
        _ => "PublishFailed",
    }
}

/// The signed-off exchange for one candidate; all fields are public bytes or handles.
pub(crate) struct Plan {
    publication: Publication,
    expected: String,
    write: HeadWrite,
    config: GatewaySessionConfig,
    vault: Arc<dyn custody::PrimaryVault>,
}

/// Renewal is due when no declaration exists, it is not layer 4, or half of its signed
/// validity has elapsed.
#[must_use]
pub(crate) fn renewal_due(current: Option<&SignedLayerDeclaration>, now: u64) -> bool {
    let Some(signed) = current else { return true };
    let declaration = &signed.declaration;
    if declaration.max_layer != MAX_MESSAGE_LAYER || now >= declaration.expires_at {
        return true;
    }
    let validity = declaration.expires_at.saturating_sub(declaration.issued_at);
    now >= declaration.issued_at.saturating_add(validity / 2)
}

fn not_ready(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::NetworkingPending
            | SdkError::AccountDbNotUnlocked
            | SdkError::PairingCode("PrimaryRequired" | "Busy" | "PublicationPending")
    )
}

/// Public bytes and handles the off-actor Publish needs; no key, lock or database handle.
pub(crate) struct PublishInput {
    publication: Publication,
    config: GatewaySessionConfig,
    vault: Arc<dyn custody::PrimaryVault>,
}

/// One courier pass. Returns whether work was done (the runner then re-polls quickly).
pub(crate) async fn pass(_context: SessionContext, writer: Writer) -> Result<bool, SdkError> {
    pass_with(writer, publish).await
}

pub(crate) async fn pass_with<F, Fut>(writer: Writer, publisher: F) -> Result<bool, SdkError>
where
    F: FnOnce(PublishInput) -> Fut,
    Fut: std::future::Future<Output = Result<String, SdkError>>,
{
    let plan = match writer.apply(|account| prepare(account)).await {
        Ok(plan) => plan,
        Err(error) if not_ready(&error) => return Ok(false),
        Err(error) => {
            tracing::debug!(code = error_code(&error), "layer declaration prepare deferred");
            let _ = writer
                .apply(|account| {
                    account.layer_publish.failed();
                    Ok(())
                })
                .await;
            return Err(error);
        }
    };
    let Some(plan) = plan else { return Ok(false) };
    let input = PublishInput {
        publication: plan.publication.clone(),
        config: plan.config.clone(),
        vault: Arc::clone(&plan.vault),
    };
    let outcome = match tokio::time::timeout(PUBLISH_DEADLINE, publisher(input)).await {
        Ok(result) => result,
        Err(_) => Err(SdkError::PairingCode("PublishTimeout")),
    };
    let result = match outcome {
        Ok(acknowledged) => writer.apply(move |account| apply(account, &plan, acknowledged)).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => Ok(true),
        Err(error) => {
            tracing::debug!(code = error_code(&error), "layer declaration publish deferred");
            let _ = writer
                .apply(|account| {
                    account.layer_publish.failed();
                    Ok(())
                })
                .await;
            Err(error)
        }
    }
}

/// Writer Prepare. Recovery of a pending layer head always runs first, before the due check.
pub(crate) fn prepare(account: &mut LocalBusAccountState) -> Result<Option<Box<Plan>>, SdkError> {
    let Some(config) = account.gateway_config.custody.clone() else { return Ok(None) };
    let Some(born) = account.client.born_v3_account.as_deref() else { return Ok(None) };
    let local = born.local_device_id()?.to_owned();
    if born.record().body.master_certificate.body.primary_device_ref.device_id != local {
        return Ok(None);
    }
    if account.layer_publish.backing_off() {
        return Ok(None);
    }
    let now = custody::network_now()?;
    if let Some(head) = account.client.account_db()?.pairing_head()? {
        if head.kind != "layer_update" {
            return Ok(None);
        }
        return resume(account, &config, head, now);
    }
    let born = account.client.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
    let record = born.record();
    let device = record
        .body
        .devices
        .iter()
        .find(|device| device.device_id == local)
        .ok_or(SdkError::NetworkingPending)?;
    let certificate_expiry =
        device.branch_certificate.as_ref().ok_or(SdkError::NetworkingPending)?.body.expires_at;
    if !renewal_due(device.message_layer.as_ref(), now) {
        return Ok(None);
    }
    let issued_at = now.max(record.body.issued_at.saturating_add(1));
    let expires_at = issued_at.saturating_add(MAX_VALIDITY_SECONDS).min(certificate_expiry);
    if expires_at < issued_at.saturating_add(MIN_REMAINING_SECONDS) {
        tracing::warn!("layer declaration renewal blocked: branch certificate too close to expiry");
        return Ok(None);
    }
    let operation_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let validity = DeclarationValidity { issued_at, expires_at };
    let write = layer_write(account, &config, operation_id, validity)?;
    submit(account, &config, write)
}

fn layer_write(
    account: &LocalBusAccountState,
    config: &crate::gateway::GatewayCustodyConfig,
    operation_id: String,
    validity: DeclarationValidity,
) -> Result<HeadWrite, SdkError> {
    let born = account.client.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
    let local = born.record().body.master_certificate.body.primary_device_ref.clone();
    Ok(HeadWrite {
        account_id: config.account_id.clone(),
        operation_id,
        invitation_id: None,
        generation: 1,
        issuer_seq: 0,
        local_seq: 0,
        kind: HeadKind::Layer(validity),
        publisher_ref: local.clone(),
        local_ref: local,
        recipient_ref: None,
        revoked_id: None,
        certificate: None,
        display_name: None,
        now: validity.issued_at,
        branch_vault_ref: born.branch_vault_ref().into(),
        data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(&config.account_id),
        primary_vault_ref: Some(born.primary_vault_ref().into()),
    })
}

/// Prepare and durably mark the exact candidate submitted before any network work.
fn submit(
    account: &mut LocalBusAccountState,
    config: &crate::gateway::GatewayCustodyConfig,
    write: HeadWrite,
) -> Result<Option<Box<Plan>>, SdkError> {
    let publication = custody::pairing::publication::prepare_head_submission_in(
        account.client.account_db()?,
        &config.account_root,
        config.vault.as_ref(),
        &write,
    )?;
    let expected = object_hash(&publication.record)?;
    Ok(Some(Box::new(Plan {
        publication,
        expected,
        write,
        config: account.gateway_config.clone(),
        vault: Arc::clone(&config.vault),
    })))
}

/// Finish whatever step a crash left behind. Acknowledged heads complete locally; prepared or
/// submitted heads resubmit the same bytes (the node is idempotent by hash).
fn resume(
    account: &mut LocalBusAccountState,
    config: &crate::gateway::GatewayCustodyConfig,
    head: ramflux_storage::HeadRow,
    now: u64,
) -> Result<Option<Box<Plan>>, SdkError> {
    let candidate: Publication = ramflux_protocol::parse_i_json(&head.candidate)
        .map_err(|_| SdkError::PairingField("candidate"))?;
    let local = account
        .client
        .born_v3_account
        .as_deref()
        .ok_or(SdkError::NetworkingPending)?
        .local_device_id()?
        .to_owned();
    let declared_expiry = candidate
        .record
        .body
        .devices
        .iter()
        .find(|device| device.device_id == local)
        .and_then(|device| device.message_layer.as_ref())
        .map_or(0, |signed| signed.declaration.expires_at);
    if head.state == "prepared"
        && declared_expiry <= now
        && account
            .client
            .account_db()?
            .discard_prepared_layer_head(&head.operation_id, &head.candidate_hash)?
    {
        // A candidate that never left this device and is already expired is rebuilt next pass.
        return Ok(None);
    }
    let validity = DeclarationValidity { issued_at: now, expires_at: declared_expiry };
    let write = layer_write(account, config, head.operation_id.clone(), validity)?;
    if head.state == "acknowledged" {
        let hash = head.candidate_hash.clone();
        finish(account, config, &write, hash.clone(), hash)?;
        return Ok(None);
    }
    submit(account, config, write)
}

/// Called by another head writer before it would answer `Busy` on a pending layer head. A head
/// that never left this device is discarded after an atomic recheck; an acknowledged head is
/// completed locally. A submitted head stays: the node may hold it, so the layer courier
/// resubmits the same bytes first.
pub(crate) fn settle_for_other_writer(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    let Some(config) = account.gateway_config.custody.clone() else { return Ok(()) };
    let Some(head) = account.client.account_db()?.pairing_head()? else { return Ok(()) };
    if head.kind != "layer_update" {
        return Ok(());
    }
    match head.state.as_str() {
        "prepared" => {
            account
                .client
                .account_db()?
                .discard_prepared_layer_head(&head.operation_id, &head.candidate_hash)?;
        }
        "acknowledged" => {
            let now = custody::network_now()?;
            resume(account, &config, head, now)?;
        }
        _ => {}
    }
    Ok(())
}

async fn publish(input: PublishInput) -> Result<String, SdkError> {
    let mut network = crate::gateway::proof_network_config(&input.config)?;
    network.gateway_address = input.config.tcp_gateway_addr.unwrap_or(input.config.gateway_addr);
    let connection = CustodyConnection::connect_for_proof(network, input.vault).await?;
    let native = ProofPairingNative::from_connection(Arc::new(tokio::sync::Mutex::new(connection)));
    native.publish(input.publication).await
}

/// Writer Apply. A stale session never reaches here: the courier checkpoint carries the
/// connection generation and the writer drops it, leaving the `submitted` row for recovery.
fn apply(
    account: &mut LocalBusAccountState,
    plan: &Plan,
    acknowledged: String,
) -> Result<(), SdkError> {
    let config = account.gateway_config.custody.clone().ok_or(SdkError::NetworkingPending)?;
    finish(account, &config, &plan.write, plan.expected.clone(), acknowledged)
}

fn finish(
    account: &mut LocalBusAccountState,
    config: &crate::gateway::GatewayCustodyConfig,
    write: &HeadWrite,
    expected: String,
    acknowledged: String,
) -> Result<(), SdkError> {
    if acknowledged != expected {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    let receipt = NativeAck { expected, acknowledged };
    let published: PublishedHead = with_db(account, |db| {
        custody::pairing::publish_head(
            db,
            &config.account_root,
            config.vault.as_ref(),
            write,
            &receipt,
        )
    })?;
    observe_published(account, &config.account_root, &published)?;
    let id = account.client.account_db()?.local_account_id.clone();
    account.client.born_v3_account = Some(Box::new(custody::load_account(
        account.client.account_index()?.root(),
        &id,
        custody::network_now()?,
    )?));
    // The own roster carries the new declaration; refresh it through the bounded queue.
    let own = account.principal_commitment.clone();
    let _ = account.head_refresh.enqueue(own);
    account.layer_publish.succeeded();
    Ok(())
}

#[cfg(test)]
mod tests;

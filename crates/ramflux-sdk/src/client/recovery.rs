// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]

use crate::prelude::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkRecoveryQuorumMember {
    pub member_kind: ramflux_protocol::RecoveryQuorumMemberKind,
    pub signing_key_id: String,
    pub public_key_base64url: String,
}

impl SdkRecoveryQuorumMember {
    #[must_use]
    pub fn commitment(&self) -> ramflux_protocol::RecoveryQuorumMemberCommitment {
        ramflux_protocol::RecoveryQuorumMemberCommitment {
            member_kind: self.member_kind.clone(),
            signing_key_id: self.signing_key_id.clone(),
            public_key_base64url: self.public_key_base64url.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkRecoveryQuorumConfiguration {
    pub recovery_quorum: ramflux_protocol::RecoveryQuorumConfigured,
    pub shares: Vec<ramflux_crypto::RecoveryShare>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub struct SdkGuardianRecoveryShare {
    pub share_id: u8,
    pub threshold: u8,
    pub total: u8,
    pub member_kind: ramflux_protocol::RecoveryQuorumMemberKind,
    pub value_base64: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SdkGuardianInviteMessage {
    pub schema: String,
    pub version: u32,
    pub invite_id: String,
    pub inviter_principal_id: String,
    pub inviter_device_id: String,
    pub inviter_device_epoch: u64,
    pub inviter_device_public_key_base64url: String,
    pub guardian_principal_id: String,
    pub recovery_quorum_id: String,
    pub share: SdkGuardianRecoveryShare,
    pub issued_at: i64,
    pub expires_at: i64,
    #[serde(flatten)]
    pub signed: ramflux_protocol::SignedFields,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SdkGuardianAcceptMessage {
    pub schema: String,
    pub version: u32,
    pub accept_id: String,
    pub invite_id: String,
    pub owner_principal_id: String,
    pub guardian_principal_id: String,
    pub guardian_device_id: String,
    pub guardian_device_epoch: u64,
    pub guardian_device_public_key_base64url: String,
    pub recovery_quorum_id: String,
    pub accepted_at: i64,
    #[serde(flatten)]
    pub signed: ramflux_protocol::SignedFields,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SdkPendingRecoveryState {
    Initiated,
    TimelockStarted,
    CollectingApprovals,
    QuorumReached,
    ReadyToFinalize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkRecoveryInitiateRequest {
    pub recovery_id: String,
    pub owner_principal_id: String,
    pub recovery_quorum: ramflux_protocol::RecoveryQuorumConfigured,
    pub lifecycle_epoch: u64,
    pub lineage_head: Option<String>,
    pub timelock_until: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkPendingRecoveryStatus {
    pub recovery_id: String,
    pub owner_principal_id: String,
    pub recovery_quorum_id: String,
    pub state: SdkPendingRecoveryState,
    pub approvals_collected: usize,
    pub threshold: u8,
    pub timelock_until: Option<u64>,
    pub ready_to_finalize: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkFinalizedRecovery {
    pub recovery_id: String,
    pub recovery_quorum: ramflux_protocol::RecoveryQuorumConfigured,
    pub proof: ramflux_protocol::RecoveryQuorumProof,
}

impl SdkRecoveryQuorumConfiguration {
    #[must_use]
    pub fn lineage_event_body(&self) -> ramflux_protocol::IdentityEventBody {
        ramflux_protocol::IdentityEventBody::RecoveryQuorumConfigured {
            recovery_quorum: self.recovery_quorum.clone(),
        }
    }
}

impl RamfluxClient {
    /// Creates a k-of-n recovery quorum configuration and Shamir shares for member distribution.
    ///
    /// The returned `recovery_quorum` is the lineage event payload that records public member
    /// commitments. The returned shares remain client-side secret material; callers must deliver
    /// them to the corresponding members out of band.
    pub fn configure_recovery_quorum(
        recovery_quorum_id: &str,
        recovery_secret: [u8; 32],
        threshold: u8,
        members: &[SdkRecoveryQuorumMember],
    ) -> Result<SdkRecoveryQuorumConfiguration, SdkError> {
        configure_recovery_quorum(recovery_quorum_id, recovery_secret, threshold, members)
    }

    /// Builds one member's signed approval for a recovery context.
    pub fn approve_recovery(
        member_kind: ramflux_protocol::RecoveryQuorumMemberKind,
        signing_key_id: &str,
        member_signing_seed: [u8; 32],
        context: &ramflux_protocol::RecoveryApprovalContext,
    ) -> Result<ramflux_protocol::RecoveryApproval, SdkError> {
        approve_recovery(member_kind, signing_key_id, member_signing_seed, context)
    }

    /// Collects signed approvals into a recovery quorum proof.
    #[must_use]
    pub fn build_recovery_proof(
        context: ramflux_protocol::RecoveryApprovalContext,
        approvals: Vec<ramflux_protocol::RecoveryApproval>,
    ) -> ramflux_protocol::RecoveryQuorumProof {
        build_recovery_proof(context, approvals)
    }

    /// Builds a signed guardian invite control message whose plaintext is intended to travel
    /// inside the existing E2EE DM/contact channel.
    pub fn invite_guardian(
        &self,
        invite_id: &str,
        recovery_quorum_id: &str,
        guardian_principal_id: &str,
        share: &ramflux_crypto::RecoveryShare,
        expires_at: i64,
    ) -> Result<SdkGuardianInviteMessage, SdkError> {
        invite_guardian(
            self,
            invite_id,
            recovery_quorum_id,
            guardian_principal_id,
            share,
            expires_at,
        )
    }

    /// Verifies an inbound guardian invite, stores the shard locally, and returns a signed accept
    /// response that callers can send back through the same E2EE channel.
    pub fn accept_guardian_invite(
        &self,
        invite: &SdkGuardianInviteMessage,
    ) -> Result<SdkGuardianAcceptMessage, SdkError> {
        accept_guardian_invite(self, invite)
    }

    /// Returns guardian shares stored locally for a recovery owner.
    pub fn guardian_recovery_shares_for_owner(
        &self,
        owner_principal_id: &str,
    ) -> Result<Vec<GuardianRecoveryShareRecord>, SdkError> {
        Ok(self.account_db()?.guardian_recovery_shares_for_owner(owner_principal_id)?)
    }

    /// Creates a pending social recovery record in the initial state.
    pub fn initiate_recovery(
        &self,
        request: &SdkRecoveryInitiateRequest,
    ) -> Result<SdkPendingRecoveryStatus, SdkError> {
        initiate_recovery(self, request)
    }

    /// Moves a pending recovery from `initiated` to `timelock_started`.
    pub fn start_recovery_timelock(
        &self,
        recovery_id: &str,
    ) -> Result<SdkPendingRecoveryStatus, SdkError> {
        transition_recovery_state(
            self,
            recovery_id,
            SdkPendingRecoveryState::Initiated,
            SdkPendingRecoveryState::TimelockStarted,
            Some(now_unix_timestamp()),
        )
    }

    /// Moves a pending recovery from `timelock_started` to `collecting_approvals`.
    pub fn begin_recovery_approval_collection(
        &self,
        recovery_id: &str,
    ) -> Result<SdkPendingRecoveryStatus, SdkError> {
        transition_recovery_state(
            self,
            recovery_id,
            SdkPendingRecoveryState::TimelockStarted,
            SdkPendingRecoveryState::CollectingApprovals,
            None,
        )
    }

    /// Builds a guardian approval after checking the guardian has the accepted shard locally.
    pub fn guardian_approve_recovery(
        &self,
        owner_principal_id: &str,
        recovery_quorum_id: &str,
        context: &ramflux_protocol::RecoveryApprovalContext,
    ) -> Result<ramflux_protocol::RecoveryApproval, SdkError> {
        guardian_approve_recovery(self, owner_principal_id, recovery_quorum_id, context)
    }

    /// Records a non-guardian or guardian approval against a pending recovery.
    pub fn collect_recovery_approval(
        &self,
        recovery_id: &str,
        approval: &ramflux_protocol::RecoveryApproval,
    ) -> Result<SdkPendingRecoveryStatus, SdkError> {
        collect_recovery_approval(self, recovery_id, approval)
    }

    /// Records a guardian approval, refusing non-guardian approvals on this entry point.
    pub fn collect_guardian_approval(
        &self,
        recovery_id: &str,
        approval: &ramflux_protocol::RecoveryApproval,
    ) -> Result<SdkPendingRecoveryStatus, SdkError> {
        if approval.member_kind != ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare {
            return Err(SdkError::LocalBus(
                "collect_guardian_approval requires guardian_share approval".to_owned(),
            ));
        }
        collect_recovery_approval(self, recovery_id, approval)
    }

    /// Returns the current pending recovery state.
    pub fn recovery_state(&self, recovery_id: &str) -> Result<SdkPendingRecoveryStatus, SdkError> {
        recovery_state(self, recovery_id)
    }

    /// Finalizes local quorum collection and returns a proof ready for the lifecycle endpoint.
    pub fn finalize_recovery(&self, recovery_id: &str) -> Result<SdkFinalizedRecovery, SdkError> {
        finalize_recovery(self, recovery_id)
    }
}

/// Creates a k-of-n recovery quorum configuration and Shamir shares for member distribution.
///
/// # Errors
/// Returns an error when the threshold/member count is invalid or Shamir share generation fails.
pub fn configure_recovery_quorum(
    recovery_quorum_id: &str,
    recovery_secret: [u8; 32],
    threshold: u8,
    members: &[SdkRecoveryQuorumMember],
) -> Result<SdkRecoveryQuorumConfiguration, SdkError> {
    let total = u8::try_from(members.len()).map_err(|_source| {
        SdkError::LocalBus("recovery quorum member count exceeds u8 range".to_owned())
    })?;
    let mut shares = ramflux_crypto::create_recovery_quorum(recovery_secret, threshold, total)?;
    for (share, member) in shares.iter_mut().zip(members) {
        share.member_kind = Some(to_crypto_member_kind(&member.member_kind));
    }
    let recovery_quorum = ramflux_protocol::RecoveryQuorumConfigured {
        recovery_quorum_id: recovery_quorum_id.to_owned(),
        threshold,
        total,
        members: members
            .iter()
            .map(|member| ramflux_protocol::RecoveryQuorumMemberCommitment {
                member_kind: member.member_kind.clone(),
                signing_key_id: member.signing_key_id.clone(),
                public_key_base64url: member.public_key_base64url.clone(),
            })
            .collect(),
    };
    Ok(SdkRecoveryQuorumConfiguration { recovery_quorum, shares })
}

/// Builds one member's signed approval for a recovery context.
///
/// # Errors
/// Returns an error when the recovery context cannot be canonicalized or signed.
pub fn approve_recovery(
    member_kind: ramflux_protocol::RecoveryQuorumMemberKind,
    signing_key_id: &str,
    member_signing_seed: [u8; 32],
    context: &ramflux_protocol::RecoveryApprovalContext,
) -> Result<ramflux_protocol::RecoveryApproval, SdkError> {
    Ok(ramflux_protocol::RecoveryApproval {
        member_kind,
        signing_key_id: signing_key_id.to_owned(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: ramflux_crypto::sign_protocol_object_with_seed(context, member_signing_seed)?,
    })
}

#[must_use]
pub fn build_recovery_proof(
    context: ramflux_protocol::RecoveryApprovalContext,
    approvals: Vec<ramflux_protocol::RecoveryApproval>,
) -> ramflux_protocol::RecoveryQuorumProof {
    ramflux_protocol::RecoveryQuorumProof { context, approvals }
}

/// Creates a pending recovery in the initial state.
///
/// # Errors
/// Returns an error when the quorum is malformed or the pending record cannot be stored.
pub fn initiate_recovery(
    client: &RamfluxClient,
    request: &SdkRecoveryInitiateRequest,
) -> Result<SdkPendingRecoveryStatus, SdkError> {
    validate_recovery_quorum_shape(&request.recovery_quorum)?;
    let context = ramflux_protocol::RecoveryApprovalContext {
        recovery_id: request.recovery_id.clone(),
        event_type: "identity.reactivated".to_owned(),
        principal_id: request.owner_principal_id.clone(),
        lifecycle_epoch: request.lifecycle_epoch,
        lineage_head: request.lineage_head.clone(),
        timelock_until: request.timelock_until,
    };
    client.account_db()?.create_pending_recovery(&PendingRecoveryWrite {
        recovery_id: &request.recovery_id,
        owner_principal_id: &request.owner_principal_id,
        recovery_quorum: &request.recovery_quorum,
        lifecycle_epoch: request.lifecycle_epoch,
        lineage_head: request.lineage_head.as_deref(),
        event_type: "identity.reactivated",
        timelock_until: request.timelock_until,
        context: &context,
    })?;
    append_identity_event_if_missing(
        client,
        &format!("recovery:{}:initiated", request.recovery_id),
        "recovery.initiated",
        &ramflux_protocol::IdentityEventBody::RecoveryInitiated {
            recovery_id: request.recovery_id.clone(),
            identity_commitment: request.owner_principal_id.clone(),
            lifecycle_epoch: request.lifecycle_epoch,
            previous_lineage_head: request.lineage_head.clone(),
            timelock_until: request.timelock_until,
        },
    )?;
    recovery_state(client, &request.recovery_id)
}

/// Builds a guardian recovery approval from a locally accepted guardian shard.
///
/// # Errors
/// Returns an error when the local account is not a guardian for the owner/quorum or signing fails.
pub fn guardian_approve_recovery(
    client: &RamfluxClient,
    owner_principal_id: &str,
    recovery_quorum_id: &str,
    context: &ramflux_protocol::RecoveryApprovalContext,
) -> Result<ramflux_protocol::RecoveryApproval, SdkError> {
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let Some(share) = client.account_db()?.guardian_recovery_share(
        owner_principal_id,
        recovery_quorum_id,
        &branch.principal_id,
    )?
    else {
        return Err(SdkError::LocalBus(format!(
            "guardian share missing for owner {owner_principal_id} quorum {recovery_quorum_id}"
        )));
    };
    if share.state != "accepted" {
        return Err(SdkError::LocalBus(format!("guardian share is not accepted: {}", share.state)));
    }
    if context.principal_id != owner_principal_id {
        return Err(SdkError::LocalBus("guardian approval context owner mismatch".to_owned()));
    }
    Ok(ramflux_protocol::RecoveryApproval {
        member_kind: ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
        signing_key_id: format!("device:{}", branch.device_id),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: ramflux_crypto::sign_protocol_object_with_device_branch(branch, context)?,
    })
}

/// Records an approval and advances to `quorum_reached` exactly when threshold is met.
///
/// # Errors
/// Returns an error when the pending recovery is not collecting approvals, the approval is invalid,
/// or the member already approved.
pub fn collect_recovery_approval(
    client: &RamfluxClient,
    recovery_id: &str,
    approval: &ramflux_protocol::RecoveryApproval,
) -> Result<SdkPendingRecoveryStatus, SdkError> {
    let pending = pending_recovery_required(client, recovery_id)?;
    let state = parse_pending_recovery_state(&pending.state)?;
    if state != SdkPendingRecoveryState::CollectingApprovals {
        return Err(SdkError::LocalBus(format!(
            "pending recovery {recovery_id} is not collecting approvals"
        )));
    }
    validate_recovery_approval_against_quorum(
        &pending.context,
        &pending.recovery_quorum,
        approval,
    )?;
    client.account_db()?.record_pending_recovery_approval(&PendingRecoveryApprovalWrite {
        recovery_id,
        approval,
        approved_at: now_unix_timestamp(),
    })?;
    append_identity_event_if_missing(
        client,
        &format!("recovery:{recovery_id}:approval:{}", approval.signing_key_id),
        "recovery.approval_collected",
        &ramflux_protocol::IdentityEventBody::RecoveryApprovalCollected {
            recovery_id: recovery_id.to_owned(),
            signing_key_id: approval.signing_key_id.clone(),
            member_kind: approval.member_kind.clone(),
        },
    )?;
    let approval_count = client.account_db()?.pending_recovery_approvals(recovery_id)?.len();
    if approval_count >= usize::from(pending.recovery_quorum.threshold) {
        let status = transition_recovery_state(
            client,
            recovery_id,
            SdkPendingRecoveryState::CollectingApprovals,
            SdkPendingRecoveryState::QuorumReached,
            None,
        )?;
        let approvals = client.account_db()?.pending_recovery_approvals(recovery_id)?;
        let proof = ramflux_protocol::RecoveryQuorumProof {
            context: pending.context.clone(),
            approvals: approvals.into_iter().map(|record| record.approval).collect(),
        };
        append_identity_event_if_missing(
            client,
            &format!("recovery:{recovery_id}:authorized"),
            "identity.recovery_authorized",
            &ramflux_protocol::IdentityEventBody::RecoveryAuthorized {
                recovery_id: recovery_id.to_owned(),
                new_device_id: current_recovery_device_id(client)?,
                recovery_method: "social_quorum".to_owned(),
                recovery_quorum_proof: proof,
            },
        )?;
        Ok(status)
    } else {
        recovery_state(client, recovery_id)
    }
}

/// Returns the current pending recovery state.
///
/// # Errors
/// Returns an error when the recovery does not exist or state is invalid.
pub fn recovery_state(
    client: &RamfluxClient,
    recovery_id: &str,
) -> Result<SdkPendingRecoveryStatus, SdkError> {
    let pending = pending_recovery_required(client, recovery_id)?;
    let approvals = client.account_db()?.pending_recovery_approvals(recovery_id)?;
    pending_recovery_status(&pending, approvals.len(), now_unix_timestamp())
}

/// Finalizes local quorum collection into a recovery proof.
///
/// # Errors
/// Returns an error when quorum or timelock gates are not satisfied.
pub fn finalize_recovery(
    client: &RamfluxClient,
    recovery_id: &str,
) -> Result<SdkFinalizedRecovery, SdkError> {
    let pending = pending_recovery_required(client, recovery_id)?;
    let state = parse_pending_recovery_state(&pending.state)?;
    if state != SdkPendingRecoveryState::QuorumReached
        && state != SdkPendingRecoveryState::ReadyToFinalize
    {
        return Err(SdkError::LocalBus(format!(
            "pending recovery {recovery_id} has not reached quorum"
        )));
    }
    let now = now_unix_u64()?;
    if let Some(timelock_until) = pending.context.timelock_until
        && now < timelock_until
    {
        return Err(SdkError::LocalBus("recovery timelock is still active".to_owned()));
    }
    let approvals = client.account_db()?.pending_recovery_approvals(recovery_id)?;
    if approvals.len() < usize::from(pending.recovery_quorum.threshold) {
        return Err(SdkError::LocalBus("recovery quorum threshold not met".to_owned()));
    }
    if !approvals.iter().any(|record| {
        record.approval.member_kind != ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare
    }) {
        return Err(SdkError::LocalBus("guardian-only recovery quorum rejected".to_owned()));
    }
    if state == SdkPendingRecoveryState::QuorumReached {
        let _ready = transition_recovery_state(
            client,
            recovery_id,
            SdkPendingRecoveryState::QuorumReached,
            SdkPendingRecoveryState::ReadyToFinalize,
            None,
        )?;
    }
    let proof = ramflux_protocol::RecoveryQuorumProof {
        context: pending.context.clone(),
        approvals: approvals.into_iter().map(|record| record.approval).collect(),
    };
    let proof_hash = recovery_quorum_proof_hash(&proof)?;
    append_identity_event_if_missing(
        client,
        &format!("recovery:{recovery_id}:finalized"),
        "recovery.finalized",
        &ramflux_protocol::IdentityEventBody::RecoveryFinalized {
            recovery_id: recovery_id.to_owned(),
            identity_commitment: pending.owner_principal_id.clone(),
            lifecycle_epoch: pending.lifecycle_epoch,
            recovery_quorum_proof_hash: proof_hash,
            recovery_quorum_proof: proof.clone(),
        },
    )?;
    Ok(SdkFinalizedRecovery {
        recovery_id: recovery_id.to_owned(),
        recovery_quorum: pending.recovery_quorum,
        proof,
    })
}

fn transition_recovery_state(
    client: &RamfluxClient,
    recovery_id: &str,
    expected: SdkPendingRecoveryState,
    next: SdkPendingRecoveryState,
    timelock_started_at: Option<i64>,
) -> Result<SdkPendingRecoveryStatus, SdkError> {
    validate_state_transition(expected, next)?;
    let pending = client.account_db()?.transition_pending_recovery(
        recovery_id,
        pending_recovery_state_name(expected),
        pending_recovery_state_name(next),
        timelock_started_at,
    )?;
    let approvals = client.account_db()?.pending_recovery_approvals(recovery_id)?;
    pending_recovery_status(&pending, approvals.len(), now_unix_timestamp())
}

fn append_identity_event_if_missing(
    client: &RamfluxClient,
    event_id: &str,
    event_type: &str,
    body: &ramflux_protocol::IdentityEventBody,
) -> Result<(), SdkError> {
    if client.event_body(event_id)?.is_none() {
        client.append_event(event_id, event_type, &serde_json::to_vec(body)?)?;
    }
    Ok(())
}

fn current_recovery_device_id(client: &RamfluxClient) -> Result<String, SdkError> {
    client
        .device_branch
        .as_ref()
        .map(|branch| branch.device_id.clone())
        .ok_or(SdkError::IdentityRootMissing)
}

fn recovery_quorum_proof_hash(
    proof: &ramflux_protocol::RecoveryQuorumProof,
) -> Result<String, SdkError> {
    let signed_bytes = ramflux_protocol::signed_bytes(proof)?;
    Ok(ramflux_crypto::blake3_256_base64url("ramflux.recovery_quorum_proof.v1", &signed_bytes))
}

/// Builds a signed guardian invite control message for E2EE transport.
///
/// # Errors
/// Returns an error when no local device branch is available or the invite cannot be signed.
pub fn invite_guardian(
    client: &RamfluxClient,
    invite_id: &str,
    recovery_quorum_id: &str,
    guardian_principal_id: &str,
    share: &ramflux_crypto::RecoveryShare,
    expires_at: i64,
) -> Result<SdkGuardianInviteMessage, SdkError> {
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let member_kind = match share.member_kind {
        Some(ramflux_crypto::RecoveryQuorumMemberKind::GuardianShare) => {
            ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare
        }
        Some(_) => {
            return Err(SdkError::LocalBus(
                "guardian invite requires a guardian recovery share".to_owned(),
            ));
        }
        None => {
            return Err(SdkError::LocalBus(
                "guardian invite share is missing member kind".to_owned(),
            ));
        }
    };
    let mut invite = SdkGuardianInviteMessage {
        schema: "ramflux.sdk.recovery.guardian_invite.v1".to_owned(),
        version: 1,
        invite_id: invite_id.to_owned(),
        inviter_principal_id: branch.principal_id.clone(),
        inviter_device_id: branch.device_id.clone(),
        inviter_device_epoch: branch.device_epoch,
        inviter_device_public_key_base64url: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        guardian_principal_id: guardian_principal_id.to_owned(),
        recovery_quorum_id: recovery_quorum_id.to_owned(),
        share: SdkGuardianRecoveryShare {
            share_id: share.share_id,
            threshold: share.threshold,
            total: share.total,
            member_kind,
            value_base64: ramflux_protocol::encode_base64url(share.value),
        },
        issued_at: now_unix_timestamp(),
        expires_at,
        signed: sdk_device_signed_fields(&branch.device_id, ""),
    };
    invite.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &invite)?;
    Ok(invite)
}

/// Verifies a signed guardian invite, stores its shard locally, and returns a signed acceptance.
///
/// # Errors
/// Returns an error when the invite signature is invalid, the invite is expired, the local account
/// is not the target guardian, or the shard cannot be stored.
pub fn accept_guardian_invite(
    client: &RamfluxClient,
    invite: &SdkGuardianInviteMessage,
) -> Result<SdkGuardianAcceptMessage, SdkError> {
    verify_guardian_invite(invite)?;
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    if branch.principal_id != invite.guardian_principal_id {
        return Err(SdkError::LocalBus(format!(
            "guardian invite target mismatch: expected {}, local {}",
            invite.guardian_principal_id, branch.principal_id
        )));
    }
    let now = now_unix_timestamp();
    if invite.expires_at <= now {
        return Err(SdkError::LocalBus(format!("guardian invite expired: {}", invite.invite_id)));
    }
    let share_value = decode_guardian_share_value(&invite.share)?;
    let mut accept = SdkGuardianAcceptMessage {
        schema: "ramflux.sdk.recovery.guardian_accept.v1".to_owned(),
        version: 1,
        accept_id: format!("guardian_accept:{}", invite.invite_id),
        invite_id: invite.invite_id.clone(),
        owner_principal_id: invite.inviter_principal_id.clone(),
        guardian_principal_id: branch.principal_id.clone(),
        guardian_device_id: branch.device_id.clone(),
        guardian_device_epoch: branch.device_epoch,
        guardian_device_public_key_base64url: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        recovery_quorum_id: invite.recovery_quorum_id.clone(),
        accepted_at: now,
        signed: sdk_device_signed_fields(&branch.device_id, ""),
    };
    accept.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &accept)?;
    client.account_db()?.record_guardian_recovery_share(&GuardianRecoveryShareWrite {
        owner_principal_id: &invite.inviter_principal_id,
        guardian_principal_id: &branch.principal_id,
        recovery_quorum_id: &invite.recovery_quorum_id,
        share_id: invite.share.share_id,
        threshold: invite.share.threshold,
        total: invite.share.total,
        member_kind: "guardian_share",
        share_value: &share_value,
        inviter_device_id: &invite.inviter_device_id,
        inviter_device_public_key_base64url: &invite.inviter_device_public_key_base64url,
        invite_id: &invite.invite_id,
        accepted_at: accept.accepted_at,
        accepted_by_device_id: &branch.device_id,
        accept_signature: &accept.signed.signature,
        state: "accepted",
    })?;
    Ok(accept)
}

/// Verifies a signed guardian acceptance.
///
/// # Errors
/// Returns an error when canonical verification fails.
pub fn verify_guardian_accept(accept: &SdkGuardianAcceptMessage) -> Result<(), SdkError> {
    Ok(ramflux_protocol::verify_signed_fields(
        accept,
        &accept.signed,
        &accept.guardian_device_public_key_base64url,
    )?)
}

fn verify_guardian_invite(invite: &SdkGuardianInviteMessage) -> Result<(), SdkError> {
    if invite.schema != "ramflux.sdk.recovery.guardian_invite.v1" || invite.version != 1 {
        return Err(SdkError::LocalBus("unsupported guardian invite schema".to_owned()));
    }
    if invite.share.member_kind != ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare {
        return Err(SdkError::LocalBus(
            "guardian invite member kind is not guardian_share".to_owned(),
        ));
    }
    Ok(ramflux_protocol::verify_signed_fields(
        invite,
        &invite.signed,
        &invite.inviter_device_public_key_base64url,
    )?)
}

fn decode_guardian_share_value(share: &SdkGuardianRecoveryShare) -> Result<[u8; 32], SdkError> {
    let share_value = ramflux_protocol::decode_base64url(&share.value_base64)
        .map_err(|error| SdkError::LocalBus(format!("guardian share is not base64url: {error}")))?;
    let value: [u8; 32] = share_value.try_into().map_err(|bytes: Vec<u8>| {
        SdkError::LocalBus(format!("guardian share has invalid length: {}", bytes.len()))
    })?;
    Ok(value)
}

fn pending_recovery_required(
    client: &RamfluxClient,
    recovery_id: &str,
) -> Result<PendingRecoveryRecord, SdkError> {
    client
        .account_db()?
        .pending_recovery(recovery_id)?
        .ok_or_else(|| SdkError::LocalBus(format!("pending recovery not found: {recovery_id}")))
}

fn pending_recovery_status(
    pending: &PendingRecoveryRecord,
    approvals_collected: usize,
    now: i64,
) -> Result<SdkPendingRecoveryStatus, SdkError> {
    let state = parse_pending_recovery_state(&pending.state)?;
    let now_u64 = u64::try_from(now).unwrap_or(0);
    let ready_to_finalize = approvals_collected >= usize::from(pending.recovery_quorum.threshold)
        && pending.context.timelock_until.is_none_or(|timelock_until| now_u64 >= timelock_until);
    Ok(SdkPendingRecoveryStatus {
        recovery_id: pending.recovery_id.clone(),
        owner_principal_id: pending.owner_principal_id.clone(),
        recovery_quorum_id: pending.recovery_quorum_id.clone(),
        state,
        approvals_collected,
        threshold: pending.recovery_quorum.threshold,
        timelock_until: pending.context.timelock_until,
        ready_to_finalize,
    })
}

fn validate_state_transition(
    expected: SdkPendingRecoveryState,
    next: SdkPendingRecoveryState,
) -> Result<(), SdkError> {
    let valid = matches!(
        (expected, next),
        (SdkPendingRecoveryState::Initiated, SdkPendingRecoveryState::TimelockStarted)
            | (
                SdkPendingRecoveryState::TimelockStarted,
                SdkPendingRecoveryState::CollectingApprovals
            )
            | (
                SdkPendingRecoveryState::CollectingApprovals,
                SdkPendingRecoveryState::QuorumReached
            )
            | (SdkPendingRecoveryState::QuorumReached, SdkPendingRecoveryState::ReadyToFinalize)
    );
    if valid {
        Ok(())
    } else {
        Err(SdkError::LocalBus(format!(
            "illegal recovery state transition: {} -> {}",
            pending_recovery_state_name(expected),
            pending_recovery_state_name(next)
        )))
    }
}

fn pending_recovery_state_name(state: SdkPendingRecoveryState) -> &'static str {
    match state {
        SdkPendingRecoveryState::Initiated => "initiated",
        SdkPendingRecoveryState::TimelockStarted => "timelock_started",
        SdkPendingRecoveryState::CollectingApprovals => "collecting_approvals",
        SdkPendingRecoveryState::QuorumReached => "quorum_reached",
        SdkPendingRecoveryState::ReadyToFinalize => "ready_to_finalize",
    }
}

fn parse_pending_recovery_state(state: &str) -> Result<SdkPendingRecoveryState, SdkError> {
    match state {
        "initiated" => Ok(SdkPendingRecoveryState::Initiated),
        "timelock_started" => Ok(SdkPendingRecoveryState::TimelockStarted),
        "collecting_approvals" => Ok(SdkPendingRecoveryState::CollectingApprovals),
        "quorum_reached" => Ok(SdkPendingRecoveryState::QuorumReached),
        "ready_to_finalize" => Ok(SdkPendingRecoveryState::ReadyToFinalize),
        other => Err(SdkError::LocalBus(format!("unknown pending recovery state: {other}"))),
    }
}

fn validate_recovery_quorum_shape(
    quorum: &ramflux_protocol::RecoveryQuorumConfigured,
) -> Result<(), SdkError> {
    if quorum.threshold == 0 || quorum.total == 0 || quorum.threshold > quorum.total {
        return Err(SdkError::LocalBus("invalid recovery quorum threshold".to_owned()));
    }
    if usize::from(quorum.total) != quorum.members.len() {
        return Err(SdkError::LocalBus("invalid recovery quorum member count".to_owned()));
    }
    let mut seen = BTreeSet::new();
    for member in &quorum.members {
        if !seen.insert(member.signing_key_id.as_str()) {
            return Err(SdkError::LocalBus("duplicate recovery quorum member".to_owned()));
        }
    }
    Ok(())
}

fn validate_recovery_approval_against_quorum(
    context: &ramflux_protocol::RecoveryApprovalContext,
    quorum: &ramflux_protocol::RecoveryQuorumConfigured,
    approval: &ramflux_protocol::RecoveryApproval,
) -> Result<(), SdkError> {
    validate_recovery_quorum_shape(quorum)?;
    if approval.signature_alg != ramflux_protocol::SignatureAlg::Ed25519 {
        return Err(SdkError::LocalBus(
            "recovery approval signature algorithm rejected".to_owned(),
        ));
    }
    let member = quorum
        .members
        .iter()
        .find(|member| member.signing_key_id == approval.signing_key_id)
        .ok_or_else(|| {
            SdkError::LocalBus("recovery approval member is not configured".to_owned())
        })?;
    if member.member_kind != approval.member_kind {
        return Err(SdkError::LocalBus("recovery approval member kind mismatch".to_owned()));
    }
    let signed_bytes = ramflux_protocol::signed_bytes(context)?;
    ramflux_crypto::verify_canonical_signature(
        &signed_bytes,
        &approval.signature,
        &member.public_key_base64url,
    )?;
    Ok(())
}

fn now_unix_u64() -> Result<u64, SdkError> {
    u64::try_from(now_unix_timestamp())
        .map_err(|_error| SdkError::LocalBus("system clock is before unix epoch".to_owned()))
}

#[must_use]
pub fn recovery_member_public_key_base64url(member_signing_seed: [u8; 32]) -> String {
    ramflux_crypto::public_key_base64url_from_seed(member_signing_seed)
}

fn to_crypto_member_kind(
    member_kind: &ramflux_protocol::RecoveryQuorumMemberKind,
) -> ramflux_crypto::RecoveryQuorumMemberKind {
    match member_kind {
        ramflux_protocol::RecoveryQuorumMemberKind::RootShare => {
            ramflux_crypto::RecoveryQuorumMemberKind::RootShare
        }
        ramflux_protocol::RecoveryQuorumMemberKind::DeviceShare => {
            ramflux_crypto::RecoveryQuorumMemberKind::DeviceShare
        }
        ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare => {
            ramflux_crypto::RecoveryQuorumMemberKind::GuardianShare
        }
        ramflux_protocol::RecoveryQuorumMemberKind::HardwareTokenShare => {
            ramflux_crypto::RecoveryQuorumMemberKind::HardwareTokenShare
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_recovery_quorum_builds_config_and_signed_proof() -> Result<(), SdkError> {
        let members = recovery_members();
        let configured =
            RamfluxClient::configure_recovery_quorum("quorum_sdk", [0x7a; 32], 2, &members)?;
        assert_eq!(configured.recovery_quorum.threshold, 2);
        assert_eq!(configured.recovery_quorum.total, 3);
        assert_eq!(configured.shares.len(), 3);
        assert_eq!(
            configured.shares[0].member_kind,
            Some(ramflux_crypto::RecoveryQuorumMemberKind::RootShare)
        );
        assert!(matches!(
            configured.lineage_event_body(),
            ramflux_protocol::IdentityEventBody::RecoveryQuorumConfigured { .. }
        ));

        let context = ramflux_protocol::RecoveryApprovalContext {
            recovery_id: "recovery_sdk".to_owned(),
            event_type: "identity.reactivated".to_owned(),
            principal_id: "principal_sdk".to_owned(),
            lifecycle_epoch: 2,
            lineage_head: Some("lineage_sdk".to_owned()),
            timelock_until: Some(1_760_000_100),
        };
        let root = RamfluxClient::approve_recovery(
            ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
            "root-share",
            [0x11; 32],
            &context,
        )?;
        let guardian = RamfluxClient::approve_recovery(
            ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
            "guardian-share",
            [0x33; 32],
            &context,
        )?;
        let proof = RamfluxClient::build_recovery_proof(context.clone(), vec![root, guardian]);
        assert_eq!(proof.context, context);
        assert_eq!(proof.approvals.len(), 2);
        Ok(())
    }

    #[test]
    fn guardian_invite_accept_stores_share_after_e2ee_delivery() -> Result<(), SdkError> {
        let (alice, alice_root) = unlocked_client(
            "guardian-invite-alice",
            "principal_alice",
            "alice_device",
            [0x31; 32],
        )?;
        let (guardian, guardian_root) =
            unlocked_client("guardian-invite-bob", "principal_bob", "bob_device", [0x41; 32])?;
        let members = vec![
            member(ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "root-share", [0x11; 32]),
            member(
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                "guardian-share",
                [0x33; 32],
            ),
        ];
        let configured =
            RamfluxClient::configure_recovery_quorum("quorum_guardian", [0x7a; 32], 2, &members)?;
        let guardian_share = configured
            .shares
            .iter()
            .find(|share| {
                share.member_kind == Some(ramflux_crypto::RecoveryQuorumMemberKind::GuardianShare)
            })
            .ok_or_else(|| SdkError::LocalBus("guardian share missing".to_owned()))?;
        let invite = alice.invite_guardian(
            "invite_guardian_a",
            "quorum_guardian",
            "principal_bob",
            guardian_share,
            now_unix_timestamp() + 300,
        )?;
        let invite_plaintext = serde_json::to_vec(&invite)?;
        let mut send_session =
            ramflux_crypto::DmSession::initiator([0x51; 32], [0x52; 32], [0x53; 32], [0x54; 32])?;
        let mut recv_session =
            ramflux_crypto::DmSession::recipient([0x51; 32], [0x53; 32], [0x52; 32], [0x54; 32])?;
        let ciphertext = send_session.encrypt(&invite_plaintext, b"guardian.invite")?;
        let ciphertext_json = serde_json::to_vec(&ciphertext)?;
        assert!(!String::from_utf8_lossy(&ciphertext_json).contains(&invite.share.value_base64));
        let delivered = recv_session.decrypt(&ciphertext, b"guardian.invite")?;
        let delivered_invite: SdkGuardianInviteMessage = serde_json::from_slice(&delivered)?;
        let accept = guardian.accept_guardian_invite(&delivered_invite)?;
        verify_guardian_accept(&accept)?;

        let shares = guardian.guardian_recovery_shares_for_owner("principal_alice")?;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].recovery_quorum_id, "quorum_guardian");
        assert_eq!(shares[0].guardian_principal_id, "principal_bob");
        assert_eq!(shares[0].share_value, guardian_share.value);
        assert_eq!(shares[0].state, "accepted");
        let _ = std::fs::remove_dir_all(alice_root);
        let _ = std::fs::remove_dir_all(guardian_root);
        Ok(())
    }

    #[test]
    fn guardian_invite_rejects_tamper_and_wrong_guardian() -> Result<(), SdkError> {
        let (alice, alice_root) = unlocked_client(
            "guardian-reject-alice",
            "principal_alice",
            "alice_device",
            [0x61; 32],
        )?;
        let (guardian, guardian_root) =
            unlocked_client("guardian-reject-bob", "principal_bob", "bob_device", [0x62; 32])?;
        let (carol, carol_root) = unlocked_client(
            "guardian-reject-carol",
            "principal_carol",
            "carol_device",
            [0x63; 32],
        )?;
        let mut share = ramflux_crypto::create_recovery_quorum([0x9a; 32], 1, 1)?
            .into_iter()
            .next()
            .ok_or_else(|| SdkError::LocalBus("share missing".to_owned()))?;
        share.member_kind = Some(ramflux_crypto::RecoveryQuorumMemberKind::GuardianShare);
        let invite = alice.invite_guardian(
            "invite_guardian_reject",
            "quorum_reject",
            "principal_bob",
            &share,
            now_unix_timestamp() + 300,
        )?;

        let mut tampered = invite.clone();
        tampered.guardian_principal_id = "principal_carol".to_owned();
        assert!(guardian.accept_guardian_invite(&tampered).is_err());
        assert!(carol.accept_guardian_invite(&invite).is_err());

        let _ = std::fs::remove_dir_all(alice_root);
        let _ = std::fs::remove_dir_all(guardian_root);
        let _ = std::fs::remove_dir_all(carol_root);
        Ok(())
    }

    #[test]
    fn pending_recovery_collects_quorum_and_finalizes_after_timelock() -> Result<(), SdkError> {
        let (alice, alice_root) =
            unlocked_client("pending-happy-alice", "principal_alice", "alice_device", [0x71; 32])?;
        let (guardian, guardian_root) =
            unlocked_client("pending-happy-bob", "principal_bob", "bob_device", [0x72; 32])?;
        let quorum = ramflux_protocol::RecoveryQuorumConfigured {
            recovery_quorum_id: "quorum_pending".to_owned(),
            threshold: 2,
            total: 2,
            members: vec![
                member(
                    ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
                    "root-share",
                    [0x11; 32],
                )
                .commitment(),
                member_with_public_key(
                    ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                    "device:bob_device",
                    recovery_member_public_key_base64url([0x72; 32]),
                )
                .commitment(),
            ],
        };
        let mut guardian_share =
            ramflux_crypto::create_recovery_quorum([0x81; 32], 2, 2)?.remove(1);
        guardian_share.member_kind = Some(ramflux_crypto::RecoveryQuorumMemberKind::GuardianShare);
        let invite = alice.invite_guardian(
            "invite_pending_bob",
            "quorum_pending",
            "principal_bob",
            &guardian_share,
            now_unix_timestamp() + 300,
        )?;
        let _accept = guardian.accept_guardian_invite(&invite)?;

        let timelock_until = now_unix_u64()?.saturating_sub(1);
        let initiated = alice.initiate_recovery(&SdkRecoveryInitiateRequest {
            recovery_id: "recovery_pending".to_owned(),
            owner_principal_id: "principal_alice".to_owned(),
            recovery_quorum: quorum.clone(),
            lifecycle_epoch: 3,
            lineage_head: Some("lineage_pending".to_owned()),
            timelock_until: Some(timelock_until),
        })?;
        assert_eq!(initiated.state, SdkPendingRecoveryState::Initiated);
        assert!(alice.begin_recovery_approval_collection("recovery_pending").is_err());
        assert_eq!(
            alice.start_recovery_timelock("recovery_pending")?.state,
            SdkPendingRecoveryState::TimelockStarted
        );
        assert_eq!(
            alice.begin_recovery_approval_collection("recovery_pending")?.state,
            SdkPendingRecoveryState::CollectingApprovals
        );
        let context = alice
            .account_db()?
            .pending_recovery("recovery_pending")?
            .ok_or_else(|| SdkError::LocalBus("pending recovery missing".to_owned()))?
            .context;
        let root_approval = RamfluxClient::approve_recovery(
            ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
            "root-share",
            [0x11; 32],
            &context,
        )?;
        let after_root = alice.collect_recovery_approval("recovery_pending", &root_approval)?;
        assert_eq!(after_root.state, SdkPendingRecoveryState::CollectingApprovals);
        assert_eq!(after_root.approvals_collected, 1);
        let guardian_approval =
            guardian.guardian_approve_recovery("principal_alice", "quorum_pending", &context)?;
        let quorum_reached =
            alice.collect_guardian_approval("recovery_pending", &guardian_approval)?;
        assert_eq!(quorum_reached.state, SdkPendingRecoveryState::QuorumReached);
        assert!(quorum_reached.ready_to_finalize);

        let finalized = alice.finalize_recovery("recovery_pending")?;
        assert_eq!(finalized.recovery_id, "recovery_pending");
        assert_eq!(finalized.recovery_quorum, quorum);
        assert_eq!(finalized.proof.context, context);
        assert_eq!(finalized.proof.approvals.len(), 2);
        assert_eq!(
            alice.recovery_state("recovery_pending")?.state,
            SdkPendingRecoveryState::ReadyToFinalize
        );
        assert_pending_recovery_lineage_events(&alice)?;
        let _ = std::fs::remove_dir_all(alice_root);
        let _ = std::fs::remove_dir_all(guardian_root);
        Ok(())
    }

    fn assert_pending_recovery_lineage_events(client: &RamfluxClient) -> Result<(), SdkError> {
        assert!(matches!(
            identity_event_body(client, "recovery:recovery_pending:initiated")?,
            ramflux_protocol::IdentityEventBody::RecoveryInitiated { .. }
        ));
        assert!(matches!(
            identity_event_body(client, "recovery:recovery_pending:approval:root-share")?,
            ramflux_protocol::IdentityEventBody::RecoveryApprovalCollected { .. }
        ));
        assert!(matches!(
            identity_event_body(client, "recovery:recovery_pending:authorized")?,
            ramflux_protocol::IdentityEventBody::RecoveryAuthorized { .. }
        ));
        assert!(matches!(
            identity_event_body(client, "recovery:recovery_pending:finalized")?,
            ramflux_protocol::IdentityEventBody::RecoveryFinalized { .. }
        ));
        Ok(())
    }

    #[test]
    fn pending_recovery_rejects_timelock_shortfall_duplicate_and_guardian_only()
    -> Result<(), SdkError> {
        let (alice, alice_root) =
            unlocked_client("pending-reject-alice", "principal_alice", "alice_device", [0x91; 32])?;
        let quorum = ramflux_protocol::RecoveryQuorumConfigured {
            recovery_quorum_id: "quorum_reject".to_owned(),
            threshold: 2,
            total: 3,
            members: vec![
                member(
                    ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
                    "root-share",
                    [0x21; 32],
                )
                .commitment(),
                member(
                    ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                    "guardian-a",
                    [0x22; 32],
                )
                .commitment(),
                member(
                    ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                    "guardian-b",
                    [0x23; 32],
                )
                .commitment(),
            ],
        };
        alice.initiate_recovery(&SdkRecoveryInitiateRequest {
            recovery_id: "recovery_reject".to_owned(),
            owner_principal_id: "principal_alice".to_owned(),
            recovery_quorum: quorum,
            lifecycle_epoch: 4,
            lineage_head: None,
            timelock_until: Some(now_unix_u64()?.saturating_add(300)),
        })?;
        alice.start_recovery_timelock("recovery_reject")?;
        alice.begin_recovery_approval_collection("recovery_reject")?;
        let context = alice
            .account_db()?
            .pending_recovery("recovery_reject")?
            .ok_or_else(|| SdkError::LocalBus("pending recovery missing".to_owned()))?
            .context;
        let root_approval = RamfluxClient::approve_recovery(
            ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
            "root-share",
            [0x21; 32],
            &context,
        )?;
        alice.collect_recovery_approval("recovery_reject", &root_approval)?;
        assert!(alice.collect_recovery_approval("recovery_reject", &root_approval).is_err());
        assert!(alice.finalize_recovery("recovery_reject").is_err());

        let guardian_a = RamfluxClient::approve_recovery(
            ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
            "guardian-a",
            [0x22; 32],
            &context,
        )?;
        alice.collect_guardian_approval("recovery_reject", &guardian_a)?;
        assert!(alice.finalize_recovery("recovery_reject").is_err());

        assert_guardian_only_recovery_rejected()?;
        let _ = std::fs::remove_dir_all(alice_root);
        Ok(())
    }

    fn assert_guardian_only_recovery_rejected() -> Result<(), SdkError> {
        let (client, client_root) = unlocked_client(
            "pending-guardian-only",
            "principal_alice",
            "alice_device_go",
            [0x92; 32],
        )?;
        client.initiate_recovery(&SdkRecoveryInitiateRequest {
            recovery_id: "recovery_guardian_only".to_owned(),
            owner_principal_id: "principal_alice".to_owned(),
            recovery_quorum: guardian_only_quorum(),
            lifecycle_epoch: 5,
            lineage_head: None,
            timelock_until: Some(now_unix_u64()?.saturating_sub(1)),
        })?;
        client.start_recovery_timelock("recovery_guardian_only")?;
        client.begin_recovery_approval_collection("recovery_guardian_only")?;
        let context = client
            .account_db()?
            .pending_recovery("recovery_guardian_only")?
            .ok_or_else(|| SdkError::LocalBus("pending recovery missing".to_owned()))?
            .context;
        for (signing_key_id, seed) in [("guardian-a", [0x32; 32]), ("guardian-b", [0x33; 32])] {
            let approval = RamfluxClient::approve_recovery(
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                signing_key_id,
                seed,
                &context,
            )?;
            client.collect_guardian_approval("recovery_guardian_only", &approval)?;
        }
        assert!(client.finalize_recovery("recovery_guardian_only").is_err());
        let _ = std::fs::remove_dir_all(client_root);
        Ok(())
    }

    fn guardian_only_quorum() -> ramflux_protocol::RecoveryQuorumConfigured {
        ramflux_protocol::RecoveryQuorumConfigured {
            recovery_quorum_id: "quorum_guardian_only".to_owned(),
            threshold: 2,
            total: 2,
            members: vec![
                member(
                    ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                    "guardian-a",
                    [0x32; 32],
                )
                .commitment(),
                member(
                    ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                    "guardian-b",
                    [0x33; 32],
                )
                .commitment(),
            ],
        }
    }

    fn recovery_members() -> Vec<SdkRecoveryQuorumMember> {
        vec![
            member(ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "root-share", [0x11; 32]),
            member(
                ramflux_protocol::RecoveryQuorumMemberKind::DeviceShare,
                "device-share",
                [0x22; 32],
            ),
            member(
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                "guardian-share",
                [0x33; 32],
            ),
        ]
    }

    fn identity_event_body(
        client: &RamfluxClient,
        event_id: &str,
    ) -> Result<ramflux_protocol::IdentityEventBody, SdkError> {
        let body = client
            .event_body(event_id)?
            .ok_or_else(|| SdkError::LocalBus(format!("missing event body: {event_id}")))?;
        Ok(serde_json::from_slice(&body)?)
    }

    fn member(
        member_kind: ramflux_protocol::RecoveryQuorumMemberKind,
        signing_key_id: &str,
        seed: [u8; 32],
    ) -> SdkRecoveryQuorumMember {
        member_with_public_key(
            member_kind,
            signing_key_id,
            recovery_member_public_key_base64url(seed),
        )
    }

    fn member_with_public_key(
        member_kind: ramflux_protocol::RecoveryQuorumMemberKind,
        signing_key_id: &str,
        public_key_base64url: String,
    ) -> SdkRecoveryQuorumMember {
        SdkRecoveryQuorumMember {
            member_kind,
            signing_key_id: signing_key_id.to_owned(),
            public_key_base64url,
        }
    }

    fn unlocked_client(
        test_name: &str,
        principal_id: &str,
        device_id: &str,
        device_seed: [u8; 32],
    ) -> Result<(RamfluxClient, PathBuf), SdkError> {
        let nanos = now_unix_timestamp();
        let root = std::env::temp_dir()
            .join(format!("ramflux-sdk-recovery-{test_name}-{}-{nanos}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal_id, [0x21; 32]);
        client.create_device_branch(principal_id, device_id, 1, device_seed);
        client.open_account_index(&root)?;
        client.create_account("acct", principal_id)?;
        client.unlock_account("acct", b"recovery-guardian-test")?;
        Ok((client, root))
    }
}

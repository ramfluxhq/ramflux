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

    fn member(
        member_kind: ramflux_protocol::RecoveryQuorumMemberKind,
        signing_key_id: &str,
        seed: [u8; 32],
    ) -> SdkRecoveryQuorumMember {
        SdkRecoveryQuorumMember {
            member_kind,
            signing_key_id: signing_key_id.to_owned(),
            public_key_base64url: recovery_member_public_key_base64url(seed),
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

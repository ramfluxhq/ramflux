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
}

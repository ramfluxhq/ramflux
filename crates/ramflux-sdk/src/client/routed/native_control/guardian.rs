// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `CONTROL_RECOVERY` (operation 9): guardian invite and guardian accept.
//! Receiving an invite never stores the share as accepted: the verified native invite waits for
//! the local user, who accepts it through `accept_guardian_invite`. A received accept is bound
//! to an invite this account issued.
use super::{authority, content, generated_signed, native_signed};
use crate::client::recovery::{
    SdkGuardianAcceptMessage, SdkGuardianInviteHandle, SdkGuardianInviteMessage,
    SdkGuardianRecoveryShare, SdkPendingGuardianInvite,
};
use crate::client::routed::{Kind, Opened};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

const INVITE_SCHEMA: &str = "ramflux.sdk.recovery.guardian_invite.v1";
const ACCEPT_SCHEMA: &str = "ramflux.sdk.recovery.guardian_accept.v1";

/// What the inviter remembers about an invite it produced; binds a later accept.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct IssuedGuardianInvite {
    pub guardian_principal_id: String,
    pub recovery_quorum_id: String,
    pub expires_at: i64,
}

#[derive(Deserialize, Serialize)]
struct PendingGuardianInvite {
    source: String,
    invite: SdkGuardianInviteMessage,
}

fn invite_fingerprint(invite: &SdkGuardianInviteMessage) -> Result<String, SdkError> {
    Ok(ramflux_protocol::encode_base64url(
        blake3::hash(&ramflux_protocol::canonical_json_bytes(invite)?).as_bytes(),
    ))
}

fn id_key(prefix: &str, id: &str) -> String {
    format!("{prefix}/{}", ramflux_protocol::encode_base64url(id.as_bytes()))
}

pub(super) fn issued_key(invite_id: &str) -> String {
    id_key("recovery/guardian-invite-issued", invite_id)
}

pub(super) fn pending_key(source: &RootQualifiedDeviceRef, invite_id: &str) -> String {
    pending_storage_key(source.storage_key(), invite_id)
}

fn pending_storage_key(source: &str, invite_id: &str) -> String {
    id_key(&format!("recovery/guardian-invite/{source}"), invite_id)
}

pub(super) fn accept_key(invite_id: &str) -> String {
    id_key("recovery/guardian-accept", invite_id)
}

fn small(value: u32) -> Result<u8, SdkError> {
    u8::try_from(value).map_err(|_| content("guardian share index out of range"))
}

fn invite_to_native(invite: &g::GuardianInvite) -> Result<SdkGuardianInviteMessage, SdkError> {
    let share = invite.share.as_ref().ok_or_else(|| content("guardian share missing"))?;
    match share.member_kind.as_ref().and_then(|kind| kind.value.as_ref()) {
        Some(g::recovery_quorum_member_kind::Value::GuardianShare(_)) => {}
        _ => return Err(content("guardian invite member kind is not guardian_share")),
    }
    if invite.schema != INVITE_SCHEMA || invite.version != 1 {
        return Err(content("guardian invite schema or version unknown"));
    }
    Ok(SdkGuardianInviteMessage {
        schema: invite.schema.clone(),
        version: invite.version,
        invite_id: invite.invite_id.clone(),
        inviter_principal_id: invite.inviter_principal_id.clone(),
        inviter_device_id: invite.inviter_device_id.clone(),
        inviter_device_epoch: invite.inviter_device_epoch,
        inviter_device_public_key_base64url: invite.inviter_device_public_key_base64url.clone(),
        guardian_principal_id: invite.guardian_principal_id.clone(),
        recovery_quorum_id: invite.recovery_quorum_id.clone(),
        share: SdkGuardianRecoveryShare {
            share_id: small(share.share_id)?,
            threshold: small(share.threshold)?,
            total: small(share.total)?,
            member_kind: ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
            value_base64: share.value_base64.clone(),
        },
        issued_at: invite.issued_at,
        expires_at: invite.expires_at,
        signed: native_signed(invite.signed.as_ref())?,
    })
}

pub(super) fn invite_to_generated(
    invite: &SdkGuardianInviteMessage,
) -> Result<g::GuardianInvite, SdkError> {
    if invite.share.member_kind != ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare {
        return Err(content("guardian invite member kind is not guardian_share"));
    }
    Ok(g::GuardianInvite {
        schema: invite.schema.clone(),
        version: invite.version,
        invite_id: invite.invite_id.clone(),
        inviter_principal_id: invite.inviter_principal_id.clone(),
        inviter_device_id: invite.inviter_device_id.clone(),
        inviter_device_epoch: invite.inviter_device_epoch,
        inviter_device_public_key_base64url: invite.inviter_device_public_key_base64url.clone(),
        guardian_principal_id: invite.guardian_principal_id.clone(),
        recovery_quorum_id: invite.recovery_quorum_id.clone(),
        share: Some(g::GuardianRecoveryShare {
            share_id: u32::from(invite.share.share_id),
            threshold: u32::from(invite.share.threshold),
            total: u32::from(invite.share.total),
            member_kind: Some(g::RecoveryQuorumMemberKind {
                value: Some(g::recovery_quorum_member_kind::Value::GuardianShare(
                    g::RecoveryQuorumMemberKindGuardianShare {},
                )),
            }),
            value_base64: invite.share.value_base64.clone(),
        }),
        issued_at: invite.issued_at,
        expires_at: invite.expires_at,
        signed: Some(generated_signed(&invite.signed)),
    })
}

fn accept_to_native(accept: &g::GuardianAccept) -> Result<SdkGuardianAcceptMessage, SdkError> {
    if accept.schema != ACCEPT_SCHEMA || accept.version != 1 {
        return Err(content("guardian accept schema or version unknown"));
    }
    Ok(SdkGuardianAcceptMessage {
        schema: accept.schema.clone(),
        version: accept.version,
        accept_id: accept.accept_id.clone(),
        invite_id: accept.invite_id.clone(),
        owner_principal_id: accept.owner_principal_id.clone(),
        guardian_principal_id: accept.guardian_principal_id.clone(),
        guardian_device_id: accept.guardian_device_id.clone(),
        guardian_device_epoch: accept.guardian_device_epoch,
        guardian_device_public_key_base64url: accept.guardian_device_public_key_base64url.clone(),
        recovery_quorum_id: accept.recovery_quorum_id.clone(),
        accepted_at: accept.accepted_at,
        signed: native_signed(accept.signed.as_ref())?,
    })
}

pub(super) fn accept_to_generated(accept: &SdkGuardianAcceptMessage) -> g::GuardianAccept {
    g::GuardianAccept {
        schema: accept.schema.clone(),
        version: accept.version,
        accept_id: accept.accept_id.clone(),
        invite_id: accept.invite_id.clone(),
        owner_principal_id: accept.owner_principal_id.clone(),
        guardian_principal_id: accept.guardian_principal_id.clone(),
        guardian_device_id: accept.guardian_device_id.clone(),
        guardian_device_epoch: accept.guardian_device_epoch,
        guardian_device_public_key_base64url: accept.guardian_device_public_key_base64url.clone(),
        recovery_quorum_id: accept.recovery_quorum_id.clone(),
        accepted_at: accept.accepted_at,
        signed: Some(generated_signed(&accept.signed)),
    }
}

/// A verified recovery control in its native form.
pub(in crate::client::routed) enum VerifiedRecovery {
    Invite(Box<SdkGuardianInviteMessage>),
    Accept(Box<SdkGuardianAcceptMessage>),
}

impl RamfluxClient {
    fn local_principal_id(&self) -> Result<&str, SdkError> {
        Ok(self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id.as_str())
    }

    /// Sender rule: invite from the recovering account to its guardian, accept from the invited
    /// guardian; accepted contact link, pinned device key and native signature in both cases.
    pub(in crate::client::routed) fn authorize_generated_recovery(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &g::RecoveryControl,
    ) -> Result<VerifiedRecovery, SdkError> {
        use crate::client::identity_authority::HeadUse;
        if opened.routing.kind != Kind::Control || opened.routing.group_id.is_some() {
            return Err(authority("recovery control requires a direct control route"));
        }
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if source != opened.remote_device
            || source.root_commitment() == self.own_account_anchor()?
        {
            return Err(authority("recovery control requires the pair peer of another root"));
        }
        self.require_accepted_contact(source.root_commitment())?;
        let (principal, key) = self.pinned_peer(&source)?;
        let peer_record = self.trusted_device(HeadUse::NewAuthorization, &source)?;
        let local = self.local_principal_id()?;
        let now = crate::time::now_unix_timestamp();
        match body.payload.as_ref() {
            Some(g::recovery_control::Payload::Invite(invite)) => {
                let native = invite_to_native(invite)?;
                if native.inviter_principal_id != principal
                    || native.inviter_device_id != source.device_id()
                    || peer_record["device_epoch"].as_u64() != Some(native.inviter_device_epoch)
                    || native.signed.signing_key_id != format!("device:{}", source.device_id())
                    || native.inviter_device_public_key_base64url != key
                    || native.guardian_principal_id != local
                    || native.guardian_principal_id == native.inviter_principal_id
                {
                    return Err(authority("guardian invite roles differ from pinned endpoints"));
                }
                if native.invite_id.is_empty()
                    || native.recovery_quorum_id.is_empty()
                    || native.issued_at <= 0
                    || native.expires_at <= native.issued_at
                    || native.expires_at <= now
                {
                    return Err(content("guardian invite lifetime invalid or expired"));
                }
                let share = ramflux_protocol::decode_base64url(&native.share.value_base64)
                    .map_err(|_| content("guardian share is not base64url"))?;
                if share.len() != 32 {
                    return Err(content("guardian share length"));
                }
                ramflux_protocol::verify_signed_fields(&native, &native.signed, &key)
                    .map_err(|_| authority("guardian invite signature invalid"))?;
                Ok(VerifiedRecovery::Invite(Box::new(native)))
            }
            Some(g::recovery_control::Payload::Accept(accept)) => {
                let native = accept_to_native(accept)?;
                if native.guardian_principal_id != principal
                    || native.guardian_device_id != source.device_id()
                    || peer_record["device_epoch"].as_u64() != Some(native.guardian_device_epoch)
                    || native.signed.signing_key_id != format!("device:{}", source.device_id())
                    || native.guardian_device_public_key_base64url != key
                    || native.owner_principal_id != local
                    || native.accept_id != format!("guardian_accept:{}", native.invite_id)
                {
                    return Err(authority("guardian accept roles differ from pinned endpoints"));
                }
                let issued = self
                    .account_db()?
                    .load_actor_state::<IssuedGuardianInvite>(&issued_key(&native.invite_id))?
                    .ok_or_else(|| authority("guardian accept has no locally issued invite"))?;
                if issued.guardian_principal_id != native.guardian_principal_id
                    || issued.recovery_quorum_id != native.recovery_quorum_id
                    || native.accepted_at <= 0
                    || native.accepted_at > issued.expires_at
                {
                    return Err(authority("guardian accept differs from the issued invite"));
                }
                ramflux_protocol::verify_signed_fields(&native, &native.signed, &key)
                    .map_err(|_| authority("guardian accept signature invalid"))?;
                Ok(VerifiedRecovery::Accept(Box::new(native)))
            }
            None => Err(content("recovery control requires Invite or Accept")),
        }
    }

    /// Durable effect: one pending invite per (source device, invite id), or one accept per
    /// issued invite. An id reused with other content is refused, never overwritten.
    pub(in crate::client::routed) fn apply_generated_recovery(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        identity: &g::EventIdentity,
        body: &g::RecoveryControl,
        exact_inner: &[u8],
    ) -> Result<bool, SdkError> {
        let verified = self.authorize_generated_recovery(opened, entry, body)?;
        let db = self.account_db()?;
        self.apply_generated_peer_control_once(entry, identity, exact_inner, 9, |source| {
            match &verified {
                VerifiedRecovery::Invite(invite) => {
                    let key = pending_key(source, &invite.invite_id);
                    if let Some(old) = db.load_actor_state::<PendingGuardianInvite>(&key)? {
                        if old.source != source.storage_key() || old.invite != **invite {
                            return Err(authority("guardian invite id reused"));
                        }
                        return Ok(());
                    }
                    db.persist_actor_state(
                        &key,
                        &PendingGuardianInvite {
                            source: source.storage_key().into(),
                            invite: *invite.clone(),
                        },
                    )?;
                }
                VerifiedRecovery::Accept(accept) => {
                    let key = accept_key(&accept.invite_id);
                    if let Some(old) = db.load_actor_state::<SdkGuardianAcceptMessage>(&key)? {
                        if old != **accept {
                            return Err(authority("guardian accept already recorded"));
                        }
                        return Ok(());
                    }
                    db.persist_actor_state(&key, &**accept)?;
                }
            }
            Ok(())
        })
    }

    /// Verified invites waiting for the local user's decision, in key order. An invite past its
    /// lifetime is erased here together with the share it carries.
    /// # Errors
    /// Returns a storage error when the account database cannot be read or written.
    pub fn pending_guardian_invites(&self) -> Result<Vec<SdkPendingGuardianInvite>, SdkError> {
        let db = self.account_db()?;
        let now = crate::time::now_unix_timestamp();
        let mut invites = Vec::new();
        for key in db.actor_state_keys("recovery/guardian-invite/")? {
            match db.load_actor_state::<PendingGuardianInvite>(&key)? {
                Some(row) if row.invite.expires_at > now => {
                    let handle = SdkGuardianInviteHandle {
                        source: row.source,
                        invite_id: row.invite.invite_id.clone(),
                        fingerprint: invite_fingerprint(&row.invite)?,
                    };
                    if pending_storage_key(&handle.source, &handle.invite_id) != key {
                        return Err(authority("pending guardian source/key mismatch"));
                    }
                    invites.push(SdkPendingGuardianInvite { handle, invite: row.invite });
                }
                Some(_) => db.remove_actor_state(&key)?,
                None => {}
            }
        }
        Ok(invites)
    }

    /// The local user's decision on a pending invite. Accepting runs the native
    /// `accept_guardian_invite` (share stored as accepted, signed accept returned for sending);
    /// either way the pending copy of the share is erased in the same transaction.
    /// # Errors
    /// Returns an error when no pending invite has this id or the native accept refuses it.
    pub fn decide_pending_guardian_invite(
        &self,
        handle: &SdkGuardianInviteHandle,
        accept: bool,
    ) -> Result<Option<SdkGuardianAcceptMessage>, SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            let key = pending_storage_key(&handle.source, &handle.invite_id);
            let row = db
                .load_actor_state::<PendingGuardianInvite>(&key)?
                .ok_or_else(|| authority("no pending guardian invite for this source and id"))?;
            let invite = row.invite;
            if row.source != handle.source
                || invite.invite_id != handle.invite_id
                || invite_fingerprint(&invite)? != handle.fingerprint
            {
                return Err(authority("pending guardian invite changed after selection"));
            }
            if accept {
                self.revalidate_pending_guardian_invite(handle, &invite)?;
            }
            let reply = if accept { Some(self.accept_guardian_invite(&invite)?) } else { None };
            db.remove_actor_state(&key)?;
            Ok(reply)
        })
    }

    fn revalidate_pending_guardian_invite(
        &self,
        handle: &SdkGuardianInviteHandle,
        invite: &SdkGuardianInviteMessage,
    ) -> Result<(), SdkError> {
        let source = self.device_identity(&handle.source)?;
        self.require_accepted_contact(source.root_commitment())?;
        let (principal, signing_key) = self.pinned_peer(&source)?;
        let current = self.trusted_device(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            &source,
        )?;
        if principal != invite.inviter_principal_id
            || source.device_id() != invite.inviter_device_id
            || signing_key != invite.inviter_device_public_key_base64url
            || invite.guardian_principal_id != self.local_principal_id()?
            || current["device_epoch"].as_u64() != Some(invite.inviter_device_epoch)
            || invite.signed.signing_key_id != format!("device:{}", source.device_id())
            || invite.expires_at <= crate::time::now_unix_timestamp()
        {
            return Err(authority("pending guardian authority expired or changed"));
        }
        ramflux_protocol::verify_signed_fields(invite, &invite.signed, &signing_key)
            .map_err(|_| authority("pending guardian signature invalid"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> SdkGuardianInviteMessage {
        SdkGuardianInviteMessage {
            schema: INVITE_SCHEMA.into(),
            version: 1,
            invite_id: "invite/1".into(),
            inviter_principal_id: "owner".into(),
            inviter_device_id: "device".into(),
            inviter_device_epoch: 3,
            inviter_device_public_key_base64url: "key".into(),
            guardian_principal_id: "guardian".into(),
            recovery_quorum_id: "quorum".into(),
            share: SdkGuardianRecoveryShare {
                share_id: 1,
                threshold: 2,
                total: 3,
                member_kind: ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                value_base64: ramflux_protocol::encode_base64url([9u8; 32]),
            },
            issued_at: 10,
            expires_at: 20,
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "device".into(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "sig".into(),
            },
        }
    }

    #[test]
    fn guardian_invite_round_trips_native_fields_exactly() -> Result<(), SdkError> {
        let native = invite();
        let generated = invite_to_generated(&native)?;
        assert_eq!(invite_to_native(&generated)?, native);
        let mut wide = generated.clone();
        if let Some(share) = wide.share.as_mut() {
            share.share_id = 256;
        }
        assert!(invite_to_native(&wide).is_err(), "share id beyond u8 admitted");
        let mut kind = generated;
        if let Some(share) = kind.share.as_mut() {
            share.member_kind = Some(g::RecoveryQuorumMemberKind {
                value: Some(g::recovery_quorum_member_kind::Value::DeviceShare(
                    g::RecoveryQuorumMemberKindDeviceShare {},
                )),
            });
        }
        assert!(invite_to_native(&kind).is_err(), "non-guardian share admitted");
        Ok(())
    }

    #[test]
    fn guardian_keys_never_split_on_separator_bytes_in_ids() {
        assert_ne!(issued_key("a/b"), issued_key("a"));
        assert!(
            !issued_key("a/b").trim_start_matches("recovery/guardian-invite-issued/").contains('/')
        );
        assert_ne!(accept_key("x"), issued_key("x"));
    }
}

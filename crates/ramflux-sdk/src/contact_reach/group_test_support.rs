// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native account signatures and independently pinned fixture-home signatures; no transport claim.
use super::{ReachReadContext, VerifiedReachState};
use crate::{
    SdkError,
    client::native_test_support::{Fixture, TestResult},
    custody::{PrimaryVault, ReachCommandContext},
};
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::{
    contact_reach::{
        Decision, GROUP_JOIN_NOTICE_DOMAIN, GroupJoinNotice, Operation, Permissions, ReachMode,
        STATE_DOMAIN, STATE_PAGES_DOMAIN, StateManifest, StatePage, StateRecord, Subject,
        state_hash,
    },
    custody,
};

pub(super) fn sealing_state(
    client: &crate::RamfluxClient,
) -> TestResult<std::collections::BTreeMap<String, serde_json::Value>> {
    let db = client.account_db()?;
    let mut state = std::collections::BTreeMap::new();
    for prefix in ["dm-pair/", "own-history/", "delivery-receipt/"] {
        let keys = db.actor_state_key_page_after(prefix, "", 65)?;
        if keys.len() > 64 {
            return Err("sealing fixture exceeded its 64-row namespace bound".into());
        }
        for key in keys {
            let value =
                db.load_actor_state::<serde_json::Value>(&key)?.ok_or("actor disappeared")?;
            state.insert(key, value);
        }
    }
    Ok(state)
}
pub(super) struct UnavailableVault;
impl PrimaryVault for UnavailableVault {
    fn preflight(&self) -> Result<(), SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    fn store_new(
        &self,
        _reference: &str,
        _key: &ramflux_crypto::custody::SelfSigningKey,
    ) -> Result<(), SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    fn load_primary(
        &self,
        _reference: &str,
    ) -> Result<ramflux_crypto::custody::SelfSigningKey, SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    fn delete(&self, _reference: &str) -> Result<(), SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    fn store_branch(
        &self,
        _reference: &str,
        _seeds: &zeroize::Zeroizing<[u8; 64]>,
    ) -> Result<(), SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
}
pub(super) fn install_grant(peer: &Fixture, state: &VerifiedGroupState) -> TestResult {
    let account = peer.client.born_v3_account.as_ref().ok_or("native peer")?;
    let now = crate::custody::network_now()?;
    let subject = Subject::Group {
        group_id: state.view().group_id.clone(),
        conversation_id: state.view().conversation_id.clone(),
        genesis_hash: state.genesis_hash()?,
        group_epoch: state.view().epoch,
        membership_hash: state.snapshot().state_hash.clone(),
    };
    let home = ramflux_protocol::encode_base64url([24; 32]);
    let context = ReachCommandContext {
        actor: &account.record().body.master_certificate.body.primary_device_ref,
        home_head_hash: &home,
        expected_revision: 1,
        now,
    };
    let notice = GroupJoinNotice {
        version: 1,
        recipient_root: account.record().body.account_anchor.clone(),
        group_id: state.view().group_id.clone(),
        conversation_id: state.view().conversation_id.clone(),
        genesis_hash: state.genesis_hash()?,
        epoch: state.view().epoch,
        membership_hash: state.snapshot().state_hash.clone(),
        inviter_root: state.creator().identity.root_commitment.clone(),
        member_root_count: u64::try_from(
            state
                .view()
                .members
                .iter()
                .map(|member| &member.identity.root_commitment)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
        )?,
    };
    let mut body = account.reach_decision_body(&context, subject.clone(), Decision::Allow)?;
    body.permissions = Some(Permissions::UNACCEPTED);
    body.grant_until = Some(0);
    body.notice_hash = Some(custody::framed_hash(GROUP_JOIN_NOTICE_DOMAIN, &notice)?);
    body.evidence_hash = Some(state.snapshot().state_hash.clone());
    let update = account.group_primary(peer.vault.as_ref())?.sign_reach_admission(
        body,
        account.verified(),
        now,
    )?;
    let Operation::Policy { update: policy } = account.prepare_reach_policy(
        peer.vault.as_ref(),
        ReachCommandContext { expected_revision: 0, ..context },
        ReachMode::ContactsOnly,
    )?
    else {
        return Err("initial policy operation".into());
    };
    install_records(
        peer,
        &home,
        vec![
            StateRecord::Policy { revision: 1, update: policy },
            StateRecord::AdmissionMeta { revision: 2, last_update: Some(update.clone()) },
            StateRecord::Grant {
                subject,
                permissions: Permissions::UNACCEPTED,
                grant_until: 0,
                update,
            },
        ],
        now,
    )?;
    Ok(())
}

fn install_records(peer: &Fixture, home: &str, records: Vec<StateRecord>, now: u64) -> TestResult {
    let verified = verified_records(peer, home, records, now)?;
    peer.client.install_reach_state(verified)?;
    Ok(())
}

pub(super) fn verified_records(
    peer: &Fixture,
    home: &str,
    records: Vec<StateRecord>,
    now: u64,
) -> TestResult<VerifiedReachState> {
    let own = peer.client.owned_device_identity()?;
    let authority = peer
        .client
        .current_custody_authority(own.root_commitment(), now)?
        .ok_or("current native authority")?;
    let mut keyed = records
        .into_iter()
        .map(|record| Ok((record.order_key()?, record)))
        .collect::<Result<Vec<_>, ramflux_protocol::ProtocolError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let records: Vec<_> = keyed.into_iter().map(|(_, record)| record).collect();
    let root = &authority.envelope().body.account_anchor;
    let policy_revision = records
        .iter()
        .find_map(|record| match record {
            StateRecord::Policy { revision, .. } => Some(*revision),
            _ => None,
        })
        .ok_or("policy revision")?;
    let admission_revision = records
        .iter()
        .find_map(|record| match record {
            StateRecord::AdmissionMeta { revision, .. } => Some(*revision),
            _ => None,
        })
        .ok_or("admission revision")?;
    let revision =
        policy_revision.checked_add(admission_revision).ok_or("state revision overflow")?;
    let hash = state_hash(root, revision, policy_revision, admission_revision, &records)?;
    let count = u64::try_from(records.len())?;
    let snapshot_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let previous = peer
        .client
        .account_db()?
        .load_actor_state::<super::provenance::RetainedProofs>("reach/provenance")?;
    let provenance = fixture_provenance(&authority, revision, &hash, &records, previous.as_ref())?;
    let signers = provenance.signers.clone();
    let pages =
        vec![StatePage { version: 1, snapshot_id: snapshot_id.clone(), page: 0, records, signers }];
    let device = authority
        .envelope()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == own.device_id())
        .ok_or("requesting device")?;
    let requesting_device = custody::DeviceRef {
        account_anchor: root.clone(),
        device_id: own.device_id().into(),
        device_epoch: device.device_epoch,
    };
    let body = StateManifest {
        version: 1,
        account_anchor: root.clone(),
        requesting_device: requesting_device.clone(),
        home_head_hash: home.into(),
        authority_head_hash: custody::object_hash(authority.envelope())?,
        revision,
        policy_revision,
        admission_revision,
        snapshot_id,
        page_count: 1,
        record_count: count,
        pages_hash: custody::framed_hash(STATE_PAGES_DOMAIN, &pages)?,
        state_hash: hash,
        provenance_hash: custody::framed_hash(
            ramflux_protocol::contact_reach::STATE_CONTENT_DOMAIN,
            &provenance,
        )?,
        provenance_count: u64::try_from(provenance.authorities.len())?,
        provenance_bytes: u64::try_from(
            ramflux_protocol::canonical_json_bytes(&provenance)?.len(),
        )?,
        issued_at: now,
        expires_at: now.checked_add(60).ok_or("state lease overflow")?,
    };
    let node_seed = [26; 32];
    let node_key = ramflux_crypto::public_key_base64url_from_seed(node_seed);
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &custody::signing_bytes(STATE_DOMAIN, &body)?,
        node_seed,
    );
    let manifest = custody::Envelope { body, signature };
    let verified = VerifiedReachState::verify(
        &manifest,
        &pages,
        fixture_stage(&manifest, provenance)?,
        ReachReadContext {
            authority: &authority,
            device: &requesting_device,
            home_head_hash: home,
            home: None,
            home_node_key: &node_key,
            minimum_revision: 0,
            now,
        },
    )?;
    Ok(verified)
}

fn fixture_provenance(
    authority: &ramflux_crypto::custody::VerifiedRecord,
    revision: u64,
    hash: &str,
    records: &[StateRecord],
    previous: Option<&super::provenance::RetainedProofs>,
) -> TestResult<ramflux_protocol::contact_reach::Provenance> {
    let root = &authority.envelope().body.account_anchor;
    let mut proof = ramflux_protocol::contact_reach::ProvenanceAuthority {
        proof_hash: String::new(),
        authority: custody::CustodyAuthority {
            publication: custody::Publication {
                record: authority.envelope().clone(),
                compacted_ids: None,
            },
            custodian_publication: None,
        },
        custodian_history: vec![],
    };
    proof.proof_hash = proof.content_hash()?;
    let mut signers = std::collections::BTreeMap::new();
    let mut proofs = std::collections::BTreeMap::new();
    for record in records {
        for mut reference in ramflux_protocol::contact_reach::record_signers(record)? {
            let selected =
                if reference.authority_head_hash == custody::object_hash(authority.envelope())? {
                    &proof
                } else {
                    let pool = previous.ok_or("original historical fixture pool")?;
                    let old = pool
                        .signers
                        .iter()
                        .find(|old| {
                            old.object_kind == reference.object_kind
                                && old.object_hash == reference.object_hash
                        })
                        .ok_or("original historical fixture reference")?;
                    pool.authorities
                        .iter()
                        .find(|proof| proof.proof_hash == old.proof_hash)
                        .ok_or("original historical fixture proof")?
                };
            reference.proof_hash.clone_from(&selected.proof_hash);
            proofs.insert(selected.proof_hash.clone(), selected.clone());
            signers.insert((reference.object_kind, reference.object_hash.clone()), reference);
        }
    }
    let signers: Vec<_> = signers.into_values().collect();
    Ok(ramflux_protocol::contact_reach::Provenance {
        kind: ramflux_protocol::contact_reach::ProvenanceKind::ReachProvenance,
        version: 1,
        account_anchor: root.clone(),
        revision,
        state_hash: hash.to_owned(),
        signers: signers.clone(),
        authorities: proofs.into_values().collect(),
    })
}

pub(super) async fn roster_fixture() -> TestResult<(Fixture, Fixture, VerifiedGroupState)> {
    let owner = Fixture::new("reach-roster-owner").await?;
    let peer = Fixture::new("reach-roster-peer").await?;
    owner.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.persist_fetched_identity_directory(&owner.manifest)?;
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("owner account")?
        .group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        "roster-group",
        "roster-thread",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    let member = peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity;
    let joined = owner.client.shared_group_change_with_primary(
        "roster-group",
        &owner.config.target_delivery_id,
        ramflux_protocol::group_state::GroupStateChange::Add {
            member,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    peer.client.accept_shared_group_state(&joined, &peer.config.target_delivery_id)?;
    install_grant(&peer, &joined)?;
    Ok((owner, peer, joined))
}

fn fixture_stage(
    manifest: &custody::Envelope<StateManifest>,
    provenance: ramflux_protocol::contact_reach::Provenance,
) -> TestResult<ramflux_crypto::contact_reach::EncryptedProvenanceStage> {
    let mut stage = ramflux_crypto::contact_reach::ProvenanceStageBuilder::new(
        &manifest.body.account_anchor,
        manifest.body.revision,
        &manifest.body.state_hash,
        provenance.signers,
    )?;
    for proof in provenance.authorities {
        stage.push(&proof)?;
    }
    Ok(stage.finish()?)
}

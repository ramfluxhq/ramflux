// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-actor v3 SAS and real pre-Issue source owner; no complete transfer/Fedwire claim.
use super::super::{PairingConfig, PairingIdentity, assemble_chunks};
use super::*;
use ramflux_protocol::custody::pairing::context_v3::{DataSelectionV3, FullAccountData};
use ramflux_protocol::custody::pairing::native::{CreateSpec, Invitation};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(n: u8) -> String {
    encode_base64url([n; 32])
}
fn reference(id: &str) -> DeviceRef {
    DeviceRef { account_anchor: h(2), device_id: id.into(), device_epoch: 1 }
}
fn invitation() -> ResultOf<Invitation> {
    let now = crate::custody::network_now()?;
    let invitation = Invitation {
        schema: "ramflux.pairing.Invitation.v2".into(),
        version: 2,
        invitation_id: h(1),
        issuer_seq: 1,
        request_id: h(3),
        node_key: ramflux_crypto::public_key_base64url_from_seed([7; 32]),
        public_origin: "https://relay.example:443".into(),
        account_anchor: h(2),
        primary_ref: reference("A"),
        base_record_hash: h(4),
        base_epoch: 1,
        purpose: "primary_transfer".into(),
        recipient_mode: "existing".into(),
        destination_ref: Some(reference("B")),
        capabilities: vec!["message".into()],
        lease_not_before: now,
        lease_expires_at: now + 604_800,
        data_selection: Vec::new(),
        transfer_id: Some(h(5)),
        created_at: now,
        expires_at: now + 300,
    };
    invitation.validate()?;
    Ok(invitation)
}
fn ceremony(role: PairingRole) -> ResultOf<Ceremony> {
    let invitation = invitation()?;
    let master = ramflux_crypto::public_key_base64url_from_seed([10; 32]);
    let full = CommonV3::from_full_invitation(&invitation, master.clone())?;
    let common = invitation.project_common(master)?;
    let mut c = PairingActor::open_ceremony(CeremonyOpen {
        operation_id: h(3),
        generation: 1,
        role,
        origin: invitation.public_origin.clone(),
        invitation,
        verified_invite: None,
        token: Zeroizing::new(h(6)),
        common: Some(common),
        display_name: role.as_str().into(),
    });
    c.full = Some(FullCeremony::new(full, None));
    let seed = if role == PairingRole::Initiator { 70 } else { 71 };
    let reference = if role == PairingRole::Initiator { reference("A") } else { reference("B") };
    PairingActor::start_full_sas(
        &mut c,
        &reference,
        Some((
            ramflux_crypto::public_key_base64url_from_seed([seed; 32]),
            encode_base64url(X25519KeyPair::from_seed([seed; 32]).public),
        )),
    )?;
    Ok(c)
}
fn exchange_commits(a: &mut Ceremony, b: &mut Ceremony) -> ResultOf {
    PairingActor::queue_full_commit(a)?;
    PairingActor::queue_full_commit(b)?;
    let RelayFrame::Commit { value: ac } = a.outbound.pop_front().ok_or("A commit")? else {
        return Err("A commit".into());
    };
    let RelayFrame::Commit { value: bc } = b.outbound.pop_front().ok_or("B commit")? else {
        return Err("B commit".into());
    };
    ac.validate()?;
    bc.validate()?;
    PairingActor::ingest_full_commit(a, PairingRole::Responder, decode32(&bc.commitment)?)?;
    PairingActor::ingest_full_commit(b, PairingRole::Initiator, decode32(&ac.commitment)?)?;
    Ok(())
}
fn reveal(c: &mut Ceremony) -> ResultOf<Vec<u8>> {
    PairingActor::maybe_full_reveal(c)?;
    let mut chunks = Vec::new();
    for frame in c.outbound.drain(..) {
        let RelayFrame::RevealChunk { object_id, index, count, total_bytes, bytes } = frame else {
            return Err("reveal carrier".into());
        };
        chunks.push((index, object_id, count, total_bytes, bytes));
    }
    Ok(assemble_chunks(&chunks)?)
}
#[test]
fn pairing_full_actor_v3_sas_uses_owned_hpke_halves_and_same_committed_transcript() -> ResultOf {
    let mut a = ceremony(PairingRole::Initiator)?;
    let mut b = ceremony(PairingRole::Responder)?;
    PairingActor::maybe_full_reveal(&mut a)?;
    assert!(a.outbound.is_empty(), "revealed before peer commitment");
    exchange_commits(&mut a, &mut b)?;
    let ar = reveal(&mut a)?;
    let br = reveal(&mut b)?;
    PairingActor::finish_full_reveal(&mut a, &br)?;
    PairingActor::finish_full_reveal(&mut b, &ar)?;
    assert_eq!(a.displayed_th, b.displayed_th);
    assert_eq!(a.emoji, b.emoji);
    assert!(!a.local_confirmed && !b.local_confirmed && !a.peer_mac_ok && !b.peer_mac_ok);
    let at = a.full.as_ref().ok_or("A full")?;
    let bt = b.full.as_ref().ok_or("B full")?;
    let transcript = at.transcript.as_ref().ok_or("transcript")?;
    assert_eq!(Some(transcript), bt.transcript.as_ref());
    assert_eq!(
        transcript.initiator.hpke_key.as_deref(),
        Some(encode_base64url(at.hpke.as_ref().ok_or("A half")?.public_key()).as_str())
    );
    assert_eq!(
        transcript.responder.hpke_key.as_deref(),
        Some(encode_base64url(bt.hpke.as_ref().ok_or("B half")?.public_key()).as_str())
    );
    Ok(())
}
#[test]
fn pairing_full_actor_v2_reveal_refused_without_consuming_frozen_v3_attempt() -> ResultOf {
    let mut a = ceremony(PairingRole::Initiator)?;
    let mut b = ceremony(PairingRole::Responder)?;
    exchange_commits(&mut a, &mut b)?;
    let br = reveal(&mut b)?;
    let mut downgraded: serde_json::Value = ramflux_protocol::parse_i_json(&br)?;
    downgraded["version"] = 2.into();
    assert!(
        PairingActor::finish_full_reveal(
            &mut a,
            &ramflux_protocol::canonical_json_bytes(&downgraded)?
        )
        .is_err()
    );
    assert!(a.full.as_ref().ok_or("full")?.pending.is_some());
    PairingActor::finish_full_reveal(&mut a, &br)?;
    Ok(())
}
struct CountingNative {
    calls: Arc<AtomicUsize>,
    loan_released: Arc<AtomicBool>,
    owner: Arc<super::super::super::LocalPairingParticipant>,
}
impl super::super::super::PairingNative for CountingNative {
    fn issue(
        &self,
        _: CreateSpec,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<ramflux_protocol::custody::pairing::native::Issued, SdkError>,
                > + std::marker::Send,
        >,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.loan_released.store(self.owner.db.try_lock().is_ok(), Ordering::SeqCst);
        Box::pin(async { Err(SdkError::PairingCode("WrongContext")) })
    }
    fn create(
        &self,
        _: ramflux_protocol::custody::pairing::native::Create,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<ramflux_protocol::custody::pairing::native::Created, SdkError>,
                > + std::marker::Send,
        >,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(SdkError::PairingCode("WrongContext")) })
    }
}
#[tokio::test]
async fn pairing_full_begin_unknown_kind_refuses_before_issue_and_releases_source_loan() -> ResultOf
{
    let root = tempfile::tempdir()?;
    let owner =
        Arc::new(super::super::super::LocalPairingParticipant::full_test_participant(root.path())?);
    {
        let slot = owner.db.lock().map_err(|_| "DB")?;
        slot.as_ref().ok_or("DB")?.persist_actor_state("undeclared/full-begin-test", &true)?;
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let loan_released = Arc::new(AtomicBool::new(false));
    let native = Arc::new(CountingNative {
        calls: calls.clone(),
        loan_released: loan_released.clone(),
        owner: owner.clone(),
    });
    let now = crate::custody::network_now()?;
    let store = Arc::new(Mutex::new(ramflux_node_core::pairing_relay::PairingRelayStore::new(
        ramflux_node_core::pairing_relay::PairingRelayConfig {
            clock: ramflux_node_core::pairing_relay::TestPairingClock::new(now),
            node_seed: [7; 32],
            public_origin: "https://relay.example:443".into(),
        },
    )?));
    let mut actor = PairingActor::new(
        PairingIdentity {
            account_id: "acct".into(),
            local_ref: reference("A"),
            master_public_key: Some(h(10)),
            base_record_hash: h(4),
            base_epoch: 1,
            is_primary: true,
        },
        Some(native),
        Arc::new(super::super::super::tests::MemoryRelay { store }),
        PairingConfig { enabled: true, extra_root_ca_pem: None },
    );
    actor.set_participant(owner.clone());
    let begin = FullTransferBegin {
        schema: "ramflux.pairing.TransferBegin.v3".into(),
        version: 3,
        recipient_mode: "existing".into(),
        destination_ref: Some(reference("B")),
        capabilities: vec!["message".into()],
        lease_not_before: now,
        lease_expires_at: now + 604_800,
        data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
        transfer_profile: TransferProfile::FullAccountDataV1,
        display_name: "A".into(),
    };
    let error = actor.begin_full(begin.clone()).await.err().ok_or("unsupported actor accepted")?;
    assert_eq!(calls.load(Ordering::SeqCst), 0, "unknown kind allocated native invitation");
    assert!(
        matches!(&error, SdkError::PairingField("UnsupportedRecord")),
        "unexpected preflight refusal: {error}"
    );
    {
        let slot = owner.db.lock().map_err(|_| "DB")?;
        slot.as_ref().ok_or("DB")?.remove_actor_state("undeclared/full-begin-test")?;
    }
    assert!(actor.begin_full(begin).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "supported preflight never reached Issue");
    assert!(loan_released.load(Ordering::SeqCst), "native Issue retained the source DB loan");
    Ok(())
}

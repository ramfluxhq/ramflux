// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! ACK actors and mailbox coordinates remain bound to the account's owned root.
use super::review::trust;
use super::*;
use std::sync::{Arc, Mutex};
struct AckWire {
    captured: Arc<Mutex<Vec<ramflux_protocol::Ack>>>,
    responses: VecDeque<Vec<u8>>,
    target: String,
}
impl ramflux_transport::GatewaySessionFrameSink for AckWire {
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let GatewayClientFrame::Ack { ack } = serde_json::from_slice(bytes)? else {
                return Err(ramflux_transport::TransportError::Quic("expected ACK".into()));
            };
            let cursor = crate::GatewayCursor {
                target_delivery_id: self.target.clone(),
                inbox_seq: ack.ext.ext["inbox_seq"].as_u64().ok_or_else(|| {
                    ramflux_transport::TransportError::Quic("missing delivery sequence".into())
                })?,
                last_envelope_id: Some(ack.envelope_id.clone()),
                acked_envelope_ids: vec![ack.envelope_id.clone()],
                nacked_envelope_ids: std::collections::BTreeMap::default(),
            };
            self.captured
                .lock()
                .map_err(|_| ramflux_transport::TransportError::Quic("mutex".into()))?
                .push(ack);
            self.responses.push_back(serde_json::to_vec(&GatewayServerFrame::Ack {
                cursor: cursor.clone(),
            })?);
            self.responses.push_back(serde_json::to_vec(&GatewayServerFrame::Cursor {
                cursor: Some(cursor),
            })?);
            Ok(())
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSource for AckWire {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async {
            self.responses
                .pop_front()
                .ok_or_else(|| ramflux_transport::TransportError::Quic("missing response".into()))
        })
    }
}
#[tokio::test]
async fn exact_delivery_ack_is_signed_by_the_owned_device_and_carries_its_root()
-> Result<(), SdkError> {
    let receiver = Fixture::new("alice", 11)?;
    let sender = Fixture::new("bob", 31)?;
    trust(&sender, &receiver)?;
    let mut entry = seal(&sender, &receiver, message("same-envelope-id", "thread"), b"body")?;
    entry.inbox_seq = 42;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut engine = GatewaySessionEngine::with_test_transport(
        receiver.config()?,
        Box::new(AckWire {
            captured: Arc::clone(&captured),
            responses: VecDeque::new(),
            target: receiver.id.clone(),
        }),
    );
    let cursor =
        receiver.client.ack_gateway_entry(&mut engine, &entry, now_unix_timestamp()).await?;
    assert_eq!(cursor.inbox_seq, 42);
    let frames = captured.lock().map_err(|_| invalid("mutex"))?;
    assert_eq!(frames.len(), 1);
    let ack = &frames[0];
    let actor = receiver.client.owned_device_identity()?;
    assert_eq!(ack.receiver_device_id, actor.device_id());
    assert_eq!(ack.ext.ext["receiver_root_commitment"], actor.root_commitment());
    assert_eq!(ack.ext.ext["inbox_seq"], 42);
    let branch = receiver.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let bytes = ramflux_protocol::signed_bytes(ack)?;
    ramflux_crypto::verify_canonical_signature(
        &bytes,
        &ack.signed.signature,
        &ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes()),
    )?;
    assert!(
        ramflux_crypto::verify_canonical_signature(
            &bytes,
            &ack.signed.signature,
            &ramflux_crypto::fixture_public_key_base64url()
        )
        .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn copied_receiver_name_cannot_cross_an_account_root_or_rewrite_a_claim_before_io()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 11)?;
    let mallory = Fixture::owned("alice", "mallory", 51, 52)?;
    let mut engine =
        GatewaySessionEngine::with_test_transport(mallory.config()?, Box::new(NoNetwork));
    let actor = alice.client.owned_device_identity()?;
    let result = alice
        .client
        .ack_gateway_delivery(&mut engine, "message", &actor, now_unix_timestamp())
        .await;
    assert!(matches!(result, Err(SdkError::InboundRejected(_))));
    let mut engine =
        GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    let forged = crate::dm::gateway_ack(
        "message",
        &mallory.client.owned_device_identity()?,
        now_unix_timestamp(),
    );
    assert!(matches!(engine.ack(forged).await, Err(SdkError::InboundRejected(_))));
    Ok(())
}

#[test]
fn ack_cache_keeps_distinct_deliveries_with_the_same_envelope_id() -> Result<(), SdkError> {
    let mut receiver = Fixture::new("alice", 61)?;
    let bob = Fixture::new("bob", 71)?;
    let mallory = Fixture::owned("bob", "mallory", 81, 82)?;
    let mut first = seal(&mallory, &receiver, message("same-id", "thread"), b"mallory")?;
    first.inbox_seq = 1;
    let mut second = seal(&bob, &receiver, message("same-id", "thread"), b"bob")?;
    second.inbox_seq = 2;
    let config = receiver.config()?;
    let mut account = LocalBusAccountState::disconnected(
        std::mem::take(&mut receiver.client),
        config,
        "unused".into(),
    );
    assert_eq!(account.merge_deliveries(vec![first.clone()])?.len(), 1);
    account.mark_acked("same-id")?;
    assert_eq!(account.merge_deliveries(vec![first, second.clone()])?.len(), 1);
    assert_eq!(account.pending_page(10)[0].inbox_seq, 2);
    let db = account.client.account_db()?;
    let own = account.client.owned_device_identity()?;
    assert!(!db.has_gateway_ack(&own, &second.target_delivery_id, second.inbox_seq)?);
    Ok(())
}

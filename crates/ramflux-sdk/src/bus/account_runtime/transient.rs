// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The account actor consumes the host's single bounded transient inbox directly.
#[cfg(test)]
mod tests;
use super::AccountRuntime;
use crate::bus::state::LocalBusDaemonState;
use crate::client::identity_authority::HeadUse;
use crate::gateway::access::GatewaySessionAccess;
use crate::{EphemeralConsumer, EphemeralSource, GatewayInboxEntry, GatewayServerFrame};

fn wall_ms() -> u64 {
    #[cfg(test)]
    if let Some(now) = crate::time::test_clock::frozen() {
        return u64::try_from(now).unwrap_or(0).saturating_mul(1000);
    }
    crate::ephemeral::session::wall_ms()
}

#[derive(Default)]
pub(in crate::bus) struct TransientHost {
    generation: Option<u64>,
    consumer: Option<EphemeralConsumer>,
}

impl TransientHost {
    pub(super) async fn next(&mut self, state: &LocalBusDaemonState, id: &str) -> Option<Vec<u8>> {
        let Some(consumer) = self.consumer.as_mut() else {
            return std::future::pending().await;
        };
        let account = state.accounts.get(id)?;
        consumer
            .next(|envelope| {
                let entry = GatewayInboxEntry {
                    envelope: envelope.clone(),
                    forwarded: false,
                    inbox_seq: 0,
                    target_delivery_id: envelope.target_delivery_id.clone(),
                };
                let device = account
                    .client
                    .authenticated_device_identity(HeadUse::NewAuthorization, &entry)
                    .ok()?;
                let record = account
                    .client
                    .authenticated_sender_record(HeadUse::NewAuthorization, &entry)
                    .ok()?;
                Some(EphemeralSource {
                    device,
                    principal_id: record["principal_id"].as_str()?.into(),
                    signing_public_key: record["signing_public_key"].as_str()?.into(),
                })
            })
            .await
            .map(|(bytes, _gateway_expiry)| bytes)
    }
}

impl AccountRuntime {
    pub(super) async fn refresh_transient_host(&mut self) {
        let session = self
            .state
            .accounts
            .get(&self.id)
            .and_then(|account| account.live_session_client().ok());
        let generation =
            session.as_ref().map(crate::bus::connection_manager::SessionClient::generation);
        if generation == self.transient.generation {
            return;
        }
        self.clear_transient_host();
        self.transient = TransientHost { generation, consumer: None };
        if let Some(account) = self.state.accounts.get(&self.id) {
            account.client.reset_transient_content();
        }
        if crate::client::target_selection::schema_v1_selected()
            && let Some(mut session) = session
            && session.ephemeral_negotiated()
        {
            self.transient.consumer = session.take_ephemeral_consumer().await.ok().flatten();
        }
    }

    pub(super) fn apply_transient_frame(&mut self, frame: Option<Vec<u8>>) {
        if let Some(bytes) = frame {
            if let Ok(GatewayServerFrame::Ephemeral { envelope, .. }) =
                ramflux_protocol::parse_i_json(&bytes)
                && let Some(account) = self.state.accounts.get(&self.id)
                && account.connection.as_ref().is_some_and(|handle| {
                    Some(handle.generation()) == self.transient.generation
                        && handle.snapshot().state
                            == crate::bus::connection_manager::NetworkingState::Live
                })
            {
                // The content receiver rechecks current native authority and computes its
                // own lifetime. Peer refusals drop this item and never stop the actor.
                let _ = account.client.receive_transient_content(
                    &envelope,
                    &account.gateway_config.device_id,
                    wall_ms(),
                    tokio::time::Instant::now().into_std(),
                );
            }
            if let Some(consumer) = self.transient.consumer.as_mut() {
                consumer.complete();
            }
        } else {
            self.transient.consumer = None;
            self.clear_transient_host();
        }
        self.publish_transient_updates();
    }

    pub(super) fn clear_transient_host(&self) {
        if let Some(account) = self.state.accounts.get(&self.id) {
            account.client.clear_transient_indicators();
        }
        self.publish_transient_updates();
        if let Some(account) = self.state.accounts.get(&self.id) {
            account.client.reset_transient_content();
        }
    }

    pub(super) fn transient_deadline(&self) -> Option<tokio::time::Instant> {
        self.state
            .accounts
            .get(&self.id)?
            .client
            .next_transient_deadline(wall_ms(), tokio::time::Instant::now().into_std())
            .map(tokio::time::Instant::from_std)
    }

    pub(super) fn publish_transient_updates(&self) {
        let Some(account) = self.state.accounts.get(&self.id) else {
            return;
        };
        let Ok(updates) = account.client.drain_transient_updates(
            &self.id,
            wall_ms(),
            tokio::time::Instant::now().into_std(),
        ) else {
            return;
        };
        let events = updates
            .into_iter()
            .filter_map(|update| {
                let body = crate::bindings::encode_message_update(&update).ok()?;
                let mut event = crate::LocalBusFrame::request(
                    "",
                    Some(self.id.clone()),
                    "ramflux.sdk.v1",
                    ramflux_protocol::message::TRANSIENT_TOPIC,
                    body,
                );
                event.kind = crate::LocalBusFrameKind::Event;
                event.seq = Some(0);
                Some(event)
            })
            .collect::<Vec<_>>();
        if !events.is_empty() {
            // Leave one router slot for durable publication, as subscriber delivery does.
            if let Ok(permit) = self.events.try_reserve()
                && self.events.capacity() > 0
            {
                let (accepted, _done) = tokio::sync::oneshot::channel();
                permit.send(crate::bus::events::EventBatch { events, accepted });
            }
        }
    }
}

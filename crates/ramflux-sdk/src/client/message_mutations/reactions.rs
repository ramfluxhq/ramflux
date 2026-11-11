// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{RamfluxClient, SdkError, refused};
use ramflux_protocol::message as g;

const MAX_REGISTERS: usize = 2048;
const MAX_VISIBLE_PER_ROOT: usize = 8;
const PREFIX: &str = "routed/reaction/";

#[derive(serde::Serialize, serde::Deserialize)]
struct Register {
    identity: g::EventIdentity,
    reaction: g::Reaction,
}

impl RamfluxClient {
    /// Apply the immutable signed order to the root/token register, including absent markers.
    /// # Errors
    /// Refuses invalid identities, foreign targets and new keys beyond the register capacity.
    pub fn apply_generated_reaction_entry(
        &self,
        entry: &crate::GatewayInboxEntry,
        identity: &g::EventIdentity,
        conversation: &str,
        reaction: &g::Reaction,
    ) -> Result<bool, SdkError> {
        g::validation::validate_reaction_token(&reaction.token)
            .map_err(|_| refused("invalid reaction token"))?;
        g::identity::verify(identity).map_err(|_| refused("invalid reaction identity"))?;
        let order =
            g::identity::order_key(identity).map_err(|_| refused("reaction order missing"))?;
        let source = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            entry,
        )?;
        let source_epoch = self
            .account_db()?
            .client_device_record(&source)?
            .and_then(|record| record["device_epoch"].as_u64())
            .ok_or_else(|| refused("reaction source epoch unavailable"))?;
        let target = reaction.target.as_ref().ok_or_else(|| refused("reaction target missing"))?;
        let id = ramflux_protocol::encode_base64url(&target.id);
        if target.conversation_id != conversation
            || identity.conversation_id != conversation
            || reaction.operation_id != identity.id
            || order.account_anchor != source.root_commitment()
            || order.device_id != source.device_id()
            || order.device_epoch != source_epoch
        {
            return Err(SdkError::InboundRejected(
                "reaction identity or conversation mismatch".into(),
            ));
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            if db.message_is_deleted(&id)? {
                return Ok(false);
            }
            let row = self
                .direct_message_by_id(&id)?
                .ok_or_else(|| SdkError::InboundPending("message target missing".into()))?;
            if row.conversation_id != conversation
                || target.author_anchor
                    != self.generated_target_author(conversation, &id, row.is_own)?
            {
                return Err(SdkError::InboundRejected("reaction target author mismatch".into()));
            }
            let operation = format!(
                "routed/reaction-operation/{}/{}",
                source.root_commitment(),
                ramflux_protocol::encode_base64url(&reaction.operation_id)
            );
            if let Some(previous) = db.load_actor_state::<g::Reaction>(&operation)? {
                if previous != *reaction {
                    return Err(SdkError::ReplayMismatch);
                }
                return Ok(false);
            }
            let key = format!(
                "{PREFIX}{}",
                ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&(
                    target,
                    source.root_commitment(),
                    &reaction.token
                ))?)
            );
            if let Some(previous) = db.load_actor_state::<Register>(&key)? {
                let previous_order = g::identity::order_key(&previous.identity)
                    .map_err(|_| refused("stored reaction order missing"))?;
                if order <= previous_order {
                    return Ok(false);
                }
            } else if db.message_actor_keys(&id, PREFIX)?.len() >= MAX_REGISTERS {
                return Err(SdkError::InboundRejected("reaction register limit reached".into()));
            }
            // Greater no-op writes still advance the marker, preventing an older opposite intent.
            db.persist_message_actor_state(
                &id,
                &key,
                &Register { identity: identity.clone(), reaction: reaction.clone() },
            )?;
            db.persist_message_actor_state(&id, &operation, reaction)?;
            Ok(true)
        })
    }

    /// Deterministic visible selection; capacity counts absent markers as well as present ones.
    /// # Errors
    /// Returns storage or malformed stored-register errors.
    pub fn generated_visible_reactions(
        &self,
        message_id: &str,
    ) -> Result<Vec<g::Reaction>, SdkError> {
        let mut registers = self
            .account_db()?
            .message_actor_entries::<Register>(message_id, PREFIX)?
            .into_iter()
            .map(|(_, register)| {
                Ok((
                    g::identity::order_key(&register.identity)
                        .map_err(|_| refused("stored reaction order missing"))?,
                    register.reaction,
                ))
            })
            .collect::<Result<Vec<_>, SdkError>>()?;
        registers.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.token.cmp(&b.1.token)));
        let mut counts = std::collections::BTreeMap::<String, usize>::new();
        Ok(registers
            .into_iter()
            .filter_map(|(order, reaction)| {
                if reaction.remove {
                    return None;
                }
                let count = counts.entry(order.account_anchor).or_default();
                if *count >= MAX_VISIBLE_PER_ROOT {
                    return None;
                }
                *count += 1;
                Some(reaction)
            })
            .collect())
    }
}

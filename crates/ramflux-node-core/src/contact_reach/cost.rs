// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persisted, bounded challenges consumed by the same writer transaction as first admission.
use super::{
    Result, refuse, storage,
    store::{encoded, row},
};
use crate::{MigrationNode, RouterRedbStore};
use ed25519_dalek::Signer;
use ramflux_protocol::{
    contact_reach::*,
    custody::{self, Envelope as Signed},
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

const CHALLENGES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_challenges_v1");
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Issued {
    expires: u64,
    consumed: Option<String>,
}

pub(super) fn consume(
    tx: &redb::WriteTransaction,
    cost: &Cost,
    operation: &str,
    now: u64,
) -> Result<()> {
    let hash = custody::framed_hash(COST_CONTEXT_DOMAIN, &cost.challenge)?;
    let mut table = tx.open_table(CHALLENGES).map_err(storage)?;
    let mut issued: Issued = table
        .get(hash.as_str())
        .map_err(storage)?
        .map(|v| row(v.value()))
        .transpose()?
        .ok_or_else(|| refuse(Reason::CostInvalid))?;
    if issued.expires <= now || issued.consumed.as_ref().is_some_and(|old| old != operation) {
        return Err(refuse(Reason::CostInvalid));
    }
    issued.consumed = Some(operation.into());
    table.insert(hash.as_str(), encoded(&issued)?.as_slice()).map_err(storage)?;
    Ok(())
}

impl RouterRedbStore {
    /// Issue a fresh signed puzzle without allocating authority or reserving a name.
    /// The caller authenticates the source home and applies source-prefix/node issue limits.
    /// # Errors
    /// Refuses malformed purposes and full unexpired challenge storage.
    pub fn reach_issue_cost(
        &self,
        node: &MigrationNode,
        request: &ChallengeRequest,
        now: u64,
    ) -> Result<Signed<Challenge>> {
        request.validate()?;
        let nonce = ramflux_crypto::random_32()?;
        let tx = self.begin_write()?;
        let now = super::store::clock(&tx, now)?;
        let expires =
            now.checked_add(COMMAND_LIFETIME).ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let body = Challenge {
            version: 1,
            issuer: node.node_id().into(),
            purpose: request.purpose,
            source_root: request.source_root.clone(),
            recipient_root: request.recipient_root.clone(),
            operation_hash: request.operation_hash.clone(),
            nonce: ramflux_protocol::encode_base64url(nonce),
            difficulty: u64::from(request.purpose.difficulty()),
            issued_at: now,
            expires_at: expires,
        };
        body.validate()?;
        let signature = ramflux_protocol::encode_base64url(
            node.key.sign(&custody::signing_bytes(COST_DOMAIN, &body)?).to_bytes(),
        );
        let signed = Signed { body, signature };
        let mut table = tx.open_table(CHALLENGES).map_err(storage)?;
        let rows = table
            .iter()
            .map_err(storage)?
            .take(4096)
            .map(|e| {
                let (k, v) = e.map_err(storage)?;
                Ok((k.value().to_owned(), row::<Issued>(v.value())?))
            })
            .collect::<Result<Vec<_>>>()?;
        for (key, issued) in rows {
            if issued.expires.checked_add(60).is_some_and(|e| e <= now) {
                table.remove(key.as_str()).map_err(storage)?;
            }
        }
        if table.len().map_err(storage)? >= 4096 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        table
            .insert(
                custody::framed_hash(COST_CONTEXT_DOMAIN, &signed)?.as_str(),
                encoded(&Issued { expires, consumed: None })?.as_slice(),
            )
            .map_err(storage)?;
        drop(table);
        tx.commit()?;
        Ok(signed)
    }
}

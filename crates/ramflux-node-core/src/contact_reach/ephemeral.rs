// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile contact routing reads adopted state and never creates a durable authority/payload sink.
use super::{AccountReach, Result, refuse, storage};
use crate::{RouterCore, RouterRedbStore, custody_authority::CustodyAccountState};
use ramflux_protocol::{
    contact_reach::{ReachEphemeral, Reason},
    custody::{self, CustodyAuthority, DeviceRef, Publication},
};
use redb::{ReadableDatabase, TableDefinition};
use std::{collections::BTreeMap, sync::Mutex};

const FOREIGN: TableDefinition<&str, &[u8]> = TableDefinition::new("foreign_custody_pins_v1");
const LOCAL: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_accounts_v3");

/// Observed transport facts, never selected from the signed route body.
#[derive(Clone, Copy)]
pub struct ReachEphemeralContext<'a> {
    pub peer_node: &'a str,
    pub local_source: bool,
    pub now_ms: u64,
}
#[derive(Default)]
pub struct ReachEphemeralAdmission {
    rates: Mutex<BTreeMap<String, (u64, u64)>>,
}
fn state(tx: &redb::ReadTransaction, root: &str, local: bool) -> Result<CustodyAccountState> {
    let table = tx.open_table(if local { LOCAL } else { FOREIGN }).map_err(storage)?;
    table
        .get(root)
        .map_err(storage)?
        .map(|v| serde_json::from_slice(v.value()).map_err(storage))
        .transpose()?
        .ok_or_else(|| refuse(Reason::ForeignReadRefused))
}
fn verify_authority(
    tx: &redb::ReadTransaction,
    root: &str,
    local: bool,
    now: u64,
) -> Result<ramflux_crypto::custody::VerifiedRecord> {
    let account = state(tx, root, local)?;
    let cert = &account.publication.record.body.master_certificate.body;
    let human = if cert.custody_kind == custody::CustodyKind::ExternalHuman {
        Some(state(tx, &cert.primary_device_ref.account_anchor, local)?)
    } else {
        None
    };
    let publication = |s: &CustodyAccountState| Publication {
        record: s.publication.record.clone(),
        compacted_ids: s.publication.compacted_ids.clone(),
    };
    let authority = ramflux_crypto::custody::verify_publication(
        &CustodyAuthority {
            publication: publication(&account),
            custodian_publication: human.as_ref().map(publication),
        },
        now,
    )?;
    account.pins.require_current(&authority)?;
    if let Some(human) = human {
        let verified = ramflux_crypto::custody::verify_record(
            &human.publication.record,
            now,
            human.publication.compacted_ids.as_deref(),
            None,
        )?;
        human.pins.require_current(&verified)?;
    }
    Ok(authority)
}
impl ReachEphemeralAdmission {
    /// Validate recipient/source/settings under read-only state, then enter the existing volatile route.
    /// `local_source` is selected from authenticated transport context, never the frame body.
    /// # Errors
    /// Refuses unknown source authority, nonlocal targets, missing grants/settings and rate pressure.
    pub fn route(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        frame: &ReachEphemeral,
        context: ReachEphemeralContext<'_>,
    ) -> Result<crate::EphemeralRouteResult> {
        let ReachEphemeralContext { peer_node, local_source, now_ms } = context;
        frame.validate(now_ms)?;
        let b = &frame.route.body;
        let tx = store.migration_db().begin_read().map_err(storage)?;
        let source = verify_authority(&tx, &b.source.account_anchor, local_source, now_ms / 1000)?;
        let recipient = verify_authority(&tx, &b.recipient_root, true, now_ms / 1000)?;
        ramflux_crypto::contact_reach::verify_ephemeral(frame, &source, now_ms)?;
        let (root, device) =
            ramflux_protocol::parse_qualified_device_id(&frame.frame.envelope.target_delivery_id)?
                .ok_or_else(|| refuse(Reason::ReachRouteInvalid))?;
        if root != b.recipient_root {
            return Err(refuse(Reason::ReachRouteInvalid));
        }
        let target = recipient
            .envelope()
            .body
            .devices
            .iter()
            .find(|d| d.device_id == device)
            .ok_or_else(|| refuse(Reason::ReachRouteInvalid))?;
        recipient.authorize(
            &DeviceRef {
                account_anchor: root,
                device_id: device,
                device_epoch: target.device_epoch,
            },
            "message",
            now_ms / 1000,
        )?;
        let table = tx.open_table(super::store::ACCOUNTS).map_err(storage)?;
        let state: AccountReach = table
            .get(b.recipient_root.as_str())
            .map_err(storage)?
            .map(|v| serde_json::from_slice(v.value()).map_err(storage))
            .transpose()?
            .ok_or_else(|| refuse(Reason::ReachPolicyRequired))?;
        state.classify(b, peer_node, now_ms / 1000)?;
        let mut rates = self.rates.lock().map_err(storage)?;
        let window = now_ms / 60_000;
        rates.retain(|_, (old, _)| *old >= window);
        for (key, cap) in [
            (format!("recipient:{}", b.recipient_root), 1000),
            (format!("source:{}:{}", b.source.account_anchor, b.recipient_root), 100),
        ] {
            if !rates.contains_key(&key) && rates.len() >= 4096 {
                return Err(refuse(Reason::ForeignCapacity));
            }
            let (_, count) = rates.entry(key).or_insert((window, 0));
            if *count >= cap {
                return Err(refuse(Reason::ForeignRateLimited));
            }
            *count += 1;
        }
        drop(rates);
        drop(table);
        drop(tx);
        let view = router.ephemeral_view();
        let result = match view.route_gate(&frame.frame.envelope.target_delivery_id) {
            crate::EphemeralRouteGate::Online { gateway_id, session_id } => view
                .admit_routed_replay(
                    &frame.frame.envelope,
                    frame.frame.expires_at_ms,
                    now_ms,
                    gateway_id,
                    session_id,
                ),
            crate::EphemeralRouteGate::Offline => {
                crate::EphemeralRouteResult::Dropped(crate::EphemeralDropReason::Offline)
            }
            crate::EphemeralRouteGate::RecipientUnsupported => {
                crate::EphemeralRouteResult::Dropped(
                    crate::EphemeralDropReason::RecipientUnsupported,
                )
            }
        };
        Ok(result)
    }
}

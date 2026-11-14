// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only current source, home, recipient and optional-signal authorization.
use super::ReachEphemeralContext;
use crate::{
    RouterRedbStore,
    contact_reach::{AccountReach, Result, refuse, storage},
    custody_authority::CustodyAccountState,
};
use ramflux_protocol::{
    contact_reach::{ReachEphemeral, Reason},
    custody::{self, CustodyAuthority, DeviceRef, Publication},
};
use redb::{ReadableDatabase, TableDefinition};
const FOREIGN: TableDefinition<&str, &[u8]> = TableDefinition::new("foreign_custody_pins_v1");
const LOCAL: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_accounts_v3");

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

fn reach_state(tx: &redb::ReadTransaction, root: &str) -> Result<AccountReach> {
    tx.open_table(crate::contact_reach::store::ACCOUNTS)
        .map_err(storage)?
        .get(root)
        .map_err(storage)?
        .map(|value| serde_json::from_slice(value.value()).map_err(storage))
        .transpose()?
        .ok_or_else(|| refuse(Reason::ReachPolicyRequired))
}

pub(super) fn require(
    store: &RouterRedbStore,
    frame: &ReachEphemeral,
    context: ReachEphemeralContext<'_>,
) -> Result<()> {
    let ReachEphemeralContext { node, peer_node, local_source, now_ms } = context;
    let b = &frame.route.body;
    let tx = store.migration_db().begin_read().map_err(storage)?;
    let source = verify_authority(&tx, &b.source.account_anchor, local_source, now_ms / 1000)?;
    let recipient = verify_authority(&tx, &b.recipient_root, true, now_ms / 1000)?;
    ramflux_crypto::contact_reach::verify_ephemeral(frame, &source, now_ms)?;
    crate::contact_reach::store::require_ephemeral_local_home(&tx, node, &b.recipient_root)?;
    if local_source {
        if peer_node != node.node_id() {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        crate::contact_reach::store::require_ephemeral_local_home(
            &tx,
            node,
            &b.source.account_anchor,
        )?;
        let source_state = reach_state(&tx, &b.source.account_anchor)?;
        crate::contact_reach::submit::require_return_grant(
            &source_state,
            b,
            &source,
            node.node_id(),
            now_ms / 1000,
        )?;
    } else {
        crate::contact_reach::store::require_adopted_source_home(
            &tx,
            &b.recipient_root,
            &source,
            peer_node,
        )?;
    }
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
        &DeviceRef { account_anchor: root, device_id: device, device_epoch: target.device_epoch },
        "message",
        now_ms / 1000,
    )?;
    let state = reach_state(&tx, &b.recipient_root)?;
    state.classify_current(b, peer_node, &recipient, now_ms / 1000)?;
    Ok(())
}

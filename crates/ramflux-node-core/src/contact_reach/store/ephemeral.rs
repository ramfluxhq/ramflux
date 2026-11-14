// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile source/home binding reads only previously adopted authority; it cannot install pins.
use super::{AdoptedPeer, HEADS, Reason, Result, TRUST, key, refuse, row, storage};
use crate::MigrationNode;
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::{custody, home_migration::RecordEvidence};

pub(in crate::contact_reach) fn require_ephemeral_local_home(
    tx: &redb::ReadTransaction,
    node: &MigrationNode,
    root: &str,
) -> Result<()> {
    let table = match tx.open_table(HEADS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        Err(error) => return Err(storage(error)),
    };
    let home: RecordEvidence = table
        .get(root)
        .map_err(storage)?
        .map(|value| row(value.value()))
        .transpose()?
        .ok_or_else(|| refuse(Reason::ForeignReadRefused))?;
    if home.record.account_anchor() != root
        || home.record.home() != (node.node_id(), node.public_key())
    {
        return Err(refuse(Reason::ForeignReadRefused));
    }
    Ok(())
}

pub(in crate::contact_reach) fn require_adopted_source_home(
    tx: &redb::ReadTransaction,
    recipient: &str,
    source: &VerifiedRecord,
    peer_node: &str,
) -> Result<()> {
    let table = match tx.open_table(TRUST) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        Err(error) => return Err(storage(error)),
    };
    let root = &source.envelope().body.account_anchor;
    let adopted: AdoptedPeer = table
        .get(key(recipient, root)?.as_str())
        .map_err(storage)?
        .map(|value| row(value.value()))
        .transpose()?
        .ok_or_else(|| refuse(Reason::ForeignReadRefused))?;
    if adopted.home.record.account_anchor() != root || adopted.home.record.home().0 != peer_node {
        return Err(refuse(Reason::ForeignReadRefused));
    }
    adopted.authority_pins.require_current(source)?;
    let certificate = &source.envelope().body.master_certificate.body;
    if certificate.custody_kind == custody::CustodyKind::ExternalHuman {
        let human = source.management_actor_authority(&certificate.primary_device_ref)?;
        adopted.custodian_pins.require_current(human)?;
    }
    Ok(())
}

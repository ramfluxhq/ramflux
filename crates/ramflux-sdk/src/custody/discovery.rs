// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded predecessor discovery before advancing durable receiving-node pins.
use super::{
    network::{CustodyNetworkConfig, exchange, now},
    node_pins::NodePins,
};
use crate::SdkError;
use ramflux_protocol::custody::{
    CustodyClientFrame, CustodyRefusal, CustodyServerFrame, Envelope, NodeIdentityRecord,
};
use ramflux_transport::GatewayTcpTlsStream;
use std::collections::BTreeSet;
const MAX_CHAIN_RECORDS: usize = 64;
pub(super) async fn authenticate(
    config: &CustodyNetworkConfig,
    stream: &mut GatewayTcpTlsStream,
    record: Envelope<NodeIdentityRecord>,
) -> Result<NodePins, SdkError> {
    let root = config.account_root.clone();
    let id = config.node_id.clone();
    let public = config.node_public_key.clone();
    let (pins, head) = tokio::task::spawn_blocking(move || {
        let pins = NodePins::new(&root, &id, &public)?;
        let head = pins.current_hash()?;
        Ok::<_, SdkError>((pins, head))
    })
    .await
    .map_err(|_| SdkError::CustodySetupInvalid)??;
    let mut chain = vec![record];
    let mut seen = BTreeSet::new();
    loop {
        let current = chain.last().ok_or(SdkError::CustodySetupInvalid)?;
        let verified = ramflux_crypto::custody::verify_node_identity_record(
            current,
            &config.node_id,
            &config.node_public_key,
            now()?,
        )?;
        if !seen.insert(verified.hash().to_string()) {
            return Err(CustodyRefusal::UpdateRequired.into());
        }
        if head.is_none()
            || head.as_deref() == Some(verified.hash())
            || current.body.previous_record_hash == head
        {
            break;
        }
        if chain.len() >= MAX_CHAIN_RECORDS {
            return Err(CustodyRefusal::UpdateRequired.into());
        }
        let hash =
            current.body.previous_record_hash.as_ref().ok_or(CustodyRefusal::UpdateRequired)?;
        let response = exchange(
            stream,
            &CustodyClientFrame::NodeIdentity { record_hash: Some(hash.clone()) },
            config.timeout,
        )
        .await?;
        let CustodyServerFrame::NodeIdentity { record, .. } = response else {
            return Err(CustodyRefusal::AuthorityUnavailable.into());
        };
        if ramflux_protocol::custody::object_hash(&record)? != *hash {
            return Err(CustodyRefusal::BindingRefused.into());
        }
        chain.push(*record);
    }
    tokio::task::spawn_blocking(move || {
        for record in chain.iter().rev() {
            pins.observe(record, now()?)?;
        }
        Ok::<_, SdkError>(pins)
    })
    .await
    .map_err(|_| SdkError::CustodySetupInvalid)?
}

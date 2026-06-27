// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::{BTreeMap, BTreeSet};

use crate::SyncError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeTrustStatus {
    Invited,
    Active,
    Suspended,
    Revoked,
    Migrated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationNode {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: String,
    pub trust_status: NodeTrustStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationMessage {
    pub from_identity: String,
    pub to_identity: String,
    pub body_ciphertext: Vec<u8>,
    pub via_node: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HomeNodeMigration {
    pub identity: String,
    pub old_home_node: String,
    pub new_home_node: String,
    pub proof_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverDelivery {
    pub delivered_to: String,
    pub used_forward: bool,
    pub used_nack_reresolve: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FederationMesh {
    nodes: BTreeMap<String, FederationNode>,
    identity_home: BTreeMap<String, String>,
    trusted_links: BTreeSet<(String, String)>,
    messages: Vec<FederationMessage>,
    zero_directory_invites: BTreeMap<String, FederationNode>,
    forwarding: BTreeMap<String, String>,
}

impl FederationMesh {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_node(&mut self, node_id: &str, endpoint: &str) -> FederationNode {
        let node = FederationNode {
            node_id: node_id.to_owned(),
            public_key: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::FEDERATION_HANDSHAKE,
                node_id.as_bytes(),
            ),
            endpoint: endpoint.to_owned(),
            trust_status: NodeTrustStatus::Invited,
        };
        self.nodes.insert(node_id.to_owned(), node.clone());
        node
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn establish_trusted_link(&mut self, left: &str, right: &str) -> Result<(), SyncError> {
        self.set_node_status(left, NodeTrustStatus::Active)?;
        self.set_node_status(right, NodeTrustStatus::Active)?;
        self.trusted_links.insert(canonical_link(left, right));
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn set_node_status(
        &mut self,
        node_id: &str,
        status: NodeTrustStatus,
    ) -> Result<(), SyncError> {
        let node = self.nodes.get_mut(node_id).ok_or(SyncError::RouteNotFound)?;
        node.trust_status = status;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn bind_identity_home(&mut self, identity: &str, node_id: &str) -> Result<(), SyncError> {
        self.ensure_active(node_id)?;
        self.identity_home.insert(identity.to_owned(), node_id.to_owned());
        Ok(())
    }

    pub fn add_zero_directory_invite(&mut self, identity: &str, node: FederationNode) {
        self.zero_directory_invites.insert(identity.to_owned(), node);
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn resolve_home_node(&mut self, identity: &str) -> Result<String, SyncError> {
        if let Some(node_id) = self.identity_home.get(identity) {
            return Ok(node_id.clone());
        }
        let node =
            self.zero_directory_invites.get(identity).cloned().ok_or(SyncError::RouteNotFound)?;
        let node_id = node.node_id.clone();
        self.nodes.insert(node_id.clone(), node);
        self.identity_home.insert(identity.to_owned(), node_id.clone());
        Ok(node_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn send_cross_node_friend_request(
        &mut self,
        requester: &str,
        target: &str,
    ) -> Result<String, SyncError> {
        let requester_node = self.resolve_home_node(requester)?;
        let target_node = self.resolve_home_node(target)?;
        self.ensure_trusted(&requester_node, &target_node)?;
        Ok(format!("{requester}->{target}"))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn send_cross_node_message(
        &mut self,
        from_identity: &str,
        to_identity: &str,
        body_ciphertext: &[u8],
    ) -> Result<FederationMessage, SyncError> {
        let from_node = self.resolve_home_node(from_identity)?;
        let to_node = self.resolve_home_node(to_identity)?;
        self.ensure_trusted(&from_node, &to_node)?;
        self.ensure_active(&to_node)?;
        let message = FederationMessage {
            from_identity: from_identity.to_owned(),
            to_identity: to_identity.to_owned(),
            body_ciphertext: body_ciphertext.to_vec(),
            via_node: to_node,
        };
        self.messages.push(message.clone());
        Ok(message)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn revoke_trust(&mut self, node_id: &str) -> Result<(), SyncError> {
        self.set_node_status(node_id, NodeTrustStatus::Revoked)
    }

    /// # Errors
    /// Returns an error when the target home node is not active.
    pub fn migrate_home_node(
        &mut self,
        migration: HomeNodeMigration,
    ) -> Result<HomeNodeMigration, SyncError> {
        self.ensure_active(&migration.new_home_node)?;
        self.identity_home.insert(migration.identity.clone(), migration.new_home_node.clone());
        self.forwarding.insert(migration.old_home_node.clone(), migration.new_home_node.clone());
        self.set_node_status(&migration.old_home_node, NodeTrustStatus::Migrated)?;
        Ok(migration)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn deliver_during_cutover(
        &mut self,
        from_identity: &str,
        to_identity: &str,
        attempted_old_node: &str,
        body_ciphertext: &[u8],
    ) -> Result<CutoverDelivery, SyncError> {
        let current_home = self.resolve_home_node(to_identity)?;
        if let Some(forward_to) = self.forwarding.get(attempted_old_node).cloned() {
            let from_node = self.resolve_home_node(from_identity)?;
            self.ensure_trusted(&from_node, &forward_to)?;
            self.messages.push(FederationMessage {
                from_identity: from_identity.to_owned(),
                to_identity: to_identity.to_owned(),
                body_ciphertext: body_ciphertext.to_vec(),
                via_node: forward_to.clone(),
            });
            Ok(CutoverDelivery {
                delivered_to: forward_to,
                used_forward: true,
                used_nack_reresolve: false,
            })
        } else if current_home != attempted_old_node {
            let message =
                self.send_cross_node_message(from_identity, to_identity, body_ciphertext)?;
            Ok(CutoverDelivery {
                delivered_to: message.via_node,
                used_forward: false,
                used_nack_reresolve: true,
            })
        } else {
            let message =
                self.send_cross_node_message(from_identity, to_identity, body_ciphertext)?;
            Ok(CutoverDelivery {
                delivered_to: message.via_node,
                used_forward: false,
                used_nack_reresolve: false,
            })
        }
    }

    #[must_use]
    pub fn heal_group_partition(
        &self,
        left_members: &BTreeSet<String>,
        right_members: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        left_members.intersection(right_members).cloned().collect()
    }

    fn ensure_trusted(&self, left: &str, right: &str) -> Result<(), SyncError> {
        self.ensure_active(left)?;
        self.ensure_active(right)?;
        if self.trusted_links.contains(&canonical_link(left, right)) {
            Ok(())
        } else {
            Err(SyncError::NodeTrustRejected)
        }
    }

    fn ensure_active(&self, node_id: &str) -> Result<(), SyncError> {
        match self.nodes.get(node_id).map(|node| node.trust_status) {
            Some(NodeTrustStatus::Active | NodeTrustStatus::Migrated) => Ok(()),
            _ => Err(SyncError::NodeTrustRejected),
        }
    }
}

fn canonical_link(left: &str, right: &str) -> (String, String) {
    if left <= right {
        (left.to_owned(), right.to_owned())
    } else {
        (right.to_owned(), left.to_owned())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The single classification and routing registry for local bus methods.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MethodClass {
    LocalRead,
    LocalMutation,
    LocalFirst,
    NeedsNetwork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MethodRoute {
    Reader,
    Actor,
    Lifecycle,
    Supervisor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Method {
    pub name: &'static str,
    pub class: MethodClass,
    pub route: MethodRoute,
    pub network: NetworkCondition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NetworkCondition {
    Always,
    RelaySelected,
}

macro_rules! methods {
    ($( $class:ident ($condition:ident) => $route:ident: [$($name:literal),* $(,)?]; )*) => {
        pub(super) const METHODS: &[Method] = &[
            $($(Method { name: $name, class: MethodClass::$class, route: MethodRoute::$route, network:NetworkCondition::$condition },)*)*
        ];
        pub(super) fn classify(name: &str) -> Option<Method> {
            static LOOKUP: std::sync::OnceLock<std::collections::HashMap<&'static str, Method>> =
                std::sync::OnceLock::new();
            LOOKUP.get_or_init(|| METHODS.iter().map(|entry| (entry.name, *entry)).collect())
                .get(name).copied()
        }
    };
}

methods! {
    LocalRead(Always) => Actor: ["account.config.get"];
    NeedsNetwork(RelaySelected) => Actor: ["object.put", "object.put.finish", "object.delete"];
    LocalFirst(Always) => Actor: ["object.get", "object.get.begin"];
    LocalRead(Always) => Actor: ["a2i.list_pending"];
    LocalMutation(Always) => Actor: [
        "account.config.set",
        "a2i.acknowledge",
        "a2ui.action",
        "a2ui.render",
        "bot.install",
        "bot.revoke",
        "bot.trust.add",
        "call.media.session",
        "contact.block",
        "contact.card.export",
        "contact.decline",
        "contact.reject",
        "contact.remove",
        "contact.request.block",
        "contact.request.decline",
        "contact.requests.policy.set",
        "contact.unblock",
        "conversation.disappearing.expire",
        "conversation.disappearing.set",
        "conversation.mute",
        "device.pair.cancel",
        "device.pair.confirm",
        "grant.approve",
        "grant.create_standing_approval",
        "grant.deny",
        "grant.request",
        "grant.revoke",
        "grant.revoke_standing_approval",
        "group.invitation.accept",
        "group.invitation.decline",
        "group.sender_key.export",
        "group.sender_key.import",
        "itest.migration.approve_once",
        "mcp.approval.denied",
        "mcp.approval.granted",
        "mcp.server.add",
        "mcp.tool.started",
        "message.focus", "message.delete",
        "message.receipt.delivered",
        "message.receipt.read",
        "object.get.finish",
        "object.get.read",
        "object.put.begin",
        "object.put.chunk",
        "task.decision.prove",
    ];
    LocalMutation(Always) => Lifecycle: [
        "account.lock",
        "account.passphrase.rotate",
        "account.unlock",
    ];
    LocalMutation(Always) => Supervisor: [
        "account.backup.export",
        "account.backup.import",
        "account.export_agent_credentials",
        "account.switch",
        "daemon.stop",
        "node.confirm",
        "node.remove",
        "node.set_default",
        "node.set_enabled",
        "subscription.open",
    ];
    LocalRead(Always) => Reader: [
        "a2i.list",
        "account.status",
        "bot.list",
        "bus.subscribe",
        "call.list",
        "contact.list",
        "contact.rejected",
        "contact.requests.list",
        "contact.requests.policy.get",
        "contact.verification.status",
        "conversation.directory",
        "conversation.list",
        "device.list",
        "device.pair.status",
        "grant.list",
        "grant.list_standing_approvals",
        "group.invitations.list",
        "group.list",
        "group.history",
        "group.members",
        "group.requests.list",
        "identity.directory",
        "mcp.approval.list",
        "mcp.audit.list",
        "mcp.server.list",
        "mcp.server.refresh",
        "mcp.tool.list",
        "message.franking_evidence",
        "message.list",
        "message.read",
        "object.directory",
        "object.get.status",
        "object.list",
        "object.put.status",
        "object.transfer.status",
        "stream.read",
        "surface.get",
        "surface.list",
        "sync.status.get",
        "task.get",
        "task.list",
    ];
    LocalRead(Always) => Supervisor: [
        "account.list",
        "daemon.status",
        "node.list",
    ];
    NeedsNetwork(Always) => Actor: [
        "a2i.append",
        "call.answer",
        "call.hangup",
        "call.invite",
        "call.reject",
        "contact.accept",
        "contact.add",
        "contact.card.import",
        "contact.request",
        "contact.request.accept",
        "contact.safety_number",
        "contact.verify",
        "device.activate",
        "device.authorize",
        "device.migrate",
        "device.pair.approve",
        "device.pair.begin",
        "device.pair.join",
        "device.push_route.set",
        "device.refresh",
        "device.revoke",
        "device.sync.export",
        "device.sync.import",
        "group.create",
        "group.invite.accept",
        "group.invite.create",
        "group.member.add",
        "group.member.ban",
        "group.member.kick",
        "group.member.remove",
        "group.message.delete",
        "group.name.set",
        "group.owner.transfer",
        "group.read",
        "group.receive",
        "group.role.set",
        "group.send",
        "message.ack",
        "message.receive",
        "message.submit",
        "conversation.send",
        "object.fetch",
        "object.import",
        "object.share",
        "object.transfer.resume",
        "surface.action",
        "surface.request_resync",
        "surface.resync",
        "surface.send",
        "task.accept",
        "task.cancel",
        "task.decline",
        "task.propose",
        "task.resolve",
        "task.start",
        "task.update",
    ];
    NeedsNetwork(Always) => Supervisor: [
        "account.create",
        "account.itest_legacy.create",
        "node.add",
        "node.probe",
    ];
}

#[cfg(test)]
mod tests;

/// Evaluates only request parameters and saved account/spool configuration, never connectivity.
pub(super) fn requires_network(
    method: &str,
    params: &serde_json::Value,
    account_has_relay: bool,
    spool_has_relay: Option<bool>,
) -> bool {
    if super::generated_typing::is_request(method, params) {
        return false;
    }
    let Some(entry) = classify(method) else {
        return false;
    };
    if entry.class != MethodClass::NeedsNetwork {
        return false;
    }
    match entry.network {
        NetworkCondition::Always => true,
        NetworkCondition::RelaySelected if method == "object.put.finish" => {
            spool_has_relay.unwrap_or(false) || account_has_relay
        }
        NetworkCondition::RelaySelected => {
            params.get("relay_endpoint").is_some_and(serde_json::Value::is_string)
                || account_has_relay
        }
    }
}

pub(super) fn account_requires_network(
    request: &crate::LocalBusFrame,
    account: &super::state::LocalBusAccountState,
) -> bool {
    let spool = request
        .body
        .get("operation_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|id| account.object_put_spools.get(id))
        .map(|spool| spool.relay_endpoint.is_some());
    requires_network(
        &request.method,
        &request.body,
        account.client.node_relay_options.is_some(),
        spool,
    )
}

/// Local lookup and erasure checks precede this shared relay boundary for `LocalFirst` methods.
pub(super) fn require_local_first_relay(
    method: &str,
    account: &super::state::LocalBusAccountState,
) -> Result<(), crate::SdkError> {
    if classify(method).is_none_or(|entry| entry.class != MethodClass::LocalFirst) {
        return Err(crate::SdkError::LocalBus(
            "relay boundary requires a LocalFirst method".into(),
        ));
    }
    let connection = account.connection.as_ref().ok_or(crate::SdkError::NetworkingPending)?;
    if connection.snapshot().state != super::connection_manager::NetworkingState::Live
        || connection.retirement_requested()
    {
        return Err(connection.pending());
    }
    Ok(())
}

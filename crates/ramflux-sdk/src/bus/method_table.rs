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
    AuthorityFromNode,
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
    LocalRead(Always) => Reader: ["search.query", "search.index.status"];
    LocalRead(Always) => Supervisor: ["search.cancel", "search.cursor.close", "search.index.rebuild.cancel"];
    LocalRead(Always) => Reader: ["attachment.transfer.list"];
    LocalMutation(Always) => Supervisor: ["attachment.transfer.pause", "attachment.transfer.resume"];
    LocalMutation(Always) => Actor: ["search.index.rebuild"];
    LocalRead(Always) => Actor: ["account.config.get", "diag.residue"];
    NeedsNetwork(RelaySelected) => Actor: ["object.put", "object.put.finish", "object.delete"];
    NeedsNetwork(AuthorityFromNode) => Actor: ["attachment.enable"];
    LocalFirst(Always) => Actor: ["object.get", "object.get.begin", "username.mutate", "profile.update", "account.reach.set"];
    LocalRead(Always) => Actor: ["a2i.list_pending", "agent.approval.list", "agent.job.list", "agent.job.sessions", "device.pair.status", "device.transfer.status"];
    LocalMutation(Always) => Actor: [
        "account.config.set",
        "a2i.acknowledge",
        "agent.approval.decide",
        "agent.approval.publish",
        "agent.job.pause",
        "agent.job.remove",
        "agent.job.resume",
        "agent.job.session",
        "agent.progress",
        "attachment.import.begin",
        "attachment.import.cancel",
        "attachment.import.finish",
        "attachment.import.read",
        "attachment.import.status",
        "attachment.prepare.begin",
        "attachment.prepare.cancel",
        "attachment.prepare.chunk",
        "attachment.prepare.finish",
        "attachment.prepare.renew",
        "attachment.prepare.status",
        "attachment.revoke",
        "bot.install",
        "bot.revoke",
        "bot.trust.add",
        "call.media.session",
        "card.session.dispose",
        "card.session.event",
        "card.session.open",
        "card.session.present",
        "card.session.resume",
        "card.session.slot",
        "card.session.suspend",
        "card.session.update",
        "contact.block",
        "contact.card.export",
        "contact.decline",
        "contact.requests.decline",
        "contact.reject",
        "contact.remove",
        "contact.requests.policy.set",
        "contact.unblock",
        "contact.verify",
        "conversation.disappearing.expire",
        "conversation.disappearing.set",
        "conversation.mute",
        "device.pair.begin",
        "device.pair.join",
        "device.pair.approve",
        "device.pair.cancel",
        "device.transfer.begin",
        "device.transfer.join",
        "device.transfer.confirm",
        "device.transfer.cancel",
        "device.transfer.tail_abandon",
        "device.transfer.prepare",
        "device.pair.confirm",
        "device.transfer.affirm",
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
        "itest.agent.approve_once",
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
        "account.sign_out",
        "account.unlock",
    ];
    LocalMutation(Always) => Supervisor: [
        "account.app_lock.configure",
        "account.app_lock.lifecycle",
        "account.app_lock.lock",
        "account.backup.export",
        "account.backup.import",
        "account.export_agent_credentials",
        "account.remove_local",
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
        "account.app_lock.state",
        "account.list",
        "daemon.status",
        "node.list",
    ];
    NeedsNetwork(Always) => Actor: [
        "conversation.start", "contact.requests.reply", "account.reach.get", "username.status", "username.resolve", "username.contact.add",
        "a2i.append",
        "call.answer",
        "call.hangup",
        "call.invite",
        "call.reject",
        "contact.accept",
        "contact.add",
        "contact.card.import",
        "contact.request",
        "contact.safety_number",
        "device.activity.report",
        "device.notifications.cleared",
        "device.push_policy.set",
        "device.push_route.set",
        "device.refresh",
        "device.revoke",
        "device.sync.export",
        "group.create",
        "group.member.add",
        "group.member.kick",
        "group.leave",
        "group.member.remove",
        "group.name.set",
        "group.owner.transfer",
        "group.read",
        "group.role.set",
        "group.send",
        "message.ack",
        "message.receive",
        "message.submit",
        "conversation.send",
        "conversation.edit",
        "conversation.react",
        "conversation.reply",
        "conversation.delete",
        "object.fetch",
        "object.import",
        "object.revoke",
        "object.share",
        "object.transfer.resume",
        "card.session.submit",
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
        NetworkCondition::AuthorityFromNode => {
            params.get("from_node").and_then(serde_json::Value::as_bool).unwrap_or(false)
        }
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
    if request.method == "attachment.enable" && account.client.attachment_plane.is_some() {
        return false;
    }
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

#[cfg(test)]
mod pairing_tests {
    use super::*;
    #[test]
    fn pairing_status_uses_coordinator_without_ordinary_network() -> Result<(), &'static str> {
        for name in ["device.pair.status", "device.transfer.status"] {
            let method = classify(name).ok_or("missing pairing status route")?;
            assert_eq!(
                method.route,
                MethodRoute::Actor,
                "test: pairing status bypassed its coordinator actor"
            );
            assert_eq!(
                method.class,
                MethodClass::LocalRead,
                "test: status was classified as a mutation"
            );
            assert!(
                !requires_network(name, &serde_json::json!({}), true, None),
                "test: pairing status opened an ordinary gateway session"
            );
        }
        for name in [
            "device.pair.begin",
            "device.pair.join",
            "device.pair.approve",
            "device.pair.confirm",
            "device.pair.cancel",
            "device.transfer.begin",
            "device.transfer.join",
            "device.transfer.confirm",
            "device.transfer.prepare",
            "device.transfer.affirm",
            "device.transfer.cancel",
            "device.transfer.tail_abandon",
        ] {
            let method = classify(name).ok_or("test: missing attended pairing action")?;
            assert_eq!(
                method.route,
                MethodRoute::Actor,
                "test: attended pairing bypassed its account actor"
            );
            assert_eq!(
                method.class,
                MethodClass::LocalMutation,
                "test: pairing action required an ordinary session before its separate proof flow"
            );
            assert!(
                !requires_network(name, &serde_json::json!({}), true, None),
                "test: pairing used the ordinary gateway connection prerequisite"
            );
        }

        Ok(())
    }
}

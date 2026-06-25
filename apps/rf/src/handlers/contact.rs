// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_contact(
    socket: PathBuf,
    command: ContactCommand,
) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        ContactAction::Add(link) => {
            let account = link.account.clone();
            let request = LocalBusContactAddRequest {
                link_id: link.link,
                requester_id: link.requester,
                target_id: link.target,
            };
            print_json(&bus.request(Some(account), "contact", "contact.add", &request).await?)
        }
        ContactAction::Request(link) => {
            let account = link.link.account.clone();
            let request = rf_contact_federated_request(link.link, link.federated);
            print_json(&bus.request(Some(account), "contact", "contact.request", &request).await?)
        }
        ContactAction::Accept(accept) => {
            let account = accept.link.account.clone();
            if let Some(federated) = accept.federated {
                let request = rf_contact_federated_request(accept.link, federated);
                print_json(
                    &bus.request(Some(account), "contact", "contact.accept", &request).await?,
                )
            } else {
                let request = LocalBusContactAddRequest {
                    link_id: accept.link.link,
                    requester_id: accept.link.requester,
                    target_id: accept.link.target,
                };
                print_json(
                    &bus.request(Some(account), "contact", "contact.accept", &request).await?,
                )
            }
        }
        ContactAction::Remove(remove) => {
            let request =
                LocalBusContactRemoveRequest { link_id: remove.link, scope: remove.scope };
            print_json(
                &bus.request(Some(remove.account), "contact", "contact.remove", &request).await?,
            )
        }
        ContactAction::Block(block) => {
            let request = LocalBusContactLinkRequest { link_id: block.link };
            print_json(
                &bus.request(Some(block.account), "contact", "contact.block", &request).await?,
            )
        }
        ContactAction::Unblock(unblock) => {
            let request = LocalBusContactLinkRequest { link_id: unblock.link };
            print_json(
                &bus.request(Some(unblock.account), "contact", "contact.unblock", &request).await?,
            )
        }
        ContactAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "contact", "contact.list", &serde_json::json!({}))
                .await?,
        ),
        ContactAction::Verify(verify) => {
            let method =
                if verify.mark_verified { "contact.verify" } else { "contact.safety_number" };
            let request = LocalBusContactSafetyRequest {
                contact_identity_commitment: verify.selector.contact,
            };
            print_json(
                &bus.request(Some(verify.selector.account), "contact", method, &request).await?,
            )
        }
        ContactAction::SafetyNumber(selector) => {
            let request =
                LocalBusContactSafetyRequest { contact_identity_commitment: selector.contact };
            print_json(
                &bus.request(Some(selector.account), "contact", "contact.safety_number", &request)
                    .await?,
            )
        }
        ContactAction::Verification(command) => {
            handle_contact_verification(&mut bus, command).await
        }
    }
}

async fn handle_contact_verification(
    bus: &mut LocalBusClient,
    command: ContactVerificationCommand,
) -> Result<(), RfError> {
    match command.action {
        ContactVerificationAction::Status(selector) => {
            let request =
                LocalBusContactSafetyRequest { contact_identity_commitment: selector.contact };
            print_json(
                &bus.request(
                    Some(selector.account),
                    "contact",
                    "contact.verification.status",
                    &request,
                )
                .await?,
            )
        }
    }
}

pub(crate) fn rf_contact_federated_request(
    link: ContactLink,
    federated: ContactFederatedArgs,
) -> LocalBusContactFederatedRequest {
    LocalBusContactFederatedRequest {
        link_id: link.link,
        requester_id: link.requester,
        target_id: link.target,
        conversation_id: federated.conversation,
        message_id: federated.message,
        envelope_id: federated.envelope,
        source_principal_id: federated.source_principal,
        sender_id: federated.sender,
        recipient_device_id: federated.recipient_device,
        target_delivery_id: federated.target_delivery,
        federation: LocalBusFederationRoute {
            federation_url: federated.federation_url,
            source_node_id: federated.source_node,
            target_node_id: federated.target_node,
            required_capability: federated.federation_capability,
            admin_token: federated.federation_admin_token,
            recipient_prekey_url: federated.recipient_prekey_url,
        },
    }
}

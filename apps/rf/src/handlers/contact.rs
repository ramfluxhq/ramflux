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
        ContactAction::Add(add) => handle_contact_add(&mut bus, add).await,
        ContactAction::Card(selector) => print_json(
            &bus.request(
                Some(selector.account),
                "contact",
                "contact.card.export",
                serde_json::json!({}),
            )
            .await?,
        ),
        ContactAction::Request(link) => {
            let account = link.link.account.clone();
            let request = rf_contact_federated_request(link.link, link.federated);
            print_json(
                &request_body(&mut bus, Some(account), "contact", "contact.request", request)
                    .await?,
            )
        }
        ContactAction::Accept(accept) => handle_contact_accept(&mut bus, accept).await,
        ContactAction::Remove(remove) => {
            let request =
                LocalBusContactRemoveRequest { link_id: remove.link, scope: remove.scope };
            print_json(
                &request_body(&mut bus, Some(remove.account), "contact", "contact.remove", request)
                    .await?,
            )
        }
        ContactAction::Reject(reject) => {
            let request = LocalBusContactLinkRequest { link_id: reject.link };
            print_json(
                &request_body(&mut bus, Some(reject.account), "contact", "contact.reject", request)
                    .await?,
            )
        }
        ContactAction::Block(block) => {
            let request = LocalBusContactLinkRequest { link_id: block.link };
            print_json(
                &request_body(&mut bus, Some(block.account), "contact", "contact.block", request)
                    .await?,
            )
        }
        ContactAction::Unblock(unblock) => {
            let request = LocalBusContactLinkRequest { link_id: unblock.link };
            print_json(
                &request_body(
                    &mut bus,
                    Some(unblock.account),
                    "contact",
                    "contact.unblock",
                    request,
                )
                .await?,
            )
        }
        ContactAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "contact", "contact.list", serde_json::json!({}))
                .await?,
        ),
        ContactAction::Requests(selector) => print_json(
            &bus.request(
                Some(selector.account),
                "contact",
                "contact.requests.list",
                serde_json::json!({}),
            )
            .await?,
        ),
        ContactAction::Verify(verify) => handle_contact_verify(&mut bus, verify).await,
        ContactAction::SafetyNumber(selector) => {
            let request =
                LocalBusContactSafetyRequest { contact_identity_commitment: selector.contact };
            print_json(
                &request_body(
                    &mut bus,
                    Some(selector.account),
                    "contact",
                    "contact.safety_number",
                    request,
                )
                .await?,
            )
        }
        ContactAction::Verification(command) => {
            handle_contact_verification(&mut bus, command).await
        }
    }
}

async fn handle_contact_add(bus: &mut LocalBusClient, add: ContactAdd) -> Result<(), RfError> {
    if let Some(name) = &add.username {
        let name = ramflux_sdk::username_directory::normalize_name(name)?;
        return print_json(
            &bus.request(
                Some(add.account),
                "username",
                "username.contact.add",
                serde_json::json!({"name":name}),
            )
            .await?,
        );
    }
    let body = contact_add_body(&add);
    contact_add_response(bus, add.account, body).await
}

async fn handle_contact_verify(
    bus: &mut LocalBusClient,
    verify: ContactVerify,
) -> Result<(), RfError> {
    let (method, body) = match verify.expected_safety {
        Some(expected) if verify.mark_verified => {
            // The SDK takes its target from the stamp; the selected contact must be it
            // (or the provisional root the stamp explicitly replaces).
            let selected = verify.selector.contact.as_str();
            if expected.contact_identity_commitment != selected
                && expected.replace_provisional_root.as_deref() != Some(selected)
            {
                return Err(ramflux_sdk::SdkError::from(
                    ramflux_sdk::ContactReason::SafetyMaterialMismatch,
                )
                .into());
            }
            (
                "contact.verify",
                serde_json::to_value(ramflux_protocol::message::ContactSafetyVerifyRequest {
                    expected: Some(expected),
                })?,
            )
        }
        _ => (
            "contact.safety_number",
            serde_json::to_value(LocalBusContactSafetyRequest {
                contact_identity_commitment: verify.selector.contact,
            })?,
        ),
    };
    print_json(&bus.request(Some(verify.selector.account), "contact", method, body).await?)
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
                &request_body(
                    bus,
                    Some(selector.account),
                    "contact",
                    "contact.verification.status",
                    request,
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
            source_node_id: String::new(),
            target_node_id: String::new(),
            required_capability: String::new(),
        },
    }
}

async fn handle_contact_accept(
    bus: &mut LocalBusClient,
    accept: ContactAccept,
) -> Result<(), RfError> {
    let account = accept.account.clone();
    let body = contact_accept_body(&accept)?;
    let frame = ramflux_sdk::LocalBusFrame::request(
        "rf-contact-accept",
        Some(account),
        "contact",
        "contact.accept",
        body,
    );
    print_json(&bus.request_frame_structured(frame).await?)
}

pub(crate) fn contact_accept_body(accept: &ContactAccept) -> Result<serde_json::Value, RfError> {
    let (key, value) = match (
        accept.principal.as_deref(),
        accept.request.as_deref(),
        accept.link.as_deref(),
        accept.root.as_deref(),
    ) {
        (Some(value), None, None, None) => ("principal_id", value),
        (None, Some(value), None, None) => ("request_id", value),
        (None, None, Some(value), None) => ("link_id", value),
        (None, None, None, Some(value)) => ("root_commitment", value),
        _ => return Err(RfError::Message("contact accept requires one selector".into())),
    };
    if value.is_empty() || value.len() > 4096 {
        return Err(RfError::Message(
            "contact accept selector is empty or longer than 4096 bytes".into(),
        ));
    }
    let mut body = serde_json::Map::new();
    body.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
    Ok(serde_json::Value::Object(body))
}

fn contact_add_body(add: &ContactAdd) -> serde_json::Value {
    if let Some(principal) = &add.principal {
        serde_json::json!({"principal_id":principal})
    } else if let Some(card) = &add.card {
        let mut body = serde_json::json!({"card":card});
        if let Some(root) = &add.replace_provisional_root {
            body["replace_provisional_root"] = serde_json::json!(root);
        }
        body
    } else {
        serde_json::json!({"link_id":add.link,"requester_id":add.requester,"target_id":add.target})
    }
}

async fn contact_add_response(
    bus: &LocalBusClient,
    account: String,
    body: serde_json::Value,
) -> Result<(), RfError> {
    let frame = ramflux_sdk::LocalBusFrame::request(
        "rf-contact-add",
        Some(account),
        "contact",
        "contact.add",
        body,
    );
    let response = bus.request_frame_response(frame).await?;
    if response.kind == ramflux_sdk::LocalBusFrameKind::Error {
        let error = response
            .error
            .ok_or_else(|| ramflux_sdk::SdkError::LocalBus("contact error body missing".into()))?;
        return Err(ramflux_sdk::SdkError::LocalBus(serde_json::to_string(&error)?).into());
    }
    print_json(&response.body)
}

#[cfg(test)]
mod tests {
    use super::contact_accept_body;
    use crate::cli::{Cli, Command, ContactAction};
    use clap::Parser;

    fn accept(args: &[&str]) -> ContactAction {
        let cli = Cli::try_parse_from(args).expect("contact accept parses");
        let Command::Contact(command) = cli.command else {
            panic!("expected contact command");
        };
        command.action
    }

    #[test]
    fn contact_accept_principal_sends_the_selector_without_a_federation_envelope() {
        let ContactAction::Accept(parsed) =
            accept(&["rf", "contact", "accept", "--account", "acct", "--principal", "peer"])
        else {
            panic!("expected accept");
        };
        let body = contact_accept_body(&parsed).expect("body");
        assert_eq!(body["principal_id"], "peer");
        assert!(body.get("requester_id").is_none());
        assert!(
            Cli::try_parse_from([
                "rf",
                "contact",
                "accept",
                "--account",
                "acct",
                "--principal",
                "peer",
                "--envelope",
                "env",
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["rf", "contact", "accept", "--account", "acct"]).is_err());
        assert!(
            Cli::try_parse_from([
                "rf",
                "contact",
                "accept",
                "--account",
                "acct",
                "--principal",
                "peer",
                "--request",
                "request",
            ])
            .is_err()
        );
    }

    #[test]
    fn contact_accept_rejects_an_empty_or_oversized_selector() {
        let ContactAction::Accept(mut parsed) =
            accept(&["rf", "contact", "accept", "--account", "acct", "--request", "request"])
        else {
            panic!("expected accept");
        };
        assert_eq!(contact_accept_body(&parsed).expect("request")["request_id"], "request");
        parsed.request = Some(String::new());
        assert!(contact_accept_body(&parsed).is_err());
        parsed.request = None;
        parsed.link = Some("link".to_owned());
        assert_eq!(contact_accept_body(&parsed).expect("link")["link_id"], "link");
        parsed.link = None;
        parsed.root = Some("r".repeat(4097));
        assert!(contact_accept_body(&parsed).is_err());
        parsed.root = Some("root".to_owned());
        assert_eq!(contact_accept_body(&parsed).expect("root")["root_commitment"], "root");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn contact_accept_keeps_a_daemon_refusal_code_and_body() {
        // The canonical macOS temp path exceeds SUN_LEN, so the socket lives in a unique directory under /tmp.
        let root = tempfile::TempDir::new_in("/tmp").expect("test: fixture directory");
        let socket = root.path().join("bus.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("test: bus socket");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let len = tokio::io::AsyncReadExt::read_u32(&mut stream).await?;
            let mut bytes = vec![0; usize::try_from(len)?];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut bytes).await?;
            let mut request: ramflux_sdk::LocalBusFrame = serde_json::from_slice(&bytes)?;
            assert_eq!(request.method, "contact.accept");
            assert_eq!(request.body["principal_id"], "peer");
            request.kind = ramflux_sdk::LocalBusFrameKind::Error;
            request.ok = Some(false);
            request.error = Some(ramflux_sdk::LocalBusErrorBody {
                details: None,
                reason_code: Some("not_linked".to_owned()),
                code: "NotAContact".to_owned(),
                message: "no inbound request matches that principal".to_owned(),
                retry_after_ms: None,
                cause: None,
            });
            request.body = serde_json::json!({"kept": true});
            let encoded = serde_json::to_vec(&request)?;
            tokio::io::AsyncWriteExt::write_u32(&mut stream, u32::try_from(encoded.len())?).await?;
            tokio::io::AsyncWriteExt::write_all(&mut stream, &encoded).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let mut bus = ramflux_sdk::LocalBusClient::connect(&socket).await.expect("test: connect");
        let error = super::handle_contact_accept(
            &mut bus,
            crate::cli::ContactAccept {
                account: "acct".to_owned(),
                principal: Some("peer".to_owned()),
                request: None,
                link: None,
                root: None,
            },
        )
        .await
        .expect_err("test: daemon refusal");
        let shown = error.to_string();
        match error {
            crate::RfError::Sdk(ramflux_sdk::SdkError::LocalBusRefused { code, message, body }) => {
                assert_eq!(code, "NotAContact");
                assert!(message.contains("no inbound request"));
                assert_eq!(body["kept"], true);
            }
            other => panic!("test: refusal lost its type: {other}"),
        }
        assert!(shown.contains("NotAContact"), "test: process text keeps the typed code");
        drop(bus);
        server.await.expect("test: server").expect("test: refusal frame");
        drop(root);
    }
}

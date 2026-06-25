// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_bot(socket: PathBuf, command: BotCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        BotAction::Trust(trust) => match trust.action {
            BotTrustAction::Add(add) => {
                let request = LocalBusBotTrustAddRequest {
                    bot_identity_commitment: add.bot,
                    bot_public_key: add.public_key,
                    signing_key_id: add.signing_key_id,
                    trust_source: add.trust_source,
                };
                print_json(&bus.request(Some(add.account), "bot", "bot.trust.add", &request).await?)
            }
        },
        BotAction::Install(install) => {
            let manifest: ramflux_protocol::BotManifest =
                serde_json::from_slice(&std::fs::read(&install.manifest)?)?;
            let install_grant: ramflux_protocol::BotInstallGrant =
                serde_json::from_slice(&std::fs::read(&install.grant)?)?;
            let request = LocalBusBotInstallRequest {
                manifest,
                install_grant,
                consent_member_ids: install.consent,
            };
            print_json(&bus.request(Some(install.account), "bot", "bot.install", &request).await?)
        }
        BotAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "bot", "bot.list", &serde_json::json!({})).await?,
        ),
        BotAction::Revoke(revoke) => {
            let request = LocalBusBotRevokeRequest { bot_id: revoke.bot };
            print_json(&bus.request(Some(revoke.account), "bot", "bot.revoke", &request).await?)
        }
    }
}

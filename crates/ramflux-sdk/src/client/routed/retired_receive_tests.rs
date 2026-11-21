// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A caller's prior history or thread hint cannot restore the removed application codec.
use super::*;
use crate::client::native_test_support::{TestResult, watchdog};

#[tokio::test(flavor = "current_thread")]
async fn prior_native_pair_and_thread_hints_cannot_enable_retired_receive() -> TestResult {
    watchdog::within(async {
        let source = Fixture::native_named("alice", 21).await?;
        let mut target = Fixture::native_named("bob", 31).await?;
        review::trust(&target, &source)?;
        target.client.establish_friend_link(
            "native-consent",
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?;
        let sent = generated_delivery(&source, &target, "current-profile", "current Message")?;
        receive_generated(&mut target, &sent.entry).await?;
        let before = target.client.generated_message_detail(&sent.conversation, &sent.message)?;
        for hint in [&sent.conversation, "caller-selected-thread"] {
            let result = target
                .client
                .receive_legacy_entry(
                    &mut GatewaySessionEngine::with_test_transport(
                        target.config()?,
                        Box::new(NoNetwork),
                    ),
                    &review::pool()?,
                    sent.entry.clone(),
                    crate::client::dm::LegacyReceive {
                        conversation_id: hint,
                        auto_fetch_attachments: true,
                        relay_service_key_base64: None,
                    },
                )
                .await;
            assert!(
                matches!(
                    result,
                    Err(SdkError::GeneratedRefused {
                        code: crate::GeneratedRefusalCode::Content,
                        ..
                    })
                ),
                "prior native state enabled the retired codec: {result:?}"
            );
        }
        assert_eq!(
            serde_json::to_value(
                target.client.generated_message_detail(&sent.conversation, &sent.message)?.message
            )?,
            serde_json::to_value(before.message)?
        );
        assert_eq!(target.client.direct_messages(&sent.conversation)?.len(), 1);
        assert_eq!(target.client.direct_messages("caller-selected-thread")?.len(), 0);
        Ok(())
    })
    .await?
}

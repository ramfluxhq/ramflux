// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared-group ciphertext authenticates the content head even when a sender reuses a seed.
use super::*;
#[tokio::test(flavor = "current_thread")]
async fn shared_group_same_epoch_forks_cannot_exchange_ciphertext_under_a_retagged_head()
-> crate::client::native_test_support::TestResult {
    crate::client::native_test_support::watchdog::within(native_activation::fork_ciphertext())
        .await?
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

/**
 * Home of the Android Keystore helper {@code KeystoreBridge}.
 *
 * <p>The helper is written and owned by the Android core module together with its Rust
 * counterpart ({@code crates/ramflux-sdk/src/custody/vault/android/jni_bridge.rs}), which
 * resolves it by this exact name: {@code org.ramflux.sdk.vault.KeystoreBridge}. It is
 * compiled into this library from this directory and kept by {@code consumer-rules.pro}.
 * Nothing in this package is duplicated elsewhere in the Gradle project.
 */
package org.ramflux.sdk.vault;

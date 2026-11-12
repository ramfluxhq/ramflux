// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Rules of the browser package that are properties of its source text. They hold for every
//! build because they are checked on the files that are shipped.

const SERVICE_WORKER: &str = include_str!("../js/service-worker.ts");
const WORKER: &str = include_str!("../js/worker.ts");
const CLIENT: &str = include_str!("../js/client.ts");
const RUST_SOURCES: &[&str] = &[
    include_str!("../src/browser/api.rs"),
    include_str!("../src/browser/driver.rs"),
    include_str!("../src/browser/js.rs"),
    include_str!("../src/browser/locks.rs"),
    include_str!("../src/browser/ports.rs"),
    include_str!("../src/browser/socket.rs"),
    include_str!("../src/browser/storage.rs"),
    include_str!("../src/browser/vault.rs"),
];

fn code_lines(source: &str) -> impl Iterator<Item = &str> {
    source.lines().map(str::trim).filter(|line| !line.starts_with("//") && !line.starts_with("///"))
}

fn code_contains(source: &str, needle: &str) -> bool {
    code_lines(source).any(|line| line.contains(needle))
}

#[test]
fn service_worker_has_no_fetch_handler_and_no_cache_storage() {
    assert!(!code_contains(SERVICE_WORKER, "\"fetch\""));
    assert!(!code_contains(SERVICE_WORKER, "caches."));
    assert!(!code_contains(SERVICE_WORKER, "importScripts"));
    assert!(!code_contains(SERVICE_WORKER, "fetch("));
}

#[test]
fn service_worker_never_loads_the_core_or_opens_storage() {
    for needle in ["ramflux_web", "indexedDB", "getDirectory", "WebSocket", "crypto.subtle"] {
        assert!(!code_contains(SERVICE_WORKER, needle), "{needle}");
    }
}

#[test]
fn push_handler_shows_only_the_generic_sentence() {
    assert!(code_contains(SERVICE_WORKER, "showNotification(NOTIFICATION_TEXT, { tag: NOTIFICATION_TAG })"));
    assert_eq!(code_lines(SERVICE_WORKER).filter(|line| line.contains("showNotification(")).count(), 1);
}

#[test]
fn nothing_is_written_to_local_storage_session_storage_or_cookies() {
    let all = [SERVICE_WORKER, WORKER, CLIENT].into_iter().chain(RUST_SOURCES.iter().copied());
    for source in all {
        for needle in ["localStorage", "sessionStorage", "document.cookie", "cookieStore", "withCredentials"] {
            assert!(!code_contains(source, needle), "{needle}");
        }
    }
}

#[test]
fn the_page_never_loads_the_core_and_never_opens_a_socket() {
    for needle in ["ramflux_web", "new WebSocket", "indexedDB", "getDirectory"] {
        assert!(!code_contains(CLIENT, needle), "{needle}");
    }
}

#[test]
fn no_context_ever_steals_the_writer_lock() {
    let all = [SERVICE_WORKER, WORKER, CLIENT].into_iter().chain(RUST_SOURCES.iter().copied());
    for source in all {
        assert!(!code_contains(source, "steal: true"));
        assert!(!code_contains(source, "\"steal\""));
    }
}

#[test]
fn every_outbound_host_is_the_node_gateway_or_relay() {
    // The only network constructor in the package is the gateway socket, dialed at the pinned
    // listener URL. No source names a literal host.
    let all = [SERVICE_WORKER, WORKER, CLIENT].into_iter().chain(RUST_SOURCES.iter().copied());
    for source in all {
        for needle in ["https://", "http://", "wss://", "ws://", "XMLHttpRequest", "sendBeacon", "EventSource"] {
            assert!(!code_contains(source, needle), "{needle}");
        }
    }
    let sockets = RUST_SOURCES.iter().filter(|source| code_contains(source, "construct(\"WebSocket\"")).count();
    assert_eq!(sockets, 1);
}

#[test]
fn the_exported_surface_has_no_account_creation_or_recovery_entry_point() {
    let api = RUST_SOURCES[0];
    for needle in ["account_create", "create_account", "recover", "mnemonic", "primary_seed", "recovery_secret", "migrate", "approve"] {
        assert!(!code_contains(api, needle), "{needle}");
    }
}

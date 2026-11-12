// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bind family, mobile host rule and the staggered connect.

use std::cell::RefCell;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn v4(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], 443))
}

fn v6(last: u16) -> SocketAddr {
    SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, last], 443))
}

fn refused(what: &str) -> SdkError {
    SdkError::LocalBus(what.to_owned())
}

#[test]
fn bind_address_follows_the_destination_family() {
    assert_eq!(bind_addr_for(v4(1)), SocketAddr::from(([0, 0, 0, 0], 0)));
    let bound = bind_addr_for(v6(1));
    assert!(bound.is_ipv6());
    assert!(bound.ip().is_unspecified());
    assert_eq!(bound.port(), 0);
}

#[test]
fn session_bind_changes_only_a_wildcard_of_the_wrong_family() {
    let v4_wildcard = SocketAddr::from(([0, 0, 0, 0], 0));
    let pinned = SocketAddr::from(([127, 0, 0, 1], 4000));
    assert_eq!(effective_bind_addr(v4_wildcard, v4(1)), v4_wildcard);
    assert_eq!(effective_bind_addr(v4_wildcard, v6(1)), bind_addr_for(v6(1)));
    assert_eq!(effective_bind_addr(bind_addr_for(v6(1)), v4(1)), v4_wildcard);
    assert_eq!(effective_bind_addr(pinned, v6(1)), pinned);
    assert_eq!(effective_bind_addr(pinned, v4(1)), pinned);
}

#[test]
fn mobile_profile_refuses_an_ipv4_literal_and_accepts_names_and_ipv6() -> TestResult {
    assert!(GatewayHost::for_mobile("192.0.2.7", 443).is_err());
    assert!(GatewayHost::for_mobile("", 443).is_err());
    assert!(GatewayHost::for_mobile("gateway.example", 0).is_err());
    let named = GatewayHost::for_mobile("gateway.example", 443)?;
    assert_eq!((named.host(), named.port()), ("gateway.example", 443));
    let literal = GatewayHost::for_mobile("[2001:db8::1]", 443)?;
    assert_eq!(literal.host(), "2001:db8::1");
    Ok(())
}

#[tokio::test]
async fn ipv6_literal_resolves_to_an_ipv6_socket_address() -> TestResult {
    let resolved = GatewayHost::for_mobile("2001:db8::1", 443)?.resolve().await?;
    assert_eq!(resolved, vec![v6(1)]);
    assert!(bind_addr_for(resolved[0]).is_ipv6());
    Ok(())
}

#[test]
fn resolved_addresses_keep_resolver_order_without_duplicates() {
    let found = vec![v6(1), v4(1), v6(1), v4(2), v4(3)];
    assert_eq!(dedup_in_order(found.into_iter(), 3), vec![v6(1), v4(1), v4(2)]);
}

#[tokio::test(start_paused = true)]
async fn second_address_starts_after_the_stagger_and_can_win() -> TestResult {
    let started = RefCell::new(Vec::new());
    let begin = tokio::time::Instant::now();
    let (value, address) = connect_staggered(&[v6(1), v4(1)], ADDRESS_STAGGER, |address| {
        started.borrow_mut().push((address, begin.elapsed()));
        async move {
            if address.is_ipv6() {
                // A black-holed path: never answers.
                std::future::pending::<()>().await;
            }
            Ok::<_, SdkError>("connected")
        }
    })
    .await?;
    assert_eq!((value, address), ("connected", v4(1)));
    assert_eq!(*started.borrow(), vec![(v6(1), Duration::ZERO), (v4(1), ADDRESS_STAGGER)]);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn failed_attempt_starts_the_next_address_without_waiting() -> TestResult {
    let begin = tokio::time::Instant::now();
    let (_, address) = connect_staggered(&[v6(1), v6(2)], ADDRESS_STAGGER, |address| async move {
        if address == v6(1) { Err(refused("unreachable")) } else { Ok(()) }
    })
    .await?;
    assert_eq!(address, v6(2));
    assert_eq!(begin.elapsed(), Duration::ZERO);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn all_addresses_failing_returns_the_last_error() {
    let result: Result<((), SocketAddr), SdkError> =
        connect_staggered(&[v6(1), v4(1)], ADDRESS_STAGGER, |address| async move {
            Err(refused(if address.is_ipv6() { "first" } else { "last" }))
        })
        .await;
    assert!(matches!(result, Err(SdkError::LocalBus(message)) if message == "last"));
    let empty: Result<((), SocketAddr), SdkError> =
        connect_staggered(&[], ADDRESS_STAGGER, |_| async { Ok(()) }).await;
    assert!(empty.is_err());
}

#[tokio::test]
async fn session_endpoints_pair_each_address_with_a_bind_of_its_family() -> TestResult {
    let endpoints = GatewayHost::for_mobile("2001:db8::1", 443)?.session_endpoints().await?;
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].gateway_addr, v6(1));
    assert!(endpoints[0].bind_addr.is_ipv6());
    assert_eq!(SessionEndpoint::for_remote(v4(1)).bind_addr, SocketAddr::from(([0, 0, 0, 0], 0)));
    Ok(())
}

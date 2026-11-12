// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{Duration, Indicator, RamfluxClient, TypingUpdate, g};

#[tokio::test(start_paused = true)]
async fn transient_deadlines_promote_and_expire_without_more_frames() {
    let client = RamfluxClient::new();
    let now = tokio::time::Instant::now().into_std();
    client.typing_receiver.borrow_mut().indicators.insert(
        ("root".into(), "device".into(), "conversation".into()),
        Indicator {
            update: TypingUpdate {
                identity: g::EventIdentity::default(),
                typing: g::Typing { active: true, expires_at: 105 },
                expires_at_ms: 105_000,
            },
            starts_at_ms: 102_000,
            hold_until: now + Duration::from_secs(30),
            expires: now + Duration::from_secs(5),
            visible: false,
            bytes: 100,
        },
    );
    assert_eq!(client.next_transient_deadline(100_000, now), Some(now + Duration::from_secs(2)));
    tokio::time::advance(Duration::from_secs(2)).await;
    let promoted = tokio::time::Instant::now().into_std();
    client.typing_receiver.borrow_mut().poll(102_000, promoted);
    let updates = client.typing_receiver.borrow_mut().drain_updates();
    assert_eq!(updates.len(), 1);
    assert!(updates[0].typing.active);
    assert_eq!(
        client.next_transient_deadline(102_000, promoted),
        Some(now + Duration::from_secs(5))
    );
    tokio::time::advance(Duration::from_secs(3)).await;
    client.typing_receiver.borrow_mut().poll(105_000, tokio::time::Instant::now().into_std());
    let updates = client.typing_receiver.borrow_mut().drain_updates();
    assert_eq!(updates.len(), 1);
    assert!(!updates[0].typing.active);
    assert!(
        client.next_transient_deadline(105_000, tokio::time::Instant::now().into_std()).is_none()
    );
}

#[test]
fn source_end_clears_visible_indicators_then_forgets_the_generation() {
    let client = RamfluxClient::new();
    let now = std::time::Instant::now();
    client.typing_receiver.borrow_mut().indicators.insert(
        ("root".into(), "device".into(), "conversation".into()),
        Indicator {
            update: TypingUpdate {
                identity: g::EventIdentity::default(),
                typing: g::Typing { active: true, expires_at: 105 },
                expires_at_ms: 105_000,
            },
            starts_at_ms: 100_000,
            hold_until: now,
            expires: now + Duration::from_secs(5),
            visible: true,
            bytes: 100,
        },
    );
    client.clear_transient_indicators();
    let updates = client.typing_receiver.borrow_mut().drain_updates();
    assert_eq!(updates.len(), 1);
    assert!(!updates[0].typing.active);
    client.reset_transient_content();
    assert!(client.typing_receiver.borrow_mut().drain_updates().is_empty());
    assert!(client.next_transient_deadline(100_000, now).is_none());
}

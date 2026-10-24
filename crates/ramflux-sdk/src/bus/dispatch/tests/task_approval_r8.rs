// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Repeated real row failures must not flood daemon logs or collapse different row identities.
use super::*;
use std::sync::atomic::AtomicUsize;
struct Warnings(Arc<AtomicUsize>);
impl tracing::Subscriber for Warnings {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.level() == &tracing::Level::WARN
            && (metadata.target().ends_with("::error_policy")
                || metadata.target().ends_with("::task_warnings"))
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
#[test]
fn r8_repeated_approval_scans_warn_once_for_each_corrupt_row() -> Case {
    let (root, mut agent, human) = pair("warning-throttle-r8")?;
    for task in ["r8-warning-one", "r8-warning-two"] {
        open_named(&human, &agent, task, "grant")?;
        let mut history = agent.client.task_history("thread", task)?;
        history.events.first_mut().ok_or("history")?.carrier.signature = "invalid".into();
        agent.client.account_db()?.persist_actor_state(
            &crate::client::task::scoped("history", "thread", task)?,
            &history,
        )?;
    }
    insert_pending(&mut agent, "approval", "grant")?;
    let count = Arc::new(AtomicUsize::new(0));
    tracing::subscriber::with_default(Warnings(Arc::clone(&count)), || {
        for _ in 0..5 {
            queue_requests(&mut agent)?;
        }
        Ok::<(), SdkError>(())
    })?;
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(agent.client.account_db()?.task_state_usage("task/approval_source/")?.0, 0);
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

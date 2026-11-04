// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A retained dependency failure emits a single structured operator-visible hold event.
use super::*;
use crate::bus::sync_driver;
use tracing::{Event, Level, Metadata, Subscriber, field::Visit, span};

#[derive(Clone)]
struct Lines(Arc<Mutex<Vec<(Level, String)>>>);
impl Subscriber for Lines {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target().starts_with("ramflux_sdk") && *metadata.level() <= Level::INFO
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        struct Fields(String);
        impl Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{}={value:?} ", field.name());
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        if let Ok(mut lines) = self.0.lock() {
            lines.push((*event.metadata().level(), fields.0));
        }
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

#[tokio::test]
async fn held_inbound_pending_logs_one_info_line_with_sequence_kind_and_reason() -> TestResult {
    let root = runtime_tests::root("inbox-hold-log");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    fixture::seed_pair(&a, &b)?;
    let mail: Shared = Arc::default();
    let mut source = a.account(None, mail.clone())?;
    let mut engine = source.session_client().await?;
    source
        .client
        .send_plaintext_direct_message_without_franking(
            &mut engine,
            a.message(&b, "held-message"),
            b"held body",
            crate::client::routed::Route::direct(),
        )
        .await?;
    source.install_test_session(engine);
    let mut entry =
        mail.lock().map_err(|_| "mail lock")?.messages.first().cloned().ok_or("entry")?;
    entry.inbox_seq = 42;
    let receiver = b.client(None)?;
    let key = receiver.inbox_admission_key(&entry)?;
    let lines = Lines(Arc::default());
    tracing::subscriber::with_default(lines.clone(), || {
        assert!(!sync_driver::quarantine_failure(
            &receiver,
            &b.device,
            &entry,
            &key,
            &SdkError::InboundPending("group root unavailable".into()),
            now_unix_timestamp(),
        )?);
        Ok::<_, SdkError>(())
    })?;
    assert!(receiver.account_db()?.has_inbox_retry(&key)?);
    let observed = lines.0.lock().map_err(|_| "lines lock")?;
    assert_eq!(observed.len(), 1, "hold must produce one operator-visible line: {observed:?}");
    assert_eq!(observed[0].0, Level::INFO);
    for expected in ["inbox_seq=42", "kind=", "InboundPending", "reason=", "group root unavailable"]
    {
        assert!(observed[0].1.contains(expected), "missing {expected}: {observed:?}");
    }
    drop(observed);
    lines.0.lock().map_err(|_| "lines lock")?.clear();
    tracing::subscriber::with_default(lines.clone(), || {
        assert!(sync_driver::quarantine_failure(
            &receiver,
            &b.device,
            &entry,
            &key,
            &SdkError::InboundRejected(
                "authenticated group conversation conflicts with local binding".into()
            ),
            now_unix_timestamp(),
        )?);
        Ok::<_, SdkError>(())
    })?;
    assert!(!receiver.account_db()?.has_inbox_retry(&key)?);
    let observed = lines.0.lock().map_err(|_| "lines lock")?;
    assert_eq!(observed.len(), 1, "{observed:?}");
    assert_eq!(observed[0].0, Level::WARN);
    for expected in [
        "gateway inbound entry dead-lettered",
        "inbox_seq=42",
        "InboundRejected",
        "authenticated group conversation conflicts with local binding",
        "outcome=",
        "envelope_id=",
        entry.envelope.envelope_id.as_str(),
        "source_device_id=",
        entry.envelope.source_device_id.as_str(),
        "target_delivery_id=",
        entry.target_delivery_id.as_str(),
    ] {
        assert!(observed[0].1.contains(expected), "missing {expected}: {observed:?}");
    }
    drop(observed);
    drop((source, receiver));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attachment diagnostics expose fixed check names and error categories, never access material.
use crate::SdkError;

pub(crate) fn failed(object_id: &str, check: &'static str, error: &SdkError) {
    tracing::warn!(
        object_id,
        check,
        error_code = crate::bus::io::local_bus_error_code(error),
        "attachment fetch check failed"
    );
}

pub(super) fn checked<T>(
    result: Result<T, SdkError>,
    object_id: &str,
    check: &'static str,
) -> Result<T, SdkError> {
    result.inspect_err(|error| failed(object_id, check, error))
}

pub(crate) fn context(object_id: &str, check: &'static str, error: &SdkError) {
    tracing::debug!(
        object_id,
        check,
        error_code = crate::bus::io::local_bus_error_code(error),
        "attachment fetch context"
    );
}

pub(super) fn checked_context<T>(
    result: Result<T, SdkError>,
    object_id: &str,
    check: &'static str,
) -> Result<T, SdkError> {
    result.inspect_err(|error| context(object_id, check, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::{Event, Metadata, Subscriber, field::Visit, span};
    struct Capture(Arc<Mutex<Vec<String>>>);
    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            struct Fields(String);
            impl Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write;
                    let _ = write!(self.0, "{}={value:?} ", field.name());
                }
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            if let Ok(mut lines) = self.0.lock() {
                lines.push(format!("{} {}", event.metadata().level(), fields.0));
            }
        }
    }
    #[test]
    fn attachment_warning_names_the_check_without_echoing_access_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let result = tracing::subscriber::with_default(Capture(lines.clone()), || {
            checked::<()>(
                Err(SdkError::CapabilityDenied("PRIVATE_GRANT_AND_KEY_MARKER".into())),
                "object-1",
                "relay_download",
            )
        });
        assert!(result.is_err());
        let lines = lines.lock().map_err(|_| "capture lock")?;
        assert_eq!(lines.len(), 1);
        for field in ["object-1", "relay_download", "error_code", "attachment fetch check failed"] {
            assert!(lines[0].contains(field), "missing {field}: {}", lines[0]);
        }
        assert!(!lines[0].contains("PRIVATE_GRANT_AND_KEY_MARKER"));
        Ok(())
    }

    #[test]
    fn attachment_failure_emits_one_warning_across_all_outer_contexts()
    -> Result<(), Box<dyn std::error::Error>> {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let result = tracing::subscriber::with_default(Capture(lines.clone()), || {
            let inner = checked::<()>(
                Err(SdkError::CapabilityDenied("PRIVATE_DIAGNOSTIC_MARKER".into())),
                "object-1",
                "manifest_hash",
            );
            let imported = checked_context(inner, "object-1", "verify_and_persist");
            let fetched = checked_context(imported, "object-1", "attachment_fetch");
            if let Err(error) = &fetched {
                context("object-1", "background_fetch", error);
            }
            fetched
        });
        assert!(
            matches!(result, Err(SdkError::CapabilityDenied(text)) if text == "PRIVATE_DIAGNOSTIC_MARKER")
        );
        let lines = lines.lock().map_err(|_| "capture lock")?;
        assert_eq!(lines.iter().filter(|line| line.starts_with("WARN ")).count(), 1);
        assert_eq!(lines.iter().filter(|line| line.starts_with("DEBUG ")).count(), 3);
        assert!(lines.iter().all(|line| !line.contains("PRIVATE_DIAGNOSTIC_MARKER")));
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host-side work and output limits, independent of the JavaScript interrupt budget.
use super::Reject;
use serde_json::Value;
use std::{
    cell::Cell,
    io::{self, Write},
};

const MAX_EXPRESSION_STEPS: usize = 4096;

pub(super) struct Steps(Cell<usize>);
impl Steps {
    pub(super) const fn new() -> Self {
        Self(Cell::new(MAX_EXPRESSION_STEPS))
    }
    pub(super) fn take(&self) -> Result<(), Reject> {
        self.0.set(self.0.get().checked_sub(1).ok_or(Reject::Limit)?);
        Ok(())
    }
}

pub(super) struct Bytes(usize);
impl Bytes {
    pub(super) const fn new(limit: usize) -> Self {
        Self(limit)
    }
    pub(super) fn take(&mut self, count: usize) -> Result<(), Reject> {
        self.0 = self.0.checked_sub(count).ok_or(Reject::Limit)?;
        Ok(())
    }
    // Count escaped JSON bytes without materializing a serialized buffer or cloning data.
    pub(super) fn key(&mut self, value: &str) -> Result<(), Reject> {
        serde_json::to_writer(self, value).map_err(|_| Reject::Limit)
    }
    pub(super) fn value(&mut self, value: &Value) -> Result<(), Reject> {
        match value {
            Value::Object(map) => {
                self.take(2 + map.len().saturating_sub(1))?;
                for (key, value) in map {
                    self.key(key)?;
                    self.take(1)?;
                    self.value(value)?;
                }
                Ok(())
            }
            Value::Array(array) => {
                self.take(2 + array.len().saturating_sub(1))?;
                for value in array {
                    self.value(value)?;
                }
                Ok(())
            }
            // Canonical numbers may differ in length from serde_json's notation.
            // Only a bounded scalar is serialized; containers never allocate a buffer.
            Value::Number(_) => self.take(super::wire::canonical(value)?.len()),
            _ => serde_json::to_writer(self, value).map_err(|_| Reject::Limit),
        }
    }
}
impl Write for Bytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.take(bytes.len()).map_err(|_| io::Error::other("expanded byte limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

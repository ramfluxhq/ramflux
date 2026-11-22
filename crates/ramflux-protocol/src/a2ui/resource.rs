// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host-side work and output limits, independent of the JavaScript interrupt budget.
use super::Reject;
use serde_json::Value;
use std::{
    cell::Cell,
    io::{self, Write},
};

const MAX_INDIRECT_STEPS: usize = 4096;
// Eight walks cover expansion, declarations, display, messages and action checks.
// A source byte can be revisited at each of 17 expression levels, and each of
// 17 enclosing formatString evaluations. Indirect programs have a separate cap.
const MAX_EXPRESSION_STEPS: usize = 8 * 17 * 17 * super::graph::MAX_EXPANDED_BYTES
    + super::graph::MAX_INSTANCES * MAX_INDIRECT_STEPS;

pub(super) struct Steps {
    remaining: Cell<usize>,
    indirect: [Cell<usize>; super::graph::MAX_INSTANCES],
    instance: Cell<usize>,
    program_depth: Cell<usize>,
}
impl Steps {
    pub(super) fn new() -> Self {
        Self {
            remaining: Cell::new(MAX_EXPRESSION_STEPS),
            indirect: std::array::from_fn(|_| Cell::new(MAX_INDIRECT_STEPS)),
            instance: Cell::new(0),
            program_depth: Cell::new(0),
        }
    }
    pub(super) fn instance(&self, index: usize) -> Result<(), Reject> {
        if index >= super::graph::MAX_INSTANCES || self.program_depth.get() != 0 {
            return Err(Reject::Limit);
        }
        self.instance.set(index);
        Ok(())
    }
    // Literal programs are bounded by signed/expanded source bytes. Programs
    // computed from model data may amplify those bytes, so all their recursive
    // work shares the instance's non-renewable allowance across every phase.
    pub(super) fn program<T>(
        &self,
        source: &Value,
        evaluate: impl FnOnce() -> Result<T, Reject>,
    ) -> Result<T, Reject> {
        let depth = self.program_depth.get();
        if !source.is_string() {
            self.program_depth.set(depth.checked_add(1).ok_or(Reject::Limit)?);
        }
        let result = evaluate();
        self.program_depth.set(depth);
        result
    }
    pub(super) fn take(&self) -> Result<(), Reject> {
        self.remaining.set(self.remaining.get().checked_sub(1).ok_or(Reject::Limit)?);
        if self.program_depth.get() != 0 {
            let remaining = self.indirect.get(self.instance.get()).ok_or(Reject::Limit)?;
            remaining.set(remaining.get().checked_sub(1).ok_or(Reject::Limit)?);
        }
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

// SPDX-License-Identifier: BSD-3-Clause
//! Shared engine compilation path for build bootstrap, release packer and tests.
use rquickjs::{
    Context, Module, Runtime,
    module::{WriteOptions, WriteOptionsEndianness},
};
use std::time::{Duration, Instant};

pub fn compile(source: &[u8], name: &str) -> rquickjs::Result<Vec<u8>> {
    let runtime = Runtime::new()?;
    runtime.set_memory_limit(32 * 1024 * 1024);
    runtime.set_max_stack_size(256 * 1024);
    let start = Instant::now();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        start.elapsed() >= Duration::from_millis(50)
    })));
    let context = Context::full(&runtime)?;
    context.with(|ctx| {
        Module::declare(ctx, name, source).and_then(|module| {
            module.write(WriteOptions {
                endianness: WriteOptionsEndianness::Little,
                ..WriteOptions::default()
            })
        })
    })
}

// SPDX-License-Identifier: BSD-3-Clause
//! Offline release tool. Never linked into an application or exposed to peers.
use ed25519_dalek::{Signer, SigningKey};
use ramflux_card::ENGINE_ID;
use rquickjs::{
    Context, Module, Runtime,
    module::{WriteOptions, WriteOptionsEndianness},
};
use std::{
    fs::File,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > max {
        return Err("input limit exceeded".into());
    }
    Ok(bytes)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).take(4).collect();
    let [source, seed, output] = args.as_slice() else {
        return Err(
            "usage: card-pack <linted-project-bundle.js> <32-byte-release-seed> <output-prefix>"
                .into(),
        );
    };
    let source = read_bounded(Path::new(source), 64 * 1024)?;
    let secret: [u8; 32] =
        read_bounded(Path::new(seed), 32)?.try_into().map_err(|_| "expected 32-byte seed")?;
    let key = SigningKey::from_bytes(&secret);
    let rt = Runtime::new()?;
    rt.set_memory_limit(32 * 1024 * 1024);
    rt.set_max_stack_size(256 * 1024);
    let start = Instant::now();
    rt.set_interrupt_handler(Some(Box::new(move || start.elapsed() > Duration::from_millis(50))));
    // Eval is present only in this offline compiler, never in CardRuntime.
    let ctx = Context::full(&rt)?;
    let bytecode = ctx.with(|ctx| {
        Module::declare(ctx, "rf-library", source).and_then(|m| {
            m.write(WriteOptions {
                endianness: WriteOptionsEndianness::Little,
                ..Default::default()
            })
        })
    })?;
    if bytecode.len() > 64 * 1024 {
        return Err("compiled package limit exceeded".into());
    }
    let mut message = b"ramflux-card-signed-bytecode-v1\0".to_vec();
    message.extend_from_slice(ENGINE_ID.as_bytes());
    message.push(0);
    message.extend_from_slice(&bytecode);
    let output = Path::new(output);
    std::fs::write(output.with_extension("qjb"), bytecode)?;
    std::fs::write(output.with_extension("sig"), key.sign(&message).to_bytes())?;
    std::fs::write(output.with_extension("pub"), key.verifying_key().to_bytes())?;
    println!("PACKAGE_OK {ENGINE_ID}");
    Ok(())
}

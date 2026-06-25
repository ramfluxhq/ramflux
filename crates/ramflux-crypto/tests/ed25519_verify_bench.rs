use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, verify_batch};
use std::error::Error;
use std::time::Instant;

const TOTAL_ENV: &str = "RAMFLUX_VERIFY_BENCH_TOTAL";
const BATCH_ENV: &str = "RAMFLUX_VERIFY_BENCH_BATCH";
const DEFAULT_TOTAL: usize = 200_000;
const DEFAULT_BATCH: usize = 64;

struct VerifyFixture {
    messages: Vec<Vec<u8>>,
    signatures: Vec<Signature>,
    verifying_keys: Vec<VerifyingKey>,
}

#[ignore = "microbenchmark; run explicitly with --ignored --nocapture"]
#[test]
fn verify_single_bench() -> Result<(), Box<dyn Error>> {
    let total = bench_usize_env(TOTAL_ENV, DEFAULT_TOTAL);
    let fixture = verify_fixture(total);
    let started = Instant::now();
    for ((message, signature), verifying_key) in
        fixture.messages.iter().zip(fixture.signatures.iter()).zip(fixture.verifying_keys.iter())
    {
        verifying_key.verify_strict(message, signature)?;
    }
    print_result("verify_single", total, started);
    Ok(())
}

#[ignore = "microbenchmark; run explicitly with --ignored --nocapture"]
#[test]
fn verify_batch64_bench() -> Result<(), Box<dyn Error>> {
    let batch_size = bench_usize_env(BATCH_ENV, DEFAULT_BATCH);
    run_batch_bench("verify_batch64", batch_size)
}

#[ignore = "microbenchmark; run explicitly with --ignored --nocapture"]
#[test]
fn verify_batch256_bench() -> Result<(), Box<dyn Error>> {
    run_batch_bench("verify_batch256", 256)
}

fn run_batch_bench(label: &str, batch_size: usize) -> Result<(), Box<dyn Error>> {
    let total = bench_usize_env(TOTAL_ENV, DEFAULT_TOTAL);
    let fixture = verify_fixture(total);
    let message_refs = fixture.messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let started = Instant::now();
    for start in (0..total).step_by(batch_size) {
        let end = start.saturating_add(batch_size).min(total);
        verify_batch(
            &message_refs[start..end],
            &fixture.signatures[start..end],
            &fixture.verifying_keys[start..end],
        )?;
    }
    print_result(&format!("{label}_size_{batch_size}"), total, started);
    Ok(())
}

fn verify_fixture(total: usize) -> VerifyFixture {
    let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
    let verifying_key = signing_key.verifying_key();
    let mut messages = Vec::with_capacity(total);
    let mut signatures = Vec::with_capacity(total);
    let mut verifying_keys = Vec::with_capacity(total);
    for index in 0..total {
        let mut message = Vec::with_capacity(48);
        message.extend_from_slice(b"ramflux.notify.verify_bench.v1:");
        message.extend_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_be_bytes());
        let signature = signing_key.sign(&message);
        messages.push(message);
        signatures.push(signature);
        verifying_keys.push(verifying_key);
    }
    VerifyFixture { messages, signatures, verifying_keys }
}

fn bench_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn print_result(label: &str, total: usize, started: Instant) {
    let elapsed = started.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let total_f64 = u32::try_from(total).map_or(f64::from(u32::MAX), f64::from);
    let ops_per_sec = if elapsed_secs > 0.0 { total_f64 / elapsed_secs } else { f64::INFINITY };
    let us_per_sig = if total > 0 { elapsed.as_secs_f64() * 1_000_000.0 / total_f64 } else { 0.0 };
    eprintln!(
        "VERIFY_BENCH label={label} total={total} elapsed_ms={} ops_per_sec={ops_per_sec:.2} us_per_sig={us_per_sig:.3}",
        elapsed.as_millis()
    );
}

// SPDX-License-Identifier: BSD-3-Clause
//! Offline project release tool; never exposed as an application/peer endpoint.
use ed25519_dalek::SigningKey;
use ramflux_card::compiler::{PackageRelease, compile_and_sign};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > max {
        return Err("input limit exceeded".into());
    }
    Ok(bytes)
}
fn append(prefix: &Path, suffix: &str) -> PathBuf {
    let mut path = prefix.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).take(5).collect();
    let [source, seed, release, output] = args.as_slice() else {
        return Err("usage: card-pack <linted-bundle.js> <32-byte-release-seed> <release.json> <output-prefix>".into());
    };
    let source = read_bounded(Path::new(source), 64 * 1024)?;
    let secret: [u8; 32] =
        read_bounded(Path::new(seed), 32)?.try_into().map_err(|_| "expected 32-byte seed")?;
    let release: PackageRelease = serde_json::from_slice(&read_bounded(Path::new(release), 4096)?)?;
    let package = compile_and_sign(&source, &SigningKey::from_bytes(&secret), &release)?;
    let output = Path::new(output);
    std::fs::write(append(output, ".qjb"), package.bytecode)?;
    std::fs::write(append(output, ".descriptor.json"), package.descriptor)?;
    std::fs::write(append(output, ".sig"), package.signature)?;
    std::fs::write(append(output, ".pub"), package.public_key)?;
    println!("PACKAGE_OK {} {}:{}", release.package_id, release.security_epoch, release.version);
    Ok(())
}

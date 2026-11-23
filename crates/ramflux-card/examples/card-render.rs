// SPDX-License-Identifier: BSD-3-Clause
//! Feed an authorized surface.get envelope to the same signed runtime used by hosts.
use ramflux_card::{AcceptancePolicy, CardSession, CardSpec, SignedPackage};
use std::{error::Error, fs::File, io::Read, path::Path};
fn read(path: &Path, max: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > max {
        return Err("input bound exceeded".into());
    }
    Ok(bytes)
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [prefix, spec, rest @ ..] = args.as_slice() else {
        return Err("usage: card-render PACKAGE_PREFIX ENVELOPE [UPDATED_ENVELOPE]".into());
    };
    if rest.len() > 1 {
        return Err("too many inputs".into());
    }
    let artifact = |suffix: &str, limit| {
        let mut name = prefix.clone();
        name.push(suffix);
        read(Path::new(&name), limit)
    };
    let bytecode = artifact(".qjb", 65536)?;
    let descriptor = artifact(".descriptor.json", 4096)?;
    let signature: [u8; 64] = artifact(".sig", 64)?.try_into().map_err(|_| "signature length")?;
    let key: [u8; 32] = artifact(".pub", 32)?.try_into().map_err(|_| "public key length")?;
    // This utility's policy/key are pinned by the operator's local artifact bundle,
    // never read from the received envelope or the package descriptor.
    let policy: AcceptancePolicy = serde_json::from_slice(&artifact(".policy.json", 4096)?)?;
    let package = SignedPackage::verify(&bytecode, &descriptor, &signature, &key, &policy)?;
    let (mut session, mount) =
        CardSession::open(CardSpec::parse(&read(Path::new(spec), 32768)?)?, package)?;
    let tree = serde_json::to_value(session.tree())?;
    let edit = rest
        .first()
        .map(|path| -> Result<_, Box<dyn Error>> {
            Ok(session.update(CardSpec::parse(&read(Path::new(path), 32768)?)?)?)
        })
        .transpose()?;
    println!(
        "{}",
        serde_json::to_string(
            &serde_json::json!({"tree":tree,"mount":mount,"edit":edit,"updated_tree":session.tree()})
        )?
    );
    Ok(())
}

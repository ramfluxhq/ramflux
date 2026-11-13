// SPDX-License-Identifier: BSD-3-Clause
#![cfg(feature = "compiler")]
#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use ramflux_card::{
        CardSession, CardSpec, SignedPackage,
        compiler::{PackageRelease, compile_and_sign},
    };
    use std::{
        fs::File,
        io::Read,
        path::{Path, PathBuf},
        process::Stdio,
        time::Duration,
    };
    const MAX_BYTECODE: u64 = 64 * 1024;
    const MAX_METADATA: u64 = 4096;
    const PACKER_DEADLINE: Duration = Duration::from_secs(5);
    fn read(path: &Path, max: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        File::open(path)
            .expect("test: output exists")
            .take(max + 1)
            .read_to_end(&mut bytes)
            .expect("test: bounded output read");
        assert!(
            u64::try_from(bytes.len()).expect("test: usize fits u64") <= max,
            "packer output exceeded its contract"
        );
        bytes
    }
    fn suffix(prefix: &Path, extension: &str) -> PathBuf {
        let mut path = prefix.as_os_str().to_os_string();
        path.push(extension);
        PathBuf::from(path)
    }
    #[tokio::test(flavor = "current_thread")]
    async fn shipping_packer_round_trips_the_real_signed_form() {
        let dir = tempfile::TempDir::new().expect("test: isolated packer directory");
        let source = dir.path().join("form.js");
        let seed = dir.path().join("seed");
        let metadata = dir.path().join("release.json");
        let prefix = dir.path().join("form.v1");
        let log = dir.path().join("packer.log");
        let release = PackageRelease {
            app_id: "org.ramflux.card".into(),
            package_id: "ramflux-card-library".into(),
            security_epoch: 1,
            version: 2,
        };
        std::fs::write(&source, include_bytes!("../library/form.js"))
            .expect("test: source fixture");
        std::fs::write(&seed, [7_u8; 32]).expect("test: synthetic seed");
        std::fs::write(&metadata, serde_json::to_vec(&release).expect("test: release metadata"))
            .expect("test: metadata fixture");
        let output = File::create(&log).expect("test: isolated process log");
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_card-pack"))
            .args([&source, &seed, &metadata, &prefix])
            .stdout(Stdio::from(output.try_clone().expect("test: log clone")))
            .stderr(Stdio::from(output))
            .kill_on_drop(true)
            .spawn()
            .expect("test: shipping packer spawn");
        let status = tokio::time::timeout(PACKER_DEADLINE, child.wait())
            .await
            .expect("test: packer deadline")
            .expect("test: process wait");
        assert!(
            status.success(),
            "shipping packer failed: {}",
            String::from_utf8_lossy(&read(&log, MAX_METADATA))
        );
        assert!(!dir.path().join("form.qjb").exists(), "dotted prefixes must not be truncated");
        let bytecode = read(&suffix(&prefix, ".qjb"), MAX_BYTECODE);
        let descriptor = read(&suffix(&prefix, ".descriptor.json"), MAX_METADATA);
        let signature: [u8; 64] =
            read(&suffix(&prefix, ".sig"), 64).try_into().expect("test: signature length");
        let public: [u8; 32] =
            read(&suffix(&prefix, ".pub"), 32).try_into().expect("test: public key length");
        let shared = compile_and_sign(
            include_bytes!("../library/form.js"),
            &SigningKey::from_bytes(&[7; 32]),
            &release,
        )
        .expect("test: shared compiler path");
        assert_eq!(
            (&bytecode, &descriptor, &signature, &public),
            (&shared.bytecode, &shared.descriptor, &shared.signature, &shared.public_key),
            "shipping packer and test compiler must emit identical engine-matched artifacts"
        );
        let package =
            SignedPackage::verify(&bytecode, &descriptor, &signature, &public, &release.policy())
                .expect("test: host policy admission");
        let spec = CardSpec::parse(include_bytes!("../fixtures/form.json"))
            .expect("test: closed card fixture");
        let (_session, batch) =
            CardSession::open(spec, package).expect("test: real packed bytecode renders");
        assert_eq!(
            batch.mutations.len(),
            4,
            "release package must render the complete form fixture"
        );
    }
}

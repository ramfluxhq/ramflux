// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline export preserves the existing discovery identity before mounting a read-only key.
pub(crate) fn export(
    state: &ramflux_node_core::FederationTrustState,
    path: &str,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    use std::io::Write;
    let seed = zeroize::Zeroizing::new(state.node_signing_seed().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::Unauthorized("no legacy signing key to export".into())
    })?);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(error)?;
    let encoded = zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(seed.as_ref()));
    file.write_all(encoded.as_bytes()).map_err(error)?;
    file.write_all(b"\n").map_err(error)?;
    file.sync_all().map_err(error)?;
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::File::open(parent).and_then(|directory| directory.sync_all()).map_err(error)?;
    }
    Ok(())
}
fn error(value: impl std::fmt::Display) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::Redb(value.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn export_preserves_identity_and_refuses_overwrite() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-key-export-{}-{}",
            std::process::id(),
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("node.key");
        let mut state = ramflux_node_core::FederationTrustState::new();
        state.set_node_signing_seed([79; 32]);
        super::export(&state, path.to_str().ok_or("key path")?)?;
        let key = ramflux_node_core::NodeSecret::from_file(&path)?;
        assert_eq!(key.with_bytes(|bytes| *bytes), [79; 32]);
        assert!(super::export(&state, path.to_str().ok_or("key path")?).is_err());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

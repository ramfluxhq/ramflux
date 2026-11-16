// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;

#[derive(Args)]
pub(crate) struct DiagCommand {
    #[command(subcommand)]
    pub(crate) action: DiagAction,
}

#[derive(Subcommand)]
pub(crate) enum DiagAction {
    /// Scan an unlocked account for a plaintext marker read from a file.
    Residue(ResidueArgs),
}

#[derive(Args)]
pub(crate) struct ResidueArgs {
    #[arg(long)]
    pub(crate) account: String,
    /// File whose bytes are the marker. The marker is never taken from argv.
    #[arg(long)]
    pub(crate) marker_file: PathBuf,
}

pub(crate) fn read_marker_file(path: &Path) -> Result<Vec<u8>, crate::RfError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        bytes.zeroize();
        return Err(crate::RfError::Message("residue marker exceeds 4096 bytes".into()));
    }
    if bytes.is_empty() {
        return Err(crate::RfError::Message("residue marker is empty".into()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn residue_reads_marker_from_a_file_not_argv() {
        let rejected = Cli::try_parse_from([
            "rf",
            "diag",
            "residue",
            "--account",
            "acct",
            "--marker",
            "b11canarymarker",
        ]);
        assert!(rejected.is_err(), "an argv marker is not a command");
        let parsed = Cli::try_parse_from([
            "rf",
            "diag",
            "residue",
            "--account",
            "acct",
            "--marker-file",
            "marker.bin",
        ])
        .expect("test: marker file command");
        match parsed.command {
            Command::Diag(command) => match command.action {
                DiagAction::Residue(residue) => {
                    assert_eq!(residue.account, "acct");
                    assert_eq!(residue.marker_file, PathBuf::from("marker.bin"));
                }
            },
            _ => panic!("test: residue command"),
        }
    }

    #[test]
    fn marker_file_is_bounded() {
        let directory = tempfile::tempdir().expect("test: temp");
        let path = directory.path().join("marker.bin");
        std::fs::write(&path, b"b11canarymarker").expect("test: write");
        let marker = read_marker_file(&path).expect("test: read");
        assert_eq!(marker, b"b11canarymarker");
        std::fs::write(&path, vec![b'x'; 4097]).expect("test: long");
        assert!(read_marker_file(&path).is_err(), "a marker over 4096 bytes is refused");
        std::fs::write(&path, b"").expect("test: empty");
        assert!(read_marker_file(&path).is_err(), "an empty marker file is refused");
    }
}

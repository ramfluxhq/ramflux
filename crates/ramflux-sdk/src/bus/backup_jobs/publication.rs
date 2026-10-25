// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! No-overwrite publication on local and removable filesystems.
use std::{io, path::Path};
pub(super) fn publish(temporary: &Path, output: &Path) -> io::Result<()> {
    publish_with_link(temporary, output, |from, to| std::fs::hard_link(from, to))
}
fn publish_with_link(
    temporary: &Path,
    output: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    match link(temporary, output) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        // The encrypted temporary is already in the destination directory. NOREPLACE maps to
        // RENAME_EXCL on Apple platforms and RENAME_NOREPLACE on Linux, without a TOCTOU check.
        Err(_) => rustix::fs::renameat_with(
            rustix::fs::CWD,
            temporary,
            rustix::fs::CWD,
            output,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r2_a_no_hardlink_destination_publishes_atomically_without_overwriting_existing_files()
    -> io::Result<()> {
        let root = crate::bus::runtime_tests::root("backup-no-hardlink");
        std::fs::create_dir_all(&root)?;
        let temp = root.join(".partial");
        let output = root.join("backup.rfb");
        std::fs::write(&temp, b"authenticated archive")?;
        publish_with_link(&temp, &output, |_, _| Err(io::ErrorKind::Unsupported.into()))?;
        assert_eq!(std::fs::read(&output)?, b"authenticated archive");
        std::fs::write(&temp, b"another archive")?;
        assert!(
            publish_with_link(&temp, &output, |_, _| Err(io::ErrorKind::PermissionDenied.into()))
                .is_err()
        );
        assert_eq!(std::fs::read(&output)?, b"authenticated archive");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exclusive archive publication, including bounded copy for NFS/FUSE without rename flags.
use super::io::PartialFile;
use std::{
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
pub(super) fn publish_cancellable(
    temporary: &Path,
    output: &Path,
    cancel: &AtomicBool,
) -> io::Result<()> {
    publish_with_operations(
        temporary,
        output,
        |from, to| std::fs::hard_link(from, to),
        exclusive_rename,
        cancel,
    )
}
fn exclusive_rename(from: &Path, to: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}
#[cfg(test)]
fn publish_with_link(
    temporary: &Path,
    output: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    publish_with_operations(temporary, output, link, exclusive_rename, &AtomicBool::new(false))
}
fn publish_with_operations(
    temporary: &Path,
    output: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
    rename: impl FnOnce(&Path, &Path) -> io::Result<()>,
    cancel: &AtomicBool,
) -> io::Result<()> {
    if cancel.load(Ordering::Acquire) {
        return Err(io::ErrorKind::ConnectionAborted.into());
    }
    match link(temporary, output) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(e),
        Err(_) => {}
    }
    match rename(temporary, output) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
        Err(_) => copy_exclusive(temporary, output, cancel),
    }
}
fn copy_exclusive(temporary: &Path, output: &Path, cancel: &AtomicBool) -> io::Result<()> {
    let mut source = std::fs::File::open(temporary)?;
    let mut destination =
        std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(output)?;
    let mut guard = PartialFile { path: output.to_owned(), published: false };
    let parent = output.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if fs2::available_space(parent)? < source.metadata()?.len() {
        return Err(io::ErrorKind::StorageFull.into());
    }
    let mut buffer = vec![0; 64 * 1024].into_boxed_slice();
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        destination.write_all(&buffer[..n])?;
    }
    destination.sync_all()?;
    guard.published = true;
    Ok(())
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

#[cfg(test)]
mod fallback_tests {
    use super::*;
    #[test]
    fn r3_no_link_or_exclusive_rename_destination_uses_streamed_no_overwrite_copy() -> io::Result<()>
    {
        let root = crate::bus::runtime_tests::root("backup-copy-fallback");
        std::fs::create_dir_all(&root)?;
        let source = root.join("partial");
        let output = root.join("final");
        let bytes = vec![42; 2 * 1024 * 1024 + 1];
        std::fs::write(&source, &bytes)?;
        let unsupported = |_: &Path, _: &Path| Err(io::ErrorKind::Unsupported.into());
        let cancel = AtomicBool::new(false);
        publish_with_operations(&source, &output, unsupported, unsupported, &cancel)?;
        assert_eq!(std::fs::read(&output)?, bytes);
        assert!(
            publish_with_operations(&source, &output, unsupported, unsupported, &cancel).is_err()
        );
        assert_eq!(std::fs::read(&output)?, bytes);
        let failed = root.join("failed");
        assert!(
            publish_with_operations(&root, &failed, unsupported, unsupported, &cancel).is_err()
        );
        assert!(!failed.exists(), "failed copy must unlink its exclusive partial final");
        let cancelled = root.join("cancelled");
        cancel.store(true, Ordering::Release);
        assert!(
            publish_with_operations(&source, &cancelled, unsupported, unsupported, &cancel)
                .is_err()
        );
        assert!(!cancelled.exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Filesystem ownership for test fixtures. Depend on this crate only as a dev-dependency.
use std::ffi::OsStr;
use std::io::{self, Write as _};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

/// A path whose clones and explicit `child` paths retain a temporary directory.
/// Ordinary `PathBuf` operations borrow/derive paths without transferring this owner.
#[derive(Clone, Debug)]
#[must_use]
pub struct TestPath {
    path: PathBuf,
    directory: Arc<TempDir>,
}

impl TestPath {
    /// Allocate an existing private directory; all derived paths stay owned by the fixture.
    ///
    /// # Errors
    /// Returns an error if allocation or CI ownership recording fails.
    #[track_caller]
    pub fn new() -> io::Result<Self> {
        let directory = Arc::new(tempfile::Builder::new().prefix("rf-test-").tempdir()?);
        let canonical = directory.path().canonicalize()?;
        record_owner(&canonical, std::panic::Location::caller())?;
        // Native tools such as OpenSSL do not consistently accept Windows verbatim paths.
        // Keep the public path absolute without introducing a verbatim prefix.
        #[cfg(windows)]
        let path = std::path::absolute(directory.path())?;
        #[cfg(not(windows))]
        let path = canonical;
        Ok(Self { path, directory })
    }

    /// Copy the path while keeping this cleanup owner in the caller's scope.
    #[must_use]
    pub fn to_path_buf(&self) -> PathBuf {
        self.path.clone()
    }

    /// Derive a path without giving up the cleanup owner.
    pub fn child(&self, path: impl AsRef<Path>) -> Self {
        Self { path: self.path.join(path), directory: Arc::clone(&self.directory) }
    }

    /// Change the extension while retaining the containing directory.
    pub fn with_extension(&self, extension: impl AsRef<OsStr>) -> Self {
        Self { path: self.path.with_extension(extension), directory: Arc::clone(&self.directory) }
    }

    /// Change the file name while retaining the containing directory.
    pub fn with_file_name(&self, name: impl AsRef<OsStr>) -> Self {
        Self { path: self.path.with_file_name(name), directory: Arc::clone(&self.directory) }
    }
}

// The job owns this bounded journal, outside individual fixtures. CI initializes it
// before sudo tests so later unprivileged allocations can still append diagnostics.
fn record_owner(path: &Path, location: &std::panic::Location<'_>) -> io::Result<()> {
    const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
    let Some(base) = std::env::var_os("RF_TEST_TMPDIR").filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let base = PathBuf::from(base).canonicalize()?;
    if path.parent() != Some(base.as_path()) {
        return Ok(());
    }
    let Some(name) = path.file_name() else { return Ok(()) };
    let thread = std::thread::current();
    let label: String = thread.name().unwrap_or("unnamed").chars().take(512).collect();
    let record = format!("{}\t{:?} at {location}\n", name.to_string_lossy(), label);
    let mut journal =
        std::fs::OpenOptions::new().create(true).append(true).open(base.join(".test-owners"))?;
    if journal.metadata()?.len() >= MAX_JOURNAL_BYTES {
        return Err(io::Error::other("test ownership journal exceeded its bounded budget"));
    }
    journal.write_all(record.as_bytes())
}

impl Deref for TestPath {
    type Target = PathBuf;
    fn deref(&self) -> &Self::Target {
        &self.path
    }
}
impl DerefMut for TestPath {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.path
    }
}
impl<T: AsRef<Path> + ?Sized> PartialEq<T> for TestPath {
    fn eq(&self, other: &T) -> bool {
        self.path == other.as_ref()
    }
}
impl PartialEq<TestPath> for PathBuf {
    fn eq(&self, other: &TestPath) -> bool {
        self == &other.path
    }
}
impl PartialEq<TestPath> for &Path {
    fn eq(&self, other: &TestPath) -> bool {
        *self == other.path
    }
}
impl Eq for TestPath {}

impl AsRef<Path> for TestPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
impl AsRef<OsStr> for TestPath {
    fn as_ref(&self) -> &OsStr {
        self.path.as_os_str()
    }
}

/// Drop the real fixture before its filesystem owner, including on an assertion failure.
#[must_use]
pub struct Fixture<T> {
    value: T,
    _path: TestPath,
}
impl<T> Fixture<T> {
    pub const fn new(value: T, path: TestPath) -> Self {
        Self { value, _path: path }
    }
}
impl<T> Deref for Fixture<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl<T> DerefMut for Fixture<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_paths_keep_files_until_the_last_owner_drops() -> io::Result<()> {
        let root = TestPath::new()?;
        let directory = root.to_path_buf();
        let file = root.child("store.redb").with_extension("wal");
        std::fs::write(&file, b"fixture")?;
        drop(root);
        assert!(file.exists(), "dropping the factory path must not invalidate its returned file");
        drop(file);
        assert!(!directory.exists(), "the last owner must remove the directory and every sidecar");
        Ok(())
    }

    #[test]
    fn fixture_drops_before_its_filesystem_owner() -> io::Result<()> {
        struct CheckFile(PathBuf);
        impl Drop for CheckFile {
            fn drop(&mut self) {
                assert!(self.0.exists(), "fixture teardown must still have access to its files");
            }
        }
        let root = TestPath::new()?;
        let directory = root.to_path_buf();
        let file = root.join("data");
        std::fs::write(&file, b"fixture")?;
        let fixture = Fixture::new(CheckFile(file), root);
        drop(fixture);
        assert!(!directory.exists(), "fixture teardown must release its final directory owner");
        Ok(())
    }
}

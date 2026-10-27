// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exclusive allocation of federation test directories; collisions are never removed.
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

pub(crate) struct TestDirectory {
    path: PathBuf,
}

impl Deref for TestDirectory {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for TestDirectory {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _removed = remove_created_directory(&self.path);
    }
}

pub(crate) fn temp_cert_root(name: &str) -> io::Result<TestDirectory> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    create_unique(&std::env::temp_dir(), name, &SEQUENCE).map(|path| TestDirectory { path })
}

pub(crate) fn temp_store_path(name: &str) -> io::Result<PathBuf> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    Ok(create_unique(&std::env::temp_dir(), name, &SEQUENCE)?.join("store.redb"))
}

pub(crate) fn remove_store_path(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "test store has no parent"))?;
    remove_created_directory(parent)
}

fn created_directories() -> &'static Mutex<std::collections::BTreeSet<PathBuf>> {
    static CREATED: OnceLock<Mutex<std::collections::BTreeSet<PathBuf>>> = OnceLock::new();
    CREATED.get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
}

fn remove_created_directory(path: &Path) -> io::Result<()> {
    let mut created =
        created_directories().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !created.contains(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test directory was not allocated by this process",
        ));
    }
    match std::fs::remove_dir_all(path) {
        Ok(()) => {
            created.retain(|candidate| !candidate.starts_with(path));
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            created.retain(|candidate| !candidate.starts_with(path));
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn create_unique(parent: &Path, name: &str, sequence: &AtomicU64) -> io::Result<PathBuf> {
    for _ in 0..1024 {
        let next = sequence.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("ramflux-federation-{name}-{}-{next}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                created_directories()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(path.clone());
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "test directory collision budget exhausted"))
}

#[test]
fn colliding_and_parallel_allocations_never_delete_another_tests_files() -> io::Result<()> {
    let parent = temp_cert_root("allocation-regression")?;
    let counter = AtomicU64::new(0);
    let collision = parent.join(format!("ramflux-federation-same-{}-0", std::process::id()));
    std::fs::create_dir(&collision)?;
    std::fs::write(collision.join("sentinel"), "owned by another fixture")?;
    let paths = std::thread::scope(|scope| -> io::Result<Vec<PathBuf>> {
        let threads: Vec<_> =
            (0..32).map(|_| scope.spawn(|| create_unique(&parent, "same", &counter))).collect();
        threads
            .into_iter()
            .map(|thread| {
                thread.join().map_err(|_| io::Error::other("allocation thread panicked"))?
            })
            .collect()
    })?;
    assert_eq!(paths.iter().collect::<std::collections::BTreeSet<_>>().len(), 32);
    assert!(!paths.contains(&collision));
    assert_eq!(std::fs::read_to_string(collision.join("sentinel"))?, "owned by another fixture");
    drop(parent);
    Ok(())
}

#[test]
fn store_paths_are_allocated_inside_exclusive_directories() -> io::Result<()> {
    let first = temp_store_path("store-allocation")?;
    let second = temp_store_path("store-allocation")?;
    assert_ne!(first.parent(), second.parent());
    assert_eq!(first.file_name().and_then(|name| name.to_str()), Some("store.redb"));
    std::fs::write(&first, "first fixture")?;
    remove_store_path(&second)?;
    assert_eq!(std::fs::read_to_string(&first)?, "first fixture");
    remove_store_path(&first)
}

#[test]
fn cleanup_rejects_an_untracked_matching_directory() -> io::Result<()> {
    let path =
        std::env::temp_dir().join(format!("ramflux-federation-untracked-{}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    let store = path.join("store.redb");
    let Err(error) = remove_store_path(&store) else {
        return Err(io::Error::other("untracked directory was removed"));
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(path.is_dir());
    std::fs::remove_dir_all(path)
}

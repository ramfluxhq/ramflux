// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded filesystem scan for residue needles. Paths are locations, not contents.

use crate::SdkError;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};
use std::time::Instant;
use zeroize::Zeroize;

const MAX_FILES: usize = 4096;
const MAX_VISITS: usize = 8192;
const MAX_DEPTH: usize = 8;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const WINDOW: usize = 64 * 1024;
const MAX_LOCATIONS: usize = 32;

pub(super) struct ScanRoot<'a> {
    pub(super) path: &'a Path,
    pub(super) scope: &'static str,
}

pub(super) struct FileRecord {
    pub(super) path: String,
    pub(super) present: bool,
    pub(super) scope: &'static str,
    pub(super) hits: u64,
    pub(super) truncated: bool,
    pub(super) locations: Vec<u64>,
}

pub(super) struct FileScan {
    pub(super) records: Vec<FileRecord>,
    pub(super) hits: u64,
    pub(super) truncated: bool,
}

pub(super) fn scan_roots(
    data_root: &Path,
    roots: &[ScanRoot<'_>],
    needles: &[Vec<u8>],
    deadline: Instant,
) -> Result<FileScan, SdkError> {
    let mut records = Vec::new();
    let mut hits = 0u64;
    let mut truncated = false;
    let mut files = 0usize;
    let mut visits = 0usize;
    for root in roots {
        check_deadline(deadline)?;
        if !allowed_scope(root.scope) {
            return Err(SdkError::LocalBus("residue scan directory scope is invalid".into()));
        }
        let relative = relative_path(data_root, root.path)?;
        let meta = match std::fs::symlink_metadata(root.path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                records.push(FileRecord {
                    path: relative,
                    present: false,
                    scope: root.scope,
                    hits: 0,
                    truncated: false,
                    locations: Vec::new(),
                });
                continue;
            }
            Err(_) => {
                return Err(SdkError::LocalBus("residue scan could not read a directory".into()));
            }
        };
        if meta.file_type().is_symlink() {
            return Err(SdkError::LocalBus("residue scan refused a symlink".into()));
        }
        if meta.is_file() {
            let scanned = scan_file(root.path, &relative, root.scope, needles, deadline)?;
            hits = hits.saturating_add(scanned.hits);
            truncated |= scanned.truncated;
            records.push(scanned);
            files = files.saturating_add(1);
            if files > MAX_FILES {
                return Err(SdkError::LocalBus("residue scan file count exceeds 4096".into()));
            }
            continue;
        }
        if !meta.is_dir() {
            return Err(SdkError::LocalBus("residue scan refused a special file".into()));
        }
        records.push(FileRecord {
            path: relative,
            present: true,
            scope: root.scope,
            hits: 0,
            truncated: false,
            locations: Vec::new(),
        });
        let mut walk = Walk {
            data_root,
            needles,
            deadline,
            records: &mut records,
            hits: &mut hits,
            truncated: &mut truncated,
            files: &mut files,
            visits: &mut visits,
        };
        walk.run(root.path, root.scope, 1)?;
    }
    Ok(FileScan { records, hits, truncated })
}

struct Walk<'a> {
    data_root: &'a Path,
    needles: &'a [Vec<u8>],
    deadline: Instant,
    records: &'a mut Vec<FileRecord>,
    hits: &'a mut u64,
    truncated: &'a mut bool,
    files: &'a mut usize,
    visits: &'a mut usize,
}

impl Walk<'_> {
    fn run(&mut self, directory: &Path, scope: &'static str, depth: usize) -> Result<(), SdkError> {
        if depth > MAX_DEPTH {
            return Err(SdkError::LocalBus("residue scan directory depth exceeds 8".into()));
        }
        check_deadline(self.deadline)?;
        let mut children = Vec::new();
        let entries = std::fs::read_dir(directory)
            .map_err(|_| SdkError::LocalBus("residue scan could not read a directory".into()))?;
        for entry in entries {
            let entry = entry.map_err(|_| {
                SdkError::LocalBus("residue scan could not read a directory".into())
            })?;
            *self.visits = self.visits.saturating_add(1);
            if *self.visits > MAX_VISITS {
                return Err(SdkError::LocalBus(
                    "residue scan directory entry count exceeds 8192".into(),
                ));
            }
            children.push(entry.path());
        }
        children.sort();
        for path in children {
            self.visit(&path, scope, depth)?;
        }
        Ok(())
    }

    fn visit(&mut self, path: &Path, scope: &'static str, depth: usize) -> Result<(), SdkError> {
        check_deadline(self.deadline)?;
        let meta = std::fs::symlink_metadata(path)
            .map_err(|_| SdkError::LocalBus("residue scan could not read a file".into()))?;
        if meta.file_type().is_symlink() {
            return Err(SdkError::LocalBus("residue scan refused a symlink".into()));
        }
        let relative = relative_path(self.data_root, path)?;
        if meta.is_dir() {
            self.records.push(FileRecord {
                path: relative,
                present: true,
                scope,
                hits: 0,
                truncated: false,
                locations: Vec::new(),
            });
            self.run(path, scope, depth.saturating_add(1))?;
        } else if meta.is_file() {
            let scanned = scan_file(path, &relative, scope, self.needles, self.deadline)?;
            *self.hits = self.hits.saturating_add(scanned.hits);
            *self.truncated |= scanned.truncated;
            self.records.push(scanned);
            *self.files = self.files.saturating_add(1);
            if *self.files > MAX_FILES {
                return Err(SdkError::LocalBus("residue scan file count exceeds 4096".into()));
            }
        } else {
            return Err(SdkError::LocalBus("residue scan refused a special file".into()));
        }
        Ok(())
    }
}

fn scan_file(
    path: &Path,
    relative: &str,
    scope: &'static str,
    needles: &[Vec<u8>],
    deadline: Instant,
) -> Result<FileRecord, SdkError> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| SdkError::LocalBus("residue scan could not read a file".into()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(SdkError::LocalBus("residue scan refused a symlink".into()));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(SdkError::LocalBus("residue scan file exceeds 16 MiB".into()));
    }
    let file = File::open(path)
        .map_err(|_| SdkError::LocalBus("residue scan could not read a file".into()))?;
    let opened = file
        .metadata()
        .map_err(|_| SdkError::LocalBus("residue scan could not read a file".into()))?;
    if opened.len() != meta.len() || !same_file(&meta, &opened) {
        return Err(SdkError::LocalBus("residue scan refused a symlink".into()));
    }
    let found = read_needles(file, needles, deadline)?;
    Ok(FileRecord {
        path: relative.to_owned(),
        present: true,
        scope,
        hits: found.hits,
        truncated: found.truncated,
        locations: found.locations,
    })
}

fn read_needles(
    mut file: File,
    needles: &[Vec<u8>],
    deadline: Instant,
) -> Result<MatchFound, SdkError> {
    let overlap = needles.iter().map(Vec::len).max().unwrap_or(0).saturating_sub(1);
    let mut carry = Vec::new();
    let mut file_offset = 0u64;
    let mut read_total = 0u64;
    let mut found = MatchFound::default();
    let mut buffer = vec![0u8; WINDOW];
    loop {
        check_deadline(deadline)?;
        let read = file
            .read(&mut buffer)
            .map_err(|_| SdkError::LocalBus("residue scan could not read a file".into()))?;
        if read == 0 {
            record_matches(&carry, file_offset, carry.len(), needles, &mut found);
            break;
        }
        read_total = read_total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if read_total > MAX_FILE_BYTES {
            buffer.zeroize();
            carry.zeroize();
            return Err(SdkError::LocalBus("residue scan file exceeds 16 MiB".into()));
        }
        carry.extend_from_slice(&buffer[..read]);
        let release = carry.len().saturating_sub(overlap);
        if release > 0 {
            record_matches(&carry, file_offset, release, needles, &mut found);
            carry.drain(..release);
            file_offset = file_offset.saturating_add(u64::try_from(release).unwrap_or(u64::MAX));
        }
    }
    buffer.zeroize();
    carry.zeroize();
    Ok(found)
}

#[derive(Default)]
struct MatchFound {
    locations: Vec<u64>,
    hits: u64,
    truncated: bool,
}

fn record_matches(
    window: &[u8],
    base: u64,
    limit: usize,
    needles: &[Vec<u8>],
    found: &mut MatchFound,
) {
    let limit = limit.min(window.len());
    for needle in needles {
        if needle.is_empty() || needle.len() > window.len() {
            continue;
        }
        let mut start = 0usize;
        while start < limit {
            let Some(index) =
                window[start..].windows(needle.len()).position(|chunk| chunk == needle.as_slice())
            else {
                break;
            };
            let at = start.saturating_add(index);
            if at >= limit {
                break;
            }
            found.hits = found.hits.saturating_add(1);
            if found.locations.len() < MAX_LOCATIONS {
                found.locations.push(base.saturating_add(u64::try_from(at).unwrap_or(u64::MAX)));
            } else {
                found.truncated = true;
            }
            start = at.saturating_add(1);
        }
    }
}

fn relative_path(data_root: &Path, path: &Path) -> Result<String, SdkError> {
    if path.components().any(|component| matches!(component, Component::ParentDir)) {
        return Err(SdkError::LocalBus("residue scan path escapes the data root".into()));
    }
    let relative = path
        .strip_prefix(data_root)
        .map_err(|_| SdkError::LocalBus("residue scan path escapes the data root".into()))?;
    let mut rendered = String::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let text = part
                    .to_str()
                    .ok_or_else(|| SdkError::LocalBus("residue scan path is not utf-8".into()))?;
                if !rendered.is_empty() {
                    rendered.push('/');
                }
                rendered.push_str(text);
            }
            Component::CurDir => {}
            _ => {
                return Err(SdkError::LocalBus("residue scan path escapes the data root".into()));
            }
        }
    }
    Ok(rendered)
}

fn allowed_scope(scope: &str) -> bool {
    scope == "account" || scope == "shared"
}

fn check_deadline(deadline: Instant) -> Result<(), SdkError> {
    if Instant::now() >= deadline {
        Err(SdkError::LocalBus("residue scan exceeded its deadline".into()))
    } else {
        Ok(())
    }
}

fn same_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev() && before.ino() == after.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (before, after);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_counts_a_match_once_when_it_starts_before_the_overlap() {
        let needle = b"b11canarymarker".to_vec();
        let mut window = vec![0u8; 80];
        window[60..75].copy_from_slice(&needle);
        let mut found = MatchFound::default();
        record_matches(&window, 1000, 64, std::slice::from_ref(&needle), &mut found);
        assert_eq!(found.hits, 1, "match starting inside the released prefix counts");
        assert_eq!(found.locations, vec![1060]);
        found = MatchFound::default();
        record_matches(&window, 1000, 60, &[needle], &mut found);
        assert_eq!(found.hits, 0, "a match starting in the overlap belongs to the next window");
    }
}

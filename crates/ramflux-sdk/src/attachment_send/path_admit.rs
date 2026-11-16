// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Open a regular file from an account-directory fd. Symlinks are `path_refused`.

use std::{fs::File, path::Path};

use super::codes::{CODE_PATH_REFUSED, Refusal};

/// # Errors
/// Returns `path_refused` for a symlink, a non-regular file, or a path that leaves the anchor.
#[cfg(unix)]
pub(crate) fn open_anchored(anchor: &Path, relative: &Path) -> Result<File, Refusal> {
    use std::path::Component;

    use rustix::fs::{self, FileType, Mode, OFlags};

    if relative.is_absolute() {
        return Err(Refusal::new(CODE_PATH_REFUSED));
    }
    let mut dir = fs::open(
        anchor,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Refusal::new(CODE_PATH_REFUSED))?;
    let parts: Vec<_> = relative.components().collect();
    if parts.is_empty() {
        return Err(Refusal::new(CODE_PATH_REFUSED));
    }
    for (index, component) in parts.iter().enumerate() {
        let Component::Normal(name) = *component else {
            return Err(Refusal::new(CODE_PATH_REFUSED));
        };
        let last = index + 1 == parts.len();
        let flags = if last {
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
        };
        let next = fs::openat(&dir, name, flags, Mode::empty())
            .map_err(|_| Refusal::new(CODE_PATH_REFUSED))?;
        if last {
            let stat = fs::fstat(&next).map_err(|_| Refusal::new(CODE_PATH_REFUSED))?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(Refusal::new(CODE_PATH_REFUSED));
            }
            return Ok(File::from(next));
        }
        dir = next;
    }
    Err(Refusal::new(CODE_PATH_REFUSED))
}

/// # Errors
/// Always returns `path_refused` on platforms without an anchored directory fd.
#[cfg(not(unix))]
pub(crate) fn open_anchored(_anchor: &Path, _relative: &Path) -> Result<File, Refusal> {
    Err(Refusal::new(CODE_PATH_REFUSED))
}

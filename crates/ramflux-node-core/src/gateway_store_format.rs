// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway format v3 is fresh-state-only; older stores fail before state publication.
use super::replay_journal;
use crate::{GATEWAY_STATE_TABLE, NodeCoreError};
use redb::{ReadableDatabase, ReadableTable};
use std::path::Path;

pub(super) const FORMAT: &str = "gateway_state_format";
// Public database paths may never enter this exclusively reserved directory.
const STAGING_DIRECTORY: &str = ".ramflux-gateway-staging-v1";
const STAGING_PREFIX: &str = ".gateway-init-";
const STAGING_RANDOM_LENGTH: usize = 16;
const STAGING_OWNER_FILE: &str = ".ramflux-gateway-staging-owner-v1";
pub(super) fn open(path: impl AsRef<Path>) -> Result<redb::Database, NodeCoreError> {
    open_with(path.as_ref(), |_| {})
}

fn open_with(
    path: &Path,
    mut initialized: impl FnMut(bool),
) -> Result<redb::Database, NodeCoreError> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    refuse_reserved_path(path)?;
    refuse_reserved_path(&directory.canonicalize().map_err(redb_error)?)?;
    if path.try_exists().map_err(redb_error)? {
        refuse_reserved_path(&path.canonicalize().map_err(redb_error)?)?;
    }
    // Serialize cleanup and publication across all stores sharing the reserved namespace.
    let initialization = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(directory.join(".gateway-init.lock"))
        .map_err(redb_error)?;
    fs2::FileExt::lock_exclusive(&initialization).map_err(redb_error)?;
    let staging_directory = directory.join(STAGING_DIRECTORY);
    prepare_staging_directory(&staging_directory)?;
    // Cleanup precedes creation/publication and never scans the public directory.
    sweep_abandoned_stages(&staging_directory, path, std::time::SystemTime::now())?;
    let mut builder = redb::Database::builder();
    builder.set_cache_size(super::GATEWAY_REPLAY_PAGE_CACHE_BYTES);
    if !path.try_exists().map_err(redb_error)? {
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        // Only a fully committed v3 database can acquire the public name. An interrupted
        // creator leaves an unpublished temporary file; old public files remain refused.
        let stage = tempfile::Builder::new()
            .prefix(STAGING_PREFIX)
            .rand_bytes(STAGING_RANDOM_LENGTH)
            .tempfile_in(&staging_directory)
            .map_err(redb_error)?;
        let db = builder.create(stage.path()).map_err(redb_error)?;
        initialized(false);
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write.open_table(GATEWAY_STATE_TABLE).map_err(redb_error)?;
            table.insert(FORMAT, b"3".as_slice()).map_err(redb_error)?;
        }
        replay_journal::initialize_tables(&write)?;
        super::session_overlay::initialize_tables(&write)?;
        write.commit().map_err(redb_error)?;
        drop(db);
        stage.as_file().sync_all().map_err(redb_error)?;
        initialized(true);
        match stage.persist_noclobber(path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(redb_error(error)),
        }
        #[cfg(unix)]
        std::fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(redb_error)?;
    }
    let db = builder.open(path).map_err(redb_error)?;
    {
        let read = db.begin_read().map_err(redb_error)?;
        let table = read
            .open_table(GATEWAY_STATE_TABLE)
            .map_err(|_| NodeCoreError::GatewayStateResetRequired)?;
        if table.get(FORMAT).map_err(redb_error)?.is_none_or(|value| value.value() != b"3") {
            return Err(NodeCoreError::GatewayStateResetRequired);
        }
    }
    Ok(db)
}
fn prepare_staging_directory(directory: &Path) -> Result<(), NodeCoreError> {
    match std::fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(redb_error(error)),
    }
    let metadata = std::fs::symlink_metadata(directory).map_err(redb_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(NodeCoreError::GatewayStateReservedPath);
    }
    let marker = directory.join(STAGING_OWNER_FILE);
    match std::fs::symlink_metadata(&marker) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 0 {
                return Err(NodeCoreError::GatewayStateReservedPath);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // An old arbitrary public path may already occupy this directory. Never adopt
            // its contents as stages. An empty directory is safe after a pre-marker crash.
            if std::fs::read_dir(directory).map_err(redb_error)?.next().is_some() {
                return Err(NodeCoreError::GatewayStateReservedPath);
            }
            // An empty create-new marker is atomic: no partial marker-content crash window.
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(marker)
                .map_err(redb_error)?;
            file.sync_all().map_err(redb_error)?;
        }
        Err(error) => return Err(redb_error(error)),
    }
    #[cfg(unix)]
    {
        std::fs::File::open(directory).and_then(|file| file.sync_all()).map_err(redb_error)?;
        if let Some(parent) = directory.parent() {
            std::fs::File::open(parent).and_then(|file| file.sync_all()).map_err(redb_error)?;
        }
    }
    Ok(())
}

fn refuse_reserved_path(path: &Path) -> Result<(), NodeCoreError> {
    if path.components().any(|part| {
        part.as_os_str().as_encoded_bytes().eq_ignore_ascii_case(STAGING_DIRECTORY.as_bytes())
    }) {
        return Err(NodeCoreError::GatewayStateReservedPath);
    }
    // Canonicalization can preserve case/Unicode aliases on case-insensitive filesystems.
    // Compare actual directory identities too, before admitting any public path.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for directory in path.ancestors() {
            let Some(parent) = directory.parent() else { continue };
            let Some(actual) = existing_metadata(directory)? else { continue };
            if !actual.is_dir() {
                continue;
            }
            if let Some(reserved) = existing_metadata(&parent.join(STAGING_DIRECTORY))?
                && actual.dev() == reserved.dev()
                && actual.ino() == reserved.ino()
            {
                return Err(NodeCoreError::GatewayStateReservedPath);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn existing_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, NodeCoreError> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(redb_error(error)),
    }
}

fn is_stage_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().and_then(|name| name.strip_prefix(STAGING_PREFIX)).is_some_and(|suffix| {
        suffix.len() == STAGING_RANDOM_LENGTH
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn sweep_abandoned_stages(
    directory: &Path,
    public_path: &Path,
    before: std::time::SystemTime,
) -> Result<(), NodeCoreError> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let published = match std::fs::metadata(public_path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(redb_error(error)),
    };
    for entry in std::fs::read_dir(directory).map_err(redb_error)? {
        let entry = entry.map_err(redb_error)?;
        if !is_stage_name(&entry.file_name()) || entry.path() == public_path {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(redb_error)?;
        // A leftover hard-link to the published inode is committed state, not an orphan.
        #[cfg(unix)]
        if metadata.nlink() > 1
            || published.as_ref().is_some_and(|published| {
                published.dev() == metadata.dev() && published.ino() == metadata.ino()
            })
        {
            continue;
        }
        // Without a portable file-identity check, retain stages when a public DB exists.
        #[cfg(not(unix))]
        if published.is_some() {
            continue;
        }
        if metadata.is_file() && metadata.modified().map_err(redb_error)? < before {
            std::fs::remove_file(entry.path()).map_err(redb_error)?;
        }
    }
    Ok(())
}

fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::ReadableTableMetadata;

    #[test]
    fn old_gateway_format_is_refused_without_partial_open() -> Result<(), Box<dyn std::error::Error>>
    {
        for (with_data, old_marker) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let directory = tempfile::TempDir::new()?;
            let path = directory.path().join("gateway.redb");
            {
                let db = redb::Database::create(&path)?;
                let write = db.begin_write()?;
                {
                    let mut table = write.open_table(GATEWAY_STATE_TABLE)?;
                    if old_marker {
                        table.insert(FORMAT, &b"2"[..])?;
                    }
                    if with_data {
                        table.insert(
                            "replay_guard_state",
                            br#"{"accepted_by_key":{}}"#.as_slice(),
                        )?;
                    }
                }
                write.commit()?;
            }
            assert!(
                matches!(
                    crate::GatewayRedbStore::open(&path),
                    Err(NodeCoreError::GatewayStateResetRequired)
                ),
                "old stores must fail closed before publication"
            );
            let db = redb::Database::open(&path)?;
            let read = db.begin_read()?;
            let table = read.open_table(GATEWAY_STATE_TABLE)?;
            assert_eq!(
                table.get(FORMAT)?.is_some(),
                old_marker,
                "refusal must not change the marker"
            );
            assert_eq!(
                table.len()?,
                u64::from(with_data) + u64::from(old_marker),
                "refusal must not rewrite old rows"
            );
            drop(table);
            drop(read);
            drop(db);
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
    #[test]
    fn staging_cleanup_preserves_public_database_with_reserved_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        // This also matches the exact stage-name grammar, but is a PUBLIC path.
        let path = directory.path().join(".gateway-init-0123456789abcdef");
        let other = directory.path().join("gateway.redb");
        let store = crate::GatewayRedbStore::open(&path)?;
        let mut state = crate::GatewayState::new();
        state.configure_pre_auth_policy(&crate::GatewayPreAuthConfig {
            per_source_ip_handshake_rate: 7,
            ..Default::default()
        })?;
        store.save_state(&state)?;
        let other_store = crate::GatewayRedbStore::open(&other)?;
        assert!(path.try_exists()?, "opening B must preserve active public A");
        assert_eq!(
            store
                .load_state()?
                .ok_or("test: active A snapshot lost")?
                .pre_auth_policy()
                .per_source_ip_handshake_rate,
            7,
            "opening B must preserve active A state"
        );
        drop(other_store);
        drop(store);
        let image = std::fs::read(&path)?;
        drop(crate::GatewayRedbStore::open(&other)?);
        assert_eq!(std::fs::read(&path)?, image, "opening B must not modify closed public A");
        let reopened = crate::GatewayRedbStore::open(&path)?;
        assert_eq!(
            reopened
                .load_state()?
                .ok_or("test: public snapshot lost")?
                .pre_auth_policy()
                .per_source_ip_handshake_rate,
            7,
            "staging cleanup must never replace the configured public database"
        );
        Ok(())
    }

    #[test]
    fn staging_cleanup_refuses_preexisting_unowned_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let reserved = directory.path().join(STAGING_DIRECTORY);
        std::fs::create_dir(&reserved)?;
        let old_public = reserved.join(".gateway-init-0123456789abcdef");
        {
            let database = redb::Database::create(&old_public)?;
            let write = database.begin_write()?;
            {
                let mut table = write.open_table(GATEWAY_STATE_TABLE)?;
                table.insert(FORMAT, b"3".as_slice())?;
                table.insert("published-canary", b"preserve".as_slice())?;
            }
            write.commit()?;
        }
        let image = std::fs::read(&old_public)?;
        #[cfg(unix)]
        {
            let alias = directory.path().join("stage-directory-alias");
            std::os::unix::fs::symlink(&reserved, &alias)?;
            assert!(
                matches!(
                    refuse_reserved_path(&alias.join("public.redb")),
                    Err(NodeCoreError::GatewayStateReservedPath)
                ),
                "directory identity must reject aliases independently of lexical canonicalization"
            );
            for name in [
                STAGING_DIRECTORY.to_ascii_uppercase(),
                STAGING_DIRECTORY.replace("staging", "ſtaging"),
            ] {
                let alias = directory.path().join(name);
                if alias.try_exists()? {
                    assert!(
                        matches!(
                            open(alias.join("public.redb")),
                            Err(NodeCoreError::GatewayStateReservedPath)
                        ),
                        "case-folding filesystem aliases must not enter the staging namespace"
                    );
                }
            }
        }
        let other = directory.path().join("other.redb");
        assert!(
            matches!(open(&other), Err(NodeCoreError::GatewayStateReservedPath)),
            "an unowned nonempty namespace must fail closed before cleanup"
        );
        assert_eq!(
            std::fs::read(&old_public)?,
            image,
            "namespace reservation must never modify an existing public database"
        );
        assert!(!other.try_exists()?, "refusal must precede new database publication");
        assert!(
            !reserved.join(STAGING_OWNER_FILE).try_exists()?,
            "an ambiguous namespace must not acquire an ownership marker"
        );
        let database = redb::Database::open(&old_public)?;
        let read = database.begin_read()?;
        let table = read.open_table(GATEWAY_STATE_TABLE)?;
        assert_eq!(
            table.get("published-canary")?.map(|value| value.value().to_vec()),
            Some(b"preserve".to_vec()),
            "committed old public data must reopen unchanged"
        );
        Ok(())
    }

    #[test]
    fn active_initializer_holds_cleanup_lock_until_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("gateway.redb");
        let database = open_with(&path, |_| {
            let lock = std::fs::OpenOptions::new()
                .write(true)
                .open(directory.path().join(".gateway-init.lock"))
                .expect("test: initializer lock exists");
            let error = fs2::FileExt::try_lock_exclusive(&lock)
                .expect_err("test: active initializer owns cleanup lock");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::WouldBlock,
                "cleanup must not enter an active initializer"
            );
        })?;
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .open(directory.path().join(".gateway-init.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        assert!(path.try_exists()?, "publication must complete before cleanup lock is released");
        drop(database);
        Ok(())
    }

    #[tokio::test]
    async fn published_database_survives_crash_and_staging_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        const CHILD_PATH: &str = "RAMFLUX_TEST_GATEWAY_PUBLISHED_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let path = Path::new(&path);
            let store = crate::GatewayRedbStore::open(path)?;
            let mut state = crate::GatewayState::new();
            state.configure_pre_auth_policy(&crate::GatewayPreAuthConfig {
                per_source_ip_handshake_rate: 11,
                ..Default::default()
            })?;
            store.save_state(&state)?;
            // Abrupt death after publication and a real committed write: no Drop cleanup.
            std::process::exit(92);
        }
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join(".gateway-init-0123456789abcdef");
        let mut command = tokio::process::Command::new(std::env::current_exe()?);
        command.args(["--exact", "gateway_state::store_format::tests::published_database_survives_crash_and_staging_cleanup"])
            .env(CHILD_PATH, &path).stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()).kill_on_drop(true);
        let status =
            tokio::time::timeout(std::time::Duration::from_secs(10), command.status()).await??;
        assert_eq!(status.code(), Some(92), "child must crash after its committed public write");
        let staging = directory.path().join(STAGING_DIRECTORY);
        let orphan = staging.join(".gateway-init-abcdefghijklmnop");
        drop(redb::Database::create(&orphan)?);
        let ambiguous = staging.join(".gateway-init-public.redb");
        std::fs::write(&ambiguous, b"not a recognized stage")?;
        let alias = staging.join(".gateway-init-ABCDEFGHIJKLMNOP");
        std::fs::hard_link(&path, &alias)?;
        assert!(
            matches!(open(&orphan), Err(NodeCoreError::GatewayStateReservedPath)),
            "public stores must never use the cleanup namespace"
        );
        drop(crate::GatewayRedbStore::open(directory.path().join("other.redb"))?);
        assert!(
            alias.try_exists()?,
            "opening another public store must preserve committed aliases"
        );
        let store = crate::GatewayRedbStore::open(&path)?;
        assert_eq!(
            store
                .load_state()?
                .ok_or("test: crash lost published state")?
                .pre_auth_policy()
                .per_source_ip_handshake_rate,
            11,
            "restart must retain the exact committed public state"
        );
        assert!(!orphan.try_exists()?, "restart must remove a real orphaned stage");
        assert!(ambiguous.try_exists()?, "non-stage names must not be swept");
        assert!(alias.try_exists()?, "published inode aliases must not be swept");
        drop(store);
        drop(crate::GatewayRedbStore::open(&path)?);
        Ok(())
    }

    #[tokio::test]
    async fn initial_creation_crash_never_publishes_unmarked_database()
    -> Result<(), Box<dyn std::error::Error>> {
        const CHILD_PATH: &str = "RAMFLUX_TEST_GATEWAY_INIT_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let after_commit = std::env::var("RAMFLUX_TEST_GATEWAY_INIT_COMMITTED")? == "true";
            open_with(Path::new(&path), |committed| {
                if committed == after_commit {
                    std::process::exit(91);
                }
            })?;
            return Err("initialization crash hook was not reached".into());
        }
        let directory = tempfile::TempDir::new()?;
        for committed in [false, true] {
            let path = directory.path().join(format!("gateway-{committed}.redb"));
            let mut command = tokio::process::Command::new(std::env::current_exe()?);
            command.args(["--exact", "gateway_state::store_format::tests::initial_creation_crash_never_publishes_unmarked_database"])
                .env(CHILD_PATH, &path)
                .env("RAMFLUX_TEST_GATEWAY_INIT_COMMITTED", committed.to_string())
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .kill_on_drop(true);
            let status = tokio::time::timeout(std::time::Duration::from_secs(10), command.status())
                .await??;
            assert_eq!(
                status.code(),
                Some(91),
                "child must crash at the selected initialization boundary"
            );
            assert!(
                !path.try_exists()?,
                "a crashed initializer must not publish a partial database"
            );
            let store = crate::GatewayRedbStore::open(&path)?;
            drop(store);
            assert!(
                std::fs::read_dir(directory.path().join(STAGING_DIRECTORY))?
                    .all(|entry| entry.is_ok_and(|entry| entry.file_name() == STAGING_OWNER_FILE)),
                "restart must sweep staging files abandoned at either crash boundary"
            );
            let db = open(&path)?;
            let read = db.begin_read()?;
            let table = read.open_table(GATEWAY_STATE_TABLE)?;
            assert_eq!(
                table.get(FORMAT)?.map(|value| value.value().to_vec()),
                Some(b"3".to_vec()),
                "retry must publish a committed v3 marker"
            );
        }
        Ok(())
    }
}

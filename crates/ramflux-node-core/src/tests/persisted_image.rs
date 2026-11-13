// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded logical redb images and byte-exact WAL images cover complete persisted state.
use std::{
    collections::BTreeMap,
    io::{Read, Seek},
    path::{Path, PathBuf},
};
const FILE_BYTE_CAP: u64 = 32 * 1024 * 1024;
const FILE_COUNT_CAP: usize = 256;
const DEPTH_CAP: usize = 4;
type Image = BTreeMap<PathBuf, (u64, [u8; 32])>;

type TestError = Box<dyn std::error::Error>;
const TABLE_COUNT_CAP: usize = 256;
const ROW_COUNT_CAP: u64 = 65_536;

fn table_image<K: redb::Key + 'static, V: redb::Value + 'static>(
    read: &redb::ReadTransaction,
    name: &str,
) -> Result<Option<(u64, [u8; 32])>, TestError> {
    use redb::ReadableTable;
    let table = match read.open_table(redb::TableDefinition::<K, V>::new(name)) {
        Ok(table) => table,
        Err(redb::TableError::TableTypeMismatch { .. }) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut hash = blake3::Hasher::new();
    hash.update(format!("{:?}/{:?}", K::type_name(), V::type_name()).as_bytes());
    let mut count = 0_u64;
    let mut bytes = 0_u64;
    for row in table.iter()? {
        if count >= ROW_COUNT_CAP {
            return Err("fixture row count exceeded bound".into());
        }
        let (key, value) = row?;
        let key = key.value();
        let value = value.value();
        let key = K::as_bytes(&key);
        let value = V::as_bytes(&value);
        for part in [key.as_ref(), value.as_ref()] {
            let len = u64::try_from(part.len())?;
            bytes = bytes.checked_add(len).ok_or("fixture byte count overflow")?;
            if bytes > FILE_BYTE_CAP {
                return Err("fixture table exceeded byte cap".into());
            }
            hash.update(&len.to_le_bytes());
            hash.update(part);
        }
        count += 1;
    }
    Ok(Some((count, *hash.finalize().as_bytes())))
}

pub(crate) fn database_image(db: &redb::Database) -> Result<(u64, [u8; 32]), TestError> {
    use redb::{ReadableDatabase, TableHandle};
    let read = db.begin_read()?;
    if read.list_multimap_tables()?.next().is_some() {
        return Err("fixture multimap type requires an explicit decoder".into());
    }
    let mut tables = BTreeMap::new();
    for handle in read.list_tables()? {
        if tables.len() >= TABLE_COUNT_CAP {
            return Err("fixture table count exceeded bound".into());
        }
        let name = handle.name();
        let mut found = None;
        macro_rules! candidate {
            ($key:ty, $value:ty) => {
                if found.is_none() {
                    found = table_image::<$key, $value>(&read, name)?;
                }
            };
        }
        candidate!(&str, &[u8]);
        candidate!(&str, u8);
        candidate!(&str, u64);
        candidate!(&str, bool);
        candidate!(&str, &str);
        candidate!(&str, (u64, u64));
        candidate!(u64, &[u8]);
        candidate!(&[u8], &[u8]);
        candidate!(&[u8], ());
        candidate!(&[u8], u64);
        candidate!(&[u8], &str);
        candidate!((u64, &str), u8);
        tables.insert(
            name.to_owned(),
            found.ok_or_else(|| format!("fixture table type requires decoder: {name}"))?,
        );
    }
    let mut hash = blake3::Hasher::new();
    for (name, (rows, digest)) in &tables {
        hash.update(&u64::try_from(name.len())?.to_le_bytes());
        hash.update(name.as_bytes());
        hash.update(&rows.to_le_bytes());
        hash.update(digest);
    }
    Ok((u64::try_from(tables.len())?, *hash.finalize().as_bytes()))
}

pub(crate) fn image(root: &Path) -> Result<Image, Box<dyn std::error::Error>> {
    fn visit(
        root: &Path,
        path: &Path,
        depth: usize,
        output: &mut Image,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if depth > DEPTH_CAP {
            return Err("fixture directory nesting exceeded bound".into());
        }
        if path.is_dir() {
            for (index, entry) in std::fs::read_dir(path)?.enumerate() {
                if index >= FILE_COUNT_CAP {
                    return Err("fixture directory exceeded bound".into());
                }
                visit(root, &entry?.path(), depth + 1, output)?;
            }
        } else {
            if output.len() >= FILE_COUNT_CAP {
                return Err("fixture file count exceeded bound".into());
            }
            let mut file = std::fs::File::open(path)?;
            if file.metadata()?.len() > FILE_BYTE_CAP {
                return Err("fixture file exceeded byte cap".into());
            }
            let mut magic = [0; 9];
            let count = file.read(&mut magic)?;
            if count == magic.len()
                && magic == [b'r', b'e', b'd', b'b', 0x1a, 0x0a, 0xa9, 0x0d, 0x0a]
            {
                drop(file);
                let db = redb::Database::open(path)?;
                output.insert(path.strip_prefix(root)?.to_path_buf(), database_image(&db)?);
                return Ok(());
            }
            file.rewind()?;
            let mut file = file.take(FILE_BYTE_CAP + 1);
            let mut count = 0_u64;
            let mut hash = blake3::Hasher::new();
            let mut buffer = [0; 4096];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                count += u64::try_from(read)?;
                if count > FILE_BYTE_CAP {
                    return Err("fixture file exceeded byte cap".into());
                }
                hash.update(buffer.get(..read).ok_or("read bounds")?);
            }
            output.insert(
                path.strip_prefix(root)?.to_path_buf(),
                (count, *hash.finalize().as_bytes()),
            );
        }
        Ok(())
    }
    let mut output = Image::new();
    visit(root, root, 0, &mut output)?;
    Ok(output)
}

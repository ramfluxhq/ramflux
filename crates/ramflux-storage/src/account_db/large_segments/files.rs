// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

#[cfg(test)]
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub(super) enum CrashPoint { Written, Synced, Renamed, Committed }

pub(super) fn private_dir(path:&Path) -> Result<(),StorageError> {
    match fs::create_dir(path) {
        Ok(()) => {
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path,fs::Permissions::from_mode(0o700))?;
            }
            sync_dir(path.parent().ok_or(StorageError::Integrity("segment directory"))?)?;
        },
        Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path)?.file_type().is_dir() { return Err(StorageError::Integrity("segment directory type")); }
        },
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn sync_dir(path:&Path) -> Result<(),StorageError> { File::open(path)?.sync_all()?; Ok(()) }
fn regular(path:&Path) -> Result<(),StorageError> {
    if !fs::symlink_metadata(path)?.file_type().is_file() { return Err(StorageError::Integrity("segment file type")); }
    Ok(())
}
fn chunk_hash(file:&mut File,offset:u64,len:usize) -> Result<[u8;32],StorageError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut remaining=len;
    let mut buffer=[0;16384];
    let mut hash=blake3::Hasher::new();
    while remaining>0 {
        let take=remaining.min(buffer.len()); file.read_exact(&mut buffer[..take])?;
        hash.update(&buffer[..take]); remaining-=take;
    }
    Ok(*hash.finalize().as_bytes())
}
fn content_hash(file:&mut File,len:u64) -> Result<[u8;32],StorageError> {
    let domain=b"ramflux.attachment.segment.cipher.v1";
    let mut hash=blake3::Hasher::new();
    hash.update(&36_u32.to_be_bytes()); hash.update(domain);
    hash.update(&u32::try_from(len).map_err(|_|StorageError::Integrity("segment length"))?.to_be_bytes());
    file.seek(SeekFrom::Start(0))?;
    let mut buffer=[0;16384]; let mut remaining=len;
    while remaining>0 {
        let take=usize::try_from(remaining.min(16384)).map_err(|_|StorageError::Integrity("segment read length"))?;
        file.read_exact(&mut buffer[..take])?; hash.update(&buffer[..take]); remaining-=take as u64;
    }
    Ok(*hash.finalize().as_bytes())
}
fn chunk_length(length:u64,chunk:u32,index:u32) -> Result<usize,StorageError> {
    let offset=u64::from(chunk)*u64::from(index);
    if offset>=length { return Err(StorageError::Integrity("network chunk index")); }
    usize::try_from((length-offset).min(u64::from(chunk))).map_err(|_|StorageError::Integrity("network chunk length"))
}
fn accounted(length:u64,chunk:u32,bits:u8) -> Result<i64,StorageError> {
    let mut bytes=0;
    for index in 0..length.div_ceil(u64::from(chunk)) {
        if bits & (1<<index) != 0 { bytes+=chunk_length(length,chunk,u32::try_from(index).map_err(|_|StorageError::Integrity("chunk index"))?)? as u64; }
    }
    integer(bytes)
}

impl SegmentStore<'_> {
    /// Writes one exact network chunk. File and directory fsync precede the
    /// durable bitmap acknowledgement; a complete segment is hashed and renamed
    /// before metadata publication. Retries must supply identical ciphertext.
    /// # Errors
    /// Refuses stale identities, conflicts, corrupt complete segments and I/O failures.
    pub fn checkpoint(&mut self,id:&str,generation:u64,index:u32,chunk_index:u32,bytes:&[u8]) -> Result<(),StorageError> {
        let (_,chunk)=self.current(id,generation)?;
        let row=self.page(id,generation,index,1)?.into_iter().next().filter(|r| r.index==index).ok_or(StorageError::Integrity("segment index"))?;
        let len=chunk_length(row.expected_length,chunk,chunk_index)?;
        if bytes.len()!=len { return Err(StorageError::Integrity("network chunk length")); }
        let dir=self.directory(id,generation)?;
        let part=dir.join(format!("{index}.part")); let final_path=dir.join(format!("{index}.segment"));
        let path=if row.cipher_verified { &final_path } else { &part };
        let mut hashes:Vec<u8>=self.db.connection.query_row("SELECT chunk_digests FROM object_segment_file WHERE transfer_id=?1 AND generation=?2 AND segment_index=?3",params![id,integer(generation)?,index],|r|r.get(0))?;
        let bit=1_u8.checked_shl(chunk_index).ok_or(StorageError::Integrity("network chunk index"))?;
        let start=chunk_index as usize*32;
        if row.received_bitmap & bit != 0 {
            regular(path)?;
            let mut file=File::open(path)?;
            let actual=chunk_hash(&mut file,u64::from(chunk)*u64::from(chunk_index),len)?;
            if actual!=*blake3::hash(bytes).as_bytes() || hashes.get(start..start+32)!=Some(actual.as_slice()) { return Err(StorageError::Integrity("conflicting chunk retry")); }
            return Ok(());
        }
        let mut file=match OpenOptions::new().read(true).write(true).create_new(true).open(&part) {
            Ok(file)=>file,
            Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists => { regular(&part)?; OpenOptions::new().read(true).write(true).open(&part)? },
            Err(e)=>return Err(e.into()),
        };
        file.seek(SeekFrom::Start(u64::from(chunk)*u64::from(chunk_index)))?;
        file.write_all(bytes)?;
        #[cfg(test)] self.crash_at(CrashPoint::Written)?;
        file.sync_all()?;
        sync_dir(&dir)?;
        #[cfg(test)] self.crash_at(CrashPoint::Synced)?;
        let bits=row.received_bitmap|bit;
        hashes.get_mut(start..start+32).ok_or(StorageError::Integrity("chunk hash length"))?.copy_from_slice(blake3::hash(bytes).as_bytes());
        let full=bits.count_ones()==u32::try_from(row.expected_length.div_ceil(u64::from(chunk))).map_err(|_|StorageError::Integrity("chunk count"))?;
        if full {
            if file.metadata()?.len()!=row.expected_length || content_hash(&mut file,row.expected_length)?!=row.expected_digest { return Err(StorageError::Integrity("segment ciphertext hash")); }
            fs::rename(&part,&final_path)?;
            sync_dir(&dir)?;
            #[cfg(test)] self.crash_at(CrashPoint::Renamed)?;
        }
        self.persist(id,generation,&row,chunk,bits,&hashes,full)?;
        #[cfg(test)] self.crash_at(CrashPoint::Committed)?;
        Ok(())
    }

    /// Revalidates a bounded page after restart, without hydrating whole segments.
    /// Missing/corrupt data loses its bitmap before the method returns. A valid
    /// renamed file from an interrupted commit can be adopted only after Hseg.
    /// # Errors
    /// Refuses stale generations, inaccessible files and database failures.
    pub fn reconcile_page(&mut self,id:&str,generation:u64,start:u32,limit:u32) -> Result<Vec<SegmentPageEntry>,StorageError> {
        let (_,chunk)=self.current(id,generation)?;
        let rows=self.page(id,generation,start,limit)?;
        let dir=self.directory(id,generation)?;
        for row in rows {
            let final_path=dir.join(format!("{}.segment",row.index)); let part=dir.join(format!("{}.part",row.index));
            let mut hashes:Vec<u8>=self.db.connection.query_row("SELECT chunk_digests FROM object_segment_file WHERE transfer_id=?1 AND generation=?2 AND segment_index=?3",params![id,integer(generation)?,row.index],|r|r.get(0))?;
            let mut bits=0_u8; let mut full=false;
            let final_exists=final_path.try_exists()?;
            let path=if final_exists { &final_path } else { &part };
            if path.try_exists()? {
                regular(path)?;
                let mut file=File::open(path)?;
                let file_len=file.metadata()?.len();
                if final_exists && file_len==row.expected_length && content_hash(&mut file,row.expected_length)?==row.expected_digest {
                    full=true;
                    for index in 0..u32::try_from(row.expected_length.div_ceil(u64::from(chunk))).map_err(|_|StorageError::Integrity("chunk count"))? {
                        bits|=1<<index;
                        let hash=chunk_hash(&mut file,u64::from(index)*u64::from(chunk),chunk_length(row.expected_length,chunk,index)?)?;
                        let offset=index as usize*32;
                        hashes.get_mut(offset..offset+32).ok_or(StorageError::Integrity("chunk hashes"))?.copy_from_slice(&hash);
                    }
                } else if !final_exists {
                    for index in 0..u32::try_from(row.expected_length.div_ceil(u64::from(chunk))).map_err(|_|StorageError::Integrity("chunk count"))? {
                        let bit=1<<index; let length=chunk_length(row.expected_length,chunk,index)?;
                        if row.received_bitmap&bit!=0 && file_len>=u64::from(index)*u64::from(chunk)+length as u64 {
                            let hash=chunk_hash(&mut file,u64::from(index)*u64::from(chunk),length)?;
                            if hashes.get(index as usize*32..index as usize*32+32)==Some(hash.as_slice()) { bits|=bit; }
                        }
                    }
                }
            }
            if final_exists && !full { fs::remove_file(&final_path)?; sync_dir(&dir)?; }
            // Re-establish durability before adopting bytes after interrupted commit.
            if full { File::open(&final_path)?.sync_all()?; sync_dir(&dir)?; }
            if bits!=row.received_bitmap || full!=row.cipher_verified || row.authenticated {
                self.persist(id,generation,&row,chunk,bits,&hashes,full)?;
            }
        }
        self.page(id,generation,start,limit)
    }

    fn persist(&self,id:&str,generation:u64,row:&SegmentPageEntry,chunk:u32,bits:u8,hashes:&[u8],full:bool) -> Result<(),StorageError> {
        let tx=self.db.connection.immediate_transaction()?;
        self.current(id,generation)?;
        let previous:u8=self.db.connection.query_row("SELECT received_bitmap FROM object_segment_file WHERE transfer_id=?1 AND generation=?2 AND segment_index=?3",params![id,integer(generation)?,row.index],|r|r.get(0))?;
        if previous!=row.received_bitmap { return Err(StorageError::ObjectIdentityConflict); }
        self.db.connection.execute("UPDATE object_segment_file SET received_bitmap=?4,chunk_digests=?5,cipher_verified=?6,authenticated=0 WHERE transfer_id=?1 AND generation=?2 AND segment_index=?3",params![id,integer(generation)?,row.index,bits,hashes,full])?;
        let delta=accounted(row.expected_length,chunk,bits)?-accounted(row.expected_length,chunk,previous)?;
        self.db.connection.execute("UPDATE object_transfer_state SET done_bytes=done_bytes+?2,segment_sequence=segment_sequence+1 WHERE transfer_id=?1",params![id,delta])?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn crash_at(&self,point:CrashPoint) -> Result<(),StorageError> {
        if self.crash==Some(point) { return Err(std::io::Error::other("simulated crash boundary").into()); }
        Ok(())
    }
}

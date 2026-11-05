// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S3 storage orchestration over an injected authenticated operator client.
//! The client must enforce finite deadlines, bounded streaming, TLS/issuer policy,
//! conditional writes and S3's embedded completion errors. It never returns URLs.
use ramflux_node_core::attachment::backend::{AttachmentBackend,BackendCommit,BackendError,BackendSegment,LocalAttachmentBackend};
use std::io::{Read,Write};

#[derive(Debug,Clone)]
pub struct S3Object {pub length:u64,pub digest:[u8;32]}
#[derive(Debug,Clone)]
pub struct MultipartUpload {pub key:String,pub upload_id:String}
pub struct MultipartPage {pub uploads:Vec<MultipartUpload>,pub next:Option<String>}
/// Operator credentials remain entirely inside this client. All writes are
/// conditional; implementations must report HTTP-200 XML Error responses as errors.
pub trait AuthenticatedS3Client:Send+Sync {
    /// # Errors
    /// Returns transport/storage errors; absence must be distinguished from failure.
    fn head(&self,key:&str)->Result<Option<S3Object>,BackendError>;
    /// # Errors
    /// Returns creation failure; caller journals the bounded ID before sending parts.
    fn begin_multipart(&self,key:&str,object:&S3Object)->Result<String,BackendError>;
    /// Streams one final part (segments are <=4MiB); it has no S3 minimum part size.
    /// # Errors
    /// Rejects truncated bodies and any remote upload failure.
    fn upload_final_part(&self,key:&str,id:&str,length:u64,body:&mut dyn Read)->Result<String,BackendError>;
    /// Uses If-None-Match:*; Conflict means an object already exists or changed.
    /// # Errors
    /// Returns conflict or any HTTP/XML/completion failure, never premature success.
    fn complete_if_absent(&self,key:&str,id:&str,etag:&str)->Result<(),BackendError>;
    /// Idempotent for already completed/aborted IDs; waits for actual cleanup.
    /// # Errors
    /// Retains debt when abort has not completed durably.
    fn abort_multipart(&self,key:&str,id:&str)->Result<(),BackendError>;
    /// # Errors
    /// Refuses failed/truncated/oversized bounded Range responses.
    fn read_range(&self,key:&str,offset:u64,length:u64,output:&mut dyn Write)->Result<(),BackendError>;
    /// Idempotent; success includes confirmed durable absence.
    /// # Errors
    /// Returns deletion failure rather than releasing unreclaimed storage charges.
    fn delete(&self,key:&str)->Result<(),BackendError>;
    /// # Errors
    /// Returns at most the requested limit and a bounded opaque continuation token.
    fn list_multipart(&self,prefix:&str,after:Option<&str>,limit:usize)->Result<MultipartPage,BackendError>;
}
pub struct S3AttachmentBackend<C> {stage:LocalAttachmentBackend,client:C}
impl<C:AuthenticatedS3Client> S3AttachmentBackend<C> {
    #[must_use] pub fn new(stage:LocalAttachmentBackend,client:C)->Self {Self {stage,client}}
    fn verify_remote(&self,spec:&BackendSegment)->Result<(),BackendError> {
        let key=self.stage.storage_key(spec);let head=self.client.head(&key)?.ok_or(BackendError::Integrity)?;
        if head.length!=spec.length()||head.digest!=spec.digest(){return Err(BackendError::Conflict);}
        let mut hash=ramflux_node_core::attachment::backend::SegmentHashWriter::new(spec.length());
        let mut offset=0;while offset<spec.length(){let length=(spec.length()-offset).min(u64::from(spec.chunk_bytes()));self.client.read_range(&key,offset,length,&mut hash)?;offset+=length;}
        hash.finish(spec.digest())
    }
    /// Lists and aborts abandoned uploads, including unjournaled creation windows.
    /// Active object owners are skipped; restart the next sweep from its first page.
    /// # Errors
    /// Refuses unbounded pages/cursors, foreign keys or failed durable cleanup.
    pub fn reconcile_multipart_page(&self,after:Option<&str>,limit:usize)->Result<MultipartPage,BackendError> {
        if limit==0||limit>128||after.is_some_and(|c|c.len()>1024){return Err(BackendError::Bounds);}
        let page=self.client.list_multipart(&self.stage.namespace_prefix(),after,limit)?;
        if page.uploads.len()>limit||page.next.as_ref().is_some_and(|s|s.len()>1024||Some(s.as_str())==after){return Err(BackendError::Bounds);}
        for upload in &page.uploads {
            if upload.upload_id.is_empty()||upload.upload_id.len()>1024{return Err(BackendError::Bounds);}
            match self.stage.abort_multipart(&upload.key,&upload.upload_id,||self.client.abort_multipart(&upload.key,&upload.upload_id)) {Ok(())|Err(BackendError::Busy)=>(),Err(e)=>return Err(e)}
        }
        Ok(page)
    }
}
impl<C:AuthenticatedS3Client> AttachmentBackend for S3AttachmentBackend<C> {
    fn write_chunk(&self,spec:&BackendSegment,offset:u64,input:&mut dyn Read)->Result<(),BackendError> {self.stage.write_chunk(spec,offset,input)}
    fn commit(&self,spec:&BackendSegment)->Result<BackendCommit,BackendError> {
        let mut prepared=self.stage.prepare(spec)?;let key=self.stage.storage_key(spec);
        if self.client.head(&key)?.is_some(){self.verify_remote(spec)?;return self.stage.publish(prepared);}
        let upload=self.client.begin_multipart(&key,&S3Object {length:spec.length(),digest:spec.digest()})?;
        if upload.is_empty()||upload.len()>1024 {let _=self.client.abort_multipart(&key,&upload);return Err(BackendError::Bounds);}
        if let Err(error)=self.stage.journal_upload(&prepared,Some(&upload)){let _=self.client.abort_multipart(&key,&upload);return Err(error);}
        let result=(|| {
            let etag=self.client.upload_final_part(&key,&upload,spec.length(),&mut prepared)?;
            if prepared.consumed()!=spec.length()||etag.is_empty()||etag.len()>1024{return Err(BackendError::Integrity);}
            match self.client.complete_if_absent(&key,&upload,&etag) {Ok(())=>(),Err(BackendError::Conflict)=>{self.client.abort_multipart(&key,&upload)?;},Err(e)=>return Err(e)}
            self.verify_remote(spec)
        })();
        if let Err(error)=result {
            if self.client.abort_multipart(&key,&upload).is_ok(){self.stage.journal_upload(&prepared,None)?;}
            return Err(error);
        }
        self.stage.publish(prepared)
    }
    fn read_range(&self,spec:&BackendSegment,offset:u64,length:u64,output:&mut dyn Write)->Result<(),BackendError> {
        // The local read gate validates range/state/tombstone and byte count before
        // remote I/O. No bulk body is retained in a metadata-only cache.
        self.stage.read_range(spec,offset,length,&mut std::io::sink())?;
        let mut bounded=BoundedWriter {output,remaining:length};self.client.read_range(&self.stage.storage_key(spec),offset,length,&mut bounded)?;
        if bounded.remaining!=0{return Err(BackendError::Integrity);}Ok(())
    }
    fn delete(&self,spec:&BackendSegment)->Result<(),BackendError> {
        // Retain local stage/journal when remote deletion fails; quota settlement
        // may only follow this method's successful result for every segment.
        let key=self.stage.storage_key(spec);
        if let Some(id)=self.stage.status(spec)?.upload {self.stage.abort_multipart(&key,&id,||self.client.abort_multipart(&key,&id))?;}
        self.client.delete(&key)?;self.stage.delete(spec)
    }
}
struct BoundedWriter<'a>{output:&'a mut dyn Write,remaining:u64}
impl Write for BoundedWriter<'_> {
    fn write(&mut self,bytes:&[u8])->std::io::Result<usize>{if bytes.len() as u64>self.remaining{return Err(std::io::Error::other("oversized S3 range"));}self.output.write_all(bytes)?;self.remaining-=bytes.len() as u64;Ok(bytes.len())}
    fn flush(&mut self)->std::io::Result<()>{self.output.flush()}
}
#[cfg(test)]
mod tests;

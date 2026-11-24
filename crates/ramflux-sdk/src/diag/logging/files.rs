// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! File ownership, bounded lines and rotation live only on the writer thread.
use super::{Command, DiagnosticConfig, now_ms};
use crate::SdkError;
use serde_json::{Value, json};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;

pub(super) struct Files {
    dir: PathBuf,
    config: DiagnosticConfig,
    file: File,
    bytes: u64,
    unflushed: usize,
    epoch: u64,
    next_name: u64,
}
impl Files {
    pub(super) fn open(
        root: &Path,
        config: DiagnosticConfig,
        epoch: u64,
    ) -> Result<Self, SdkError> {
        let dir = root.join("diag");
        if !dir.exists() {
            crate::platform::fs::create_owner_only_dir(&dir)?;
        }
        if !std::fs::symlink_metadata(&dir)?.is_dir() {
            return Err(SdkError::LocalBus("diagnostic directory refused".into()));
        }
        crate::platform::fs::set_owner_only_dir(&dir)?;
        prune(&dir, &config)?;
        let (file, next_name) = create(&dir, &config.process, epoch)?;
        Ok(Self { dir, config, file, bytes: 0, unflushed: 0, epoch, next_name })
    }
    pub(super) fn run(mut self, receiver: &Receiver<Command>) {
        while let Ok(command) = receiver.recv() {
            match command {
                Command::Record(value, flush) => {
                    if self.write(value, flush).is_err() {
                        break;
                    }
                }
                Command::Flush(done) => {
                    let _ = self.file.sync_data();
                    let _ = done.send(());
                }
                Command::Stop => break,
            }
        }
        let _ = self.file.sync_data();
    }
    fn write(&mut self, mut value: Value, flush: bool) -> Result<(), SdkError> {
        // Reserve the largest sequence spelling before choosing the file; the actual line is smaller.
        value["s"] = json!(u64::MAX);
        let mut line = serde_json::to_vec(&value)?;
        if line.len() >= 2048 {
            value["f"] = json!({});
            value["trunc"] = json!(true);
            line = serde_json::to_vec(&value)?;
        }
        if line.len() >= 2048 {
            return Ok(());
        }
        line.push(b'\n');
        if self.bytes.saturating_add(line.len() as u64) > self.config.max_file_bytes {
            self.file.sync_data()?;
            prune(&self.dir, &self.config)?;
            let (file, next) =
                create(&self.dir, &self.config.process, now_ms().max(self.next_name))?;
            self.file = file;
            self.next_name = next;
            self.bytes = 0;
        }
        if self.bytes == 0 {
            self.header()?;
        }
        value["s"] = json!(super::next_sequence());
        line = serde_json::to_vec(&value)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.bytes += line.len() as u64;
        self.unflushed += line.len();
        if flush || self.unflushed >= 16 * 1024 {
            self.file.sync_data()?;
            self.unflushed = 0;
        }
        Ok(())
    }
    fn header(&mut self) -> Result<(), SdkError> {
        let mut header = serde_json::to_vec(
            &json!({"schema":"ramflux.diag.v1","t":now_ms(),"m":super::elapsed_ms(),"s":super::next_sequence(),"lv":"I","p":self.config.process,"ly":"sdk","c":"sdk.diag","e":"proc.start","f":{"build_class":self.config.build_class,"level":self.config.level,"key_epoch":self.epoch}}),
        )?;
        header.push(b'\n');
        self.file.write_all(&header)?;
        self.bytes = header.len() as u64;
        Ok(())
    }
}
fn create(dir: &Path, process: &str, initial: u64) -> Result<(File, u64), SdkError> {
    for offset in 0..32 {
        let stamp = initial.saturating_add(offset);
        match crate::platform::fs::create_new_owner_only_io(
            &dir.join(format!("{process}.{stamp}.ndjson")),
        ) {
            Ok(file) => return Ok((file, stamp.saturating_add(1))),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(SdkError::LocalBus("diagnostic file collision".into()))
}
fn prune(dir: &Path, config: &DiagnosticConfig) -> Result<(), SdkError> {
    let mut files = Vec::new();
    for (visited, entry) in std::fs::read_dir(dir)?.take(4097).enumerate() {
        if visited == 4096 {
            return Err(SdkError::LocalBus("diagnostic directory capacity".into()));
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(stamp) = name
            .strip_prefix(&format!("{}.", config.process))
            .and_then(|s| s.strip_suffix(".ndjson"))
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        if !entry.file_type()?.is_file() {
            continue;
        }
        if files.len() == 4096 {
            return Err(SdkError::LocalBus("diagnostic directory capacity".into()));
        }
        let modified = entry
            .metadata()?
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |v| u64::try_from(v.as_millis()).unwrap_or(u64::MAX));
        let modified = if entry.metadata()?.len() > config.max_file_bytes { 0 } else { modified };
        files.push((stamp, modified, entry.path()));
    }
    files.sort_by_key(|entry| entry.0);
    let remove_count = files.len().saturating_sub(config.max_files.saturating_sub(1));
    let cutoff = now_ms().saturating_sub(config.max_age_days * 86_400_000);
    for (index, (_, modified, path)) in files.into_iter().enumerate() {
        if index < remove_count || modified < cutoff {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

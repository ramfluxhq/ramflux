// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `runtime.json` and the ancestor permission rule. A file is fresh when its pid is the process
//! that wrote `started_at` and a loopback capabilities read still advertises `host_bootstrap_v1`.

use super::refused;
use crate::SdkError;
use ramflux_prx_client::{ClientConfig, HOST_BOOTSTRAP_V1, PrxClient};
use serde::Deserialize;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct RuntimeView {
    pub path: PathBuf,
    pub prx_version: String,
    pub api_base: String,
    pub pid: u32,
    pub owner_id: String,
    pub started_at: String,
    pub fresh: bool,
    pub alive: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    prx_version: String,
    api_base: String,
    pid: u32,
    owner_id: String,
    started_at: String,
    capabilities_url: String,
}

pub(crate) fn check_dir(path: &Path, memory: bool) -> Result<(), SdkError> {
    let chain = chain(path)?;
    let uid = rustix::process::getuid().as_raw();
    for (index, dir) in chain.iter().enumerate() {
        let meta = std::fs::metadata(dir)?;
        if !meta.is_dir() || !allows(&meta, uid, index == 0 && memory) {
            return Err(rejected(dir, meta.mode()));
        }
    }
    Ok(())
}

pub(crate) async fn inspect(dir: &Path) -> Result<Option<RuntimeView>, SdkError> {
    let path = dir.join("runtime.json");
    if !path.is_file() {
        return Ok(None);
    }
    let wire = read_runtime(&path)?;
    let started = parse_rfc3339(&wire.started_at);
    let start = process_start(wire.pid);
    let alive = start.is_some();
    let same = match (start, started) {
        (Some(start), Some(at)) => start <= at.saturating_add(2),
        _ => false,
    };
    let fresh = same && capabilities_ok(&wire, &dir.join("owner.token")).await;
    Ok(Some(RuntimeView {
        path,
        prx_version: wire.prx_version,
        api_base: wire.api_base,
        pid: wire.pid,
        owner_id: wire.owner_id,
        started_at: wire.started_at,
        fresh,
        alive,
    }))
}

fn allows(meta: &std::fs::Metadata, uid: u32, memory: bool) -> bool {
    let mode = meta.mode();
    let owner = meta.uid();
    if memory {
        return owner == uid && mode & 0o777 == 0o700;
    }
    let writable = mode & 0o022 != 0;
    let sticky_root = owner == 0 && mode & 0o1000 != 0;
    (owner == uid || owner == 0) && (!writable || sticky_root)
}

fn rejected(path: &Path, mode: u32) -> SdkError {
    refused("ancestor_rejected", format!("{} mode {:04o}", path.display(), mode & 0o7777))
}

fn chain(start: &Path) -> Result<Vec<PathBuf>, SdkError> {
    let mut out = Vec::new();
    let mut cur = std::fs::canonicalize(start)?;
    loop {
        out.push(cur.clone());
        match cur.parent() {
            Some(parent) if parent != cur => cur = parent.to_path_buf(),
            _ => break,
        }
    }
    Ok(out)
}

fn read_runtime(path: &Path) -> Result<Wire, SdkError> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || meta.mode() & 0o777 != 0o600 {
        return Err(refused("runtime_mode", "runtime.json must be mode 0600"));
    }
    let bytes =
        read_capped(path, 8192).ok_or_else(|| refused("runtime_invalid", "runtime.json"))?;
    let wire: Wire =
        serde_json::from_slice(&bytes).map_err(|_| refused("runtime_invalid", "runtime.json"))?;
    if !field_ok(&wire.prx_version, 64)
        || !field_ok(&wire.owner_id, 128)
        || !loopback_base(&wire.api_base)
        || wire.capabilities_url != format!("{}/api/capabilities", wire.api_base)
        || wire.pid == 0
        || parse_rfc3339(&wire.started_at).is_none()
    {
        return Err(refused("runtime_invalid", "runtime.json"));
    }
    Ok(wire)
}

fn field_ok(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

fn loopback_base(url: &str) -> bool {
    let rest = url.strip_prefix("http://127.0.0.1:").or_else(|| url.strip_prefix("http://[::1]:"));
    matches!(rest.and_then(|text| text.parse::<u16>().ok()), Some(port) if port != 0)
}

async fn capabilities_ok(wire: &Wire, token: &Path) -> bool {
    let settings = ClientConfig::new(&wire.api_base, token);
    let Ok(client) = PrxClient::new(&settings) else {
        return false;
    };
    let Ok(caps) = client.capabilities().await else {
        return false;
    };
    caps.prx_version == wire.prx_version && caps.has(HOST_BOOTSTRAP_V1)
}

fn process_start(pid: u32) -> Option<i64> {
    if pid == 0 {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        linux_start(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos_start(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_start(pid: u32) -> Option<i64> {
    let stat = read_capped(format!("/proc/{pid}/stat"), 4096)?;
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    let rest = std::str::from_utf8(stat.get(close.saturating_add(1)..)?).ok()?;
    let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    let text = read_capped("/proc/stat", 65_536)?;
    let text = std::str::from_utf8(&text).ok()?;
    let btime = btime_of(text)?;
    i64::try_from(btime.saturating_add(ticks / 100)).ok()
}

#[cfg(target_os = "linux")]
fn btime_of(text: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn macos_start(pid: u32) -> Option<i64> {
    let output = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    parse_lstart(text.trim())
}

fn read_capped(path: impl AsRef<Path>, max: usize) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = file.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > max {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    if buf.is_empty() { None } else { Some(buf) }
}

#[cfg(target_os = "macos")]
fn parse_lstart(text: &str) -> Option<i64> {
    let mut parts = text.split_whitespace();
    let _dow = parts.next()?;
    let month = month_name(parts.next()?)?;
    let day: u32 = parts.next()?.parse().ok()?;
    let clock = parts.next()?;
    let year: i32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let (hour, minute, second) = parse_hms(clock)?;
    unix_secs(year, month, day, hour, minute, second)
}

fn parse_rfc3339(text: &str) -> Option<i64> {
    if text.len() > 40 {
        return None;
    }
    let (date, rest) = text.split_once('T')?;
    let mut parts = date.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let (time, offset) = split_zone(rest)?;
    let time = time.split_once('.').map_or(time, |(head, _)| head);
    let (hour, minute, second) = parse_hms(time)?;
    unix_secs(year, month, day, hour, minute, second)?.checked_sub(offset)
}

fn split_zone(rest: &str) -> Option<(&str, i64)> {
    if let Some(time) = rest.strip_suffix('Z') {
        return Some((time, 0));
    }
    let (sign, at) = if let Some(at) = rest.rfind('+') {
        (1_i64, at)
    } else {
        let at = rest.rfind('-')?;
        (-1, at)
    };
    let time = rest.get(..at)?;
    let zone = rest.get(at.saturating_add(1)..)?;
    let (hours, mins) = zone.split_once(':')?;
    let hours: i64 = hours.parse().ok()?;
    let mins: i64 = mins.parse().ok()?;
    if hours > 23 || mins > 59 {
        return None;
    }
    Some((time, sign * (hours * 3600 + mins * 60)))
}

fn parse_hms(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split(':');
    let hour = parts.next()?.parse().ok()?;
    let minute = parts.next()?.parse().ok()?;
    let second = parts.next()?.parse().ok()?;
    if parts.next().is_some() { None } else { Some((hour, minute, second)) }
}

fn unix_secs(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<i64> {
    if !(1970..=2100).contains(&year) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    if month == 0 || month > 12 || day == 0 || day > days_in(year, month) {
        return None;
    }
    let mut days = 0_i64;
    let mut cursor = 1970_i32;
    while cursor < year {
        days += i64::from(if leap(cursor) { 366 } else { 365 });
        cursor += 1;
    }
    let mut walk = 1_u32;
    while walk < month {
        days += i64::from(days_in(year, walk));
        walk += 1;
    }
    days += i64::from(day - 1);
    Some(days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))
}

fn days_in(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[cfg(target_os = "macos")]
fn month_name(name: &str) -> Option<u32> {
    match name {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

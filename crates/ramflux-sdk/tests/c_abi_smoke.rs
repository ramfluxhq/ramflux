// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn c_abi_smoke_runs_real_sdk_storage_and_event_queue() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_root = std::env::temp_dir().join(format!(
        "ramflux-sdk-cabi-smoke-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&temp_root)?;

    let account_root = temp_root.join("accounts");
    let mut setup_client = ramflux_sdk::RamfluxClient::new();
    setup_client.open_account_index(&account_root)?;
    setup_client.create_account("acct_cabi", "principal_cabi")?;
    drop(setup_client);

    let build_status = Command::new(env!("CARGO"))
        .current_dir(&manifest_dir)
        .args(["build", "--features", "c-abi", "--lib"])
        .status()?;
    if !build_status.success() {
        return Err("cargo build --features c-abi --lib failed".into());
    }

    let c_source = temp_root.join("c_abi_smoke.c");
    let c_binary = temp_root.join("c_abi_smoke");
    std::fs::write(&c_source, C_SMOKE_SOURCE)?;

    let include_dir = manifest_dir.join("target/include");
    let lib_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            manifest_dir.parent().and_then(std::path::Path::parent).map(|root| root.join("target"))
        })
        .ok_or("failed to locate workspace target dir")?
        .join("debug");
    let mut compile = Command::new("cc");
    compile
        .arg(&c_source)
        .arg("-I")
        .arg(&include_dir)
        .arg("-L")
        .arg(&lib_dir)
        .arg("-lramflux_sdk")
        .arg(format!("-Wl,-rpath,{}", lib_dir.display()))
        .arg("-o")
        .arg(&c_binary);
    let compile_status = compile.status()?;
    if !compile_status.success() {
        return Err("C smoke compilation failed".into());
    }

    let output = Command::new(&c_binary)
        .arg(account_root.to_string_lossy().as_ref())
        .env("DYLD_LIBRARY_PATH", &lib_dir)
        .env("LD_LIBRARY_PATH", &lib_dir)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "C smoke failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    if !stdout.contains("C_ABI_SMOKE_OK") {
        return Err(format!("C smoke did not report success: {stdout}").into());
    }

    let _ = std::fs::remove_dir_all(temp_root);
    Ok(())
}

const C_SMOKE_SOURCE: &str = r#"
#include "ramflux_sdk.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains(struct RamfluxBuffer *buffer, const char *needle) {
  if (buffer == NULL || buffer->ptr == NULL) {
    return 0;
  }
  size_t needle_len = strlen(needle);
  if (needle_len == 0) {
    return 1;
  }
  if (buffer->len < needle_len) {
    return 0;
  }
  for (size_t index = 0; index <= buffer->len - needle_len; index++) {
    if (memcmp(buffer->ptr + index, needle, needle_len) == 0) {
      return 1;
    }
  }
  return 0;
}

static int require_ok(int32_t code, struct RamfluxBuffer *error, const char *step) {
  if (code == 0) {
    return 1;
  }
  fprintf(stderr, "%s failed with code %d", step, code);
  if (error != NULL && error->ptr != NULL) {
    fprintf(stderr, ": %.*s", (int)error->len, (const char *)error->ptr);
  }
  fprintf(stderr, "\n");
  if (error != NULL) {
    ramflux_buffer_free(error);
  }
  return 0;
}

static void free_if_present(struct RamfluxBuffer *buffer) {
  if (buffer != NULL) {
    ramflux_buffer_free(buffer);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: c_abi_smoke <account_root>\n");
    return 2;
  }
  if (ramflux_sdk_abi_version_major() != 1 || ramflux_sdk_protocol_version() != 1) {
    fprintf(stderr, "unexpected ABI/protocol version\n");
    return 3;
  }

  char config[2048];
  snprintf(config, sizeof(config), "{\"account_root\":\"%s\"}", argv[1]);
  struct RamfluxClient *client = NULL;
  struct RamfluxBuffer *error = NULL;
  int32_t code = ramflux_client_new((const unsigned char *)config, strlen(config), &client, &error);
  if (!require_ok(code, error, "client_new") || client == NULL) {
    return 4;
  }

  struct RamfluxEventQueue *queue = NULL;
  error = NULL;
  code = ramflux_client_event_queue_new(client, &queue, &error);
  if (!require_ok(code, error, "event_queue_new") || queue == NULL) {
    ramflux_client_free(client);
    return 5;
  }

  const char *unlock = "{\"local_account_id\":\"acct_cabi\",\"account_secret\":\"secret-cabi\"}";
  struct RamfluxBuffer *out = NULL;
  error = NULL;
  code = ramflux_client_unlock_account(client, (const unsigned char *)unlock, strlen(unlock), &out, &error);
  if (!require_ok(code, error, "unlock_account") || !contains(out, "acct_cabi")) {
    free_if_present(out);
    ramflux_event_queue_free(queue);
    ramflux_client_free(client);
    return 6;
  }
  ramflux_buffer_free(out);

  const char *append = "{\"event_id\":\"evt_cabi\",\"event_type\":\"message.created\",\"body_base64\":\"b3BhcXVl\"}";
  out = NULL;
  error = NULL;
  code = ramflux_client_append_event(client, (const unsigned char *)append, strlen(append), &out, &error);
  if (!require_ok(code, error, "append_event") || !contains(out, "evt_cabi")) {
    free_if_present(out);
    ramflux_event_queue_free(queue);
    ramflux_client_free(client);
    return 7;
  }
  ramflux_buffer_free(out);

  const char *read = "{\"event_id\":\"evt_cabi\"}";
  out = NULL;
  error = NULL;
  code = ramflux_client_read_projection(client, (const unsigned char *)read, strlen(read), &out, &error);
  if (!require_ok(code, error, "read_projection") || !contains(out, "b3BhcXVl")) {
    free_if_present(out);
    ramflux_event_queue_free(queue);
    ramflux_client_free(client);
    return 8;
  }
  ramflux_buffer_free(out);

  uint64_t operation_id = 0;
  const char *put_object = "{\"object_id\":\"object_cabi\",\"plaintext_base64\":\"b2JqZWN0\"}";
  error = NULL;
  code = ramflux_client_put_object(client, (const unsigned char *)put_object, strlen(put_object), &operation_id, &error);
  if (!require_ok(code, error, "put_object") || operation_id == 0) {
    ramflux_event_queue_free(queue);
    ramflux_client_free(client);
    return 9;
  }

  out = NULL;
  error = NULL;
  code = ramflux_event_queue_poll(queue, 8, &out, &error);
  if (!require_ok(code, error, "event_queue_poll") || !contains(out, "\"accepted\"") || !contains(out, "\"completed\"")) {
    free_if_present(out);
    ramflux_event_queue_free(queue);
    ramflux_client_free(client);
    return 10;
  }
  ramflux_buffer_free(out);

  error = NULL;
  code = ramflux_client_close(client, &error);
  if (!require_ok(code, error, "client_close")) {
    ramflux_event_queue_free(queue);
    ramflux_client_free(client);
    return 11;
  }

  out = NULL;
  error = NULL;
  code = ramflux_event_queue_poll(queue, 8, &out, &error);
  if (!require_ok(code, error, "event_queue_poll_shutdown") || !contains(out, "\"shutdown\"")) {
    free_if_present(out);
    ramflux_event_queue_free(queue);
    ramflux_client_free(client);
    return 12;
  }
  ramflux_buffer_free(out);

  ramflux_event_queue_free(queue);
  ramflux_client_free(client);
  printf("C_ABI_SMOKE_OK\n");
  return 0;
}
"#;

/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026 Span Brain */

/*
 * Ramflux SDK C ABI, major 2.
 *
 * Hand-kept. `c_abi::v2::tests::header_declares_every_export` fails when an exported
 * major-2 symbol is missing here or a declared one is not exported.
 *
 * Built with `--features c-abi-v2`. The major-1 symbols of `ramflux_sdk.h` keep their
 * signatures and their own backend; `ramflux_sdk_abi_version_major()` still returns 1.
 * A host that wants major 2 calls `ramflux_v2_abi_version` first.
 *
 * Contract
 * --------
 * Versioned structs. Every struct passed by the host starts with `struct_size`, set to
 *   `sizeof` of the struct the host was compiled against. A size below the 2.0 layout is
 *   RAMFLUX_ERROR_CODE_INVALID_ARGUMENT (1). A size above what the core knows is
 *   RAMFLUX_ERROR_CODE_UNSUPPORTED_VERSION (3): the host negotiates down, the core never
 *   ignores a field it does not know. Reserved `flags` must be zero.
 *
 * Ownership. Inputs are borrowed for the call and copied; the host may free them when the
 *   call returns. Every `RamfluxBuffer *` written to an out-parameter belongs to the host
 *   and is released with `ramflux_buffer_free` (or `ramflux_v2_buffer_wipe_free` when it
 *   may hold a secret). Out-parameters are set to NULL before anything else happens, so a
 *   failed call never leaves a stale pointer. Handles are released with their `_free`
 *   function, exactly once.
 *
 * Errors. The return value is a `RamfluxErrorCode` number (0 = ok), the same numbers as
 *   major 1, including SchemaResetRequired = 23. `out_error_json` is optional (may be
 *   NULL) and receives diagnostic JSON:
 *     {"code":10,"name":"Timeout","message":"...","effect":"unknown",
 *      "reason_code":"deadline_exceeded","bus_code":null,"retry_after_ms":null,
 *      "details":null}
 *   Match `code` and `effect`. Strings are diagnostic.
 *     effect "none"    - the request never reached the supervisor.
 *     effect "refused" - the supervisor answered with a refusal.
 *     effect "unknown" - the request was handed to the supervisor and no answer was seen
 *                        (deadline, cancellation, close). It may have run. Reconcile with
 *                        the SAME operation_id. Do not send a new one.
 *   A cancelled request returns Timeout (10) with reason_code "cancelled".
 *
 * Panics. No call unwinds into the host. A panic is reported as PanicAborted (17).
 *
 * Threads. Calls may come from any thread. The calling thread blocks, outside the
 *   supervisor thread, for at most the request deadline plus five seconds. `_free` of a
 *   handle must not race with another call on that handle; `ramflux_v2_core_close` may.
 *
 * Events. Polling only; there is no callback. Each subscription has a bounded queue. A
 *   host that falls behind receives a terminal record {"kind":"lagged","last_seq":"N"} and
 *   subscribes again from the last sequence it applied. Sequence numbers are decimal
 *   strings.
 *
 * Disposition of the major-1 symbols
 * ----------------------------------
 * Major 1 is unchanged in this build and keeps its own backend. A host that moves to
 * major 2 replaces each symbol as follows; nothing below is removed yet.
 *   ramflux_sdk_abi_version_major, _minor, ramflux_sdk_protocol_version
 *       kept, still report major 1. Major 2 is reported by ramflux_v2_abi_version.
 *   ramflux_client_new, ramflux_client_close, ramflux_client_free
 *       ramflux_v2_core_new, ramflux_v2_core_start, ramflux_v2_core_close,
 *       ramflux_v2_core_free. Construction attaches to the one supervisor of the data
 *       root; it is not a second account runtime.
 *   ramflux_buffer_free
 *       kept and shared by both majors.
 *   ramflux_client_event_queue_new, ramflux_event_queue_poll, ramflux_event_queue_free
 *       ramflux_v2_subscribe, ramflux_v2_subscription_poll, ramflux_v2_subscription_free.
 *       Events are the supervisor's; there are no synthetic accepted or completed records.
 *   ramflux_client_negotiate_capabilities
 *       ramflux_v2_abi_version and the host ABI fields of RamfluxV2Config.
 *   ramflux_client_unlock_account, ramflux_client_validate_mcp_grant,
 *   ramflux_client_put_object
 *       ramflux_v2_execute with the supervisor's own methods (account.unlock, the MCP
 *       methods, the bounded object-transfer methods).
 *   ramflux_client_create_device_session
 *       no major-2 symbol. It already returns UnsupportedVersion and stays so.
 *   ramflux_client_append_event, ramflux_client_read_projection,
 *   ramflux_client_submit_envelope
 *       no major-2 symbol. They are raw bypass interfaces; use message.submit and the
 *       typed read methods through ramflux_v2_execute.
 */

#ifndef RAMFLUX_SDK_V2_H
#define RAMFLUX_SDK_V2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAMFLUX_V2_ABI_MAJOR 2
#define RAMFLUX_V2_ABI_MINOR 0

/* Lifecycle states written by ramflux_v2_core_state. */
#define RAMFLUX_V2_STATE_STOPPED 0
#define RAMFLUX_V2_STATE_RUNNING 1
#define RAMFLUX_V2_STATE_SUSPENDED 2

/* Same layout and free function as major 1. */
#ifndef RAMFLUX_SDK_H
typedef struct RamfluxBuffer {
  unsigned char *ptr;
  size_t len;
} RamfluxBuffer;
void ramflux_buffer_free(struct RamfluxBuffer *buffer);
#endif

typedef struct RamfluxV2Core RamfluxV2Core;
typedef struct RamfluxV2Subscription RamfluxV2Subscription;
typedef struct RamfluxV2Cancel RamfluxV2Cancel;
typedef struct RamfluxV2AccountCreation RamfluxV2AccountCreation;

typedef struct RamfluxV2Version {
  uint32_t struct_size; /* in: sizeof(RamfluxV2Version) */
  uint32_t abi_major;
  uint32_t abi_minor;
  uint32_t protocol_version;
  uint32_t max_frame_bytes;
  uint32_t max_queue_events;
  uint8_t descriptor_fingerprint[32]; /* all zero: no generated descriptor compiled in */
} RamfluxV2Version;

typedef struct RamfluxV2Config {
  uint32_t struct_size;
  uint32_t host_abi_major; /* RAMFLUX_V2_ABI_MAJOR */
  uint32_t host_abi_minor; /* RAMFLUX_V2_ABI_MINOR */
  uint32_t flags;          /* reserved, 0 */
  const unsigned char *data_root; /* UTF-8, not NUL terminated; chosen by the host */
  size_t data_root_len;
  uint32_t suspend_deadline_ms; /* 0 = default */
  uint32_t request_deadline_ms; /* 0 = default */
} RamfluxV2Config;

typedef struct RamfluxV2Request {
  uint32_t struct_size;
  uint32_t flags; /* reserved, 0 */
  const unsigned char *method; /* UTF-8, e.g. "message.submit" */
  size_t method_len;
  const unsigned char *sdk_api; /* UTF-8, e.g. "message" */
  size_t sdk_api_len;
  const unsigned char *account_id; /* UTF-8 or NULL */
  size_t account_id_len;
  const unsigned char *operation_id; /* UTF-8 or NULL; chosen by the host */
  size_t operation_id_len;
  const unsigned char *body_json; /* JSON object; NULL or empty means {} */
  size_t body_json_len;
  uint64_t deadline_unix_ms; /* absolute; 0 = configured default */
  const RamfluxV2Cancel *cancel; /* optional, borrowed */
} RamfluxV2Request;

typedef struct RamfluxV2SubscribeOptions {
  uint32_t struct_size;
  uint32_t queue_capacity; /* 0 = default; at most max_queue_events */
  const unsigned char *account_id; /* UTF-8 or NULL */
  size_t account_id_len;
  const unsigned char *body_json; /* body of subscription.open, e.g. {"topics":[...]} */
  size_t body_json_len;
} RamfluxV2SubscribeOptions;

typedef struct RamfluxV2CreateOptions {
  uint32_t struct_size;
  uint32_t flags; /* reserved, 0 */
  const unsigned char *display_name; /* UTF-8 */
  size_t display_name_len;
  const unsigned char *node_id; /* UTF-8 or NULL for the default node */
  size_t node_id_len;
} RamfluxV2CreateOptions;

typedef struct RamfluxV2CreateConfirm {
  uint32_t struct_size;
  uint32_t flags; /* reserved, 0 */
  const unsigned char *words[3]; /* the words at the challenged positions, UTF-8 */
  size_t word_lens[3];
  const unsigned char *passphrase; /* UTF-8 */
  size_t passphrase_len;
} RamfluxV2CreateConfirm;

int32_t ramflux_v2_abi_version(RamfluxV2Version *out_version);

int32_t ramflux_v2_core_new(const RamfluxV2Config *config, RamfluxV2Core **out_core,
                            RamfluxBuffer **out_error_json);
int32_t ramflux_v2_core_start(RamfluxV2Core *core, RamfluxBuffer **out_error_json);
int32_t ramflux_v2_core_suspend(RamfluxV2Core *core, RamfluxBuffer **out_report_json,
                                RamfluxBuffer **out_error_json);
int32_t ramflux_v2_core_resume(RamfluxV2Core *core, RamfluxBuffer **out_error_json);
int32_t ramflux_v2_core_stop(RamfluxV2Core *core, RamfluxBuffer **out_error_json);
int32_t ramflux_v2_core_state(RamfluxV2Core *core, uint32_t *out_state);
int32_t ramflux_v2_core_close(RamfluxV2Core *core, RamfluxBuffer **out_error_json);
void ramflux_v2_core_free(RamfluxV2Core *core);

int32_t ramflux_v2_execute(RamfluxV2Core *core, const RamfluxV2Request *request,
                           RamfluxBuffer **out_response_json, RamfluxBuffer **out_error_json);

int32_t ramflux_v2_cancel_new(RamfluxV2Cancel **out_cancel);
int32_t ramflux_v2_cancel(RamfluxV2Cancel *cancel);
void ramflux_v2_cancel_free(RamfluxV2Cancel *cancel);

int32_t ramflux_v2_subscribe(RamfluxV2Core *core, const RamfluxV2SubscribeOptions *options,
                             RamfluxV2Subscription **out_subscription,
                             RamfluxBuffer **out_error_json);
int32_t ramflux_v2_subscription_poll(RamfluxV2Subscription *subscription, uint32_t max_events,
                                     uint32_t timeout_ms, RamfluxBuffer **out_events_json,
                                     RamfluxBuffer **out_error_json);
int32_t ramflux_v2_subscription_cancel(RamfluxV2Subscription *subscription);
void ramflux_v2_subscription_free(RamfluxV2Subscription *subscription);

/*
 * Account creation is a ceremony on its own connection, not an execute request:
 *   begin -> show_once (display the phrase, then wipe it) -> challenge (three one-based
 *   positions) -> confirm (one attempt) -> free. Freeing before a successful confirm
 *   cancels. The phrase buffer is released with ramflux_v2_buffer_wipe_free. The host
 *   erases its own copies of the words and the passphrase after confirm returns.
 */
int32_t ramflux_v2_account_creation_begin(RamfluxV2Core *core,
                                          const RamfluxV2CreateOptions *options,
                                          RamfluxV2AccountCreation **out_creation,
                                          RamfluxBuffer **out_pending_json,
                                          RamfluxBuffer **out_error_json);
int32_t ramflux_v2_account_creation_show_once(RamfluxV2AccountCreation *creation,
                                              RamfluxBuffer **out_phrase,
                                              RamfluxBuffer **out_error_json);
int32_t ramflux_v2_account_creation_challenge(RamfluxV2AccountCreation *creation,
                                              uint8_t *out_positions,
                                              RamfluxBuffer **out_error_json);
int32_t ramflux_v2_account_creation_confirm(RamfluxV2AccountCreation *creation,
                                            const RamfluxV2CreateConfirm *confirm,
                                            RamfluxBuffer **out_account_json,
                                            RamfluxBuffer **out_error_json);
int32_t ramflux_v2_account_creation_cancel(RamfluxV2AccountCreation *creation,
                                           RamfluxBuffer **out_error_json);
void ramflux_v2_account_creation_free(RamfluxV2AccountCreation *creation);

void ramflux_v2_buffer_wipe_free(RamfluxBuffer *buffer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RAMFLUX_SDK_V2_H */

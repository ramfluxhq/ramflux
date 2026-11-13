/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef RAMFLUX_SDK_H
#define RAMFLUX_SDK_H

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef RAMFLUX_WITH_CARD_RUNTIME
#include "ramflux_card.h"
#endif

enum RamfluxErrorCode
#ifdef __cplusplus
  : int32_t
#endif // __cplusplus
 {
  RAMFLUX_ERROR_CODE_OK = 0,
  RAMFLUX_ERROR_CODE_INVALID_ARGUMENT = 1,
  RAMFLUX_ERROR_CODE_INVALID_CANONICAL_JSON = 2,
  RAMFLUX_ERROR_CODE_UNSUPPORTED_VERSION = 3,
  RAMFLUX_ERROR_CODE_CAPABILITY_REJECTED = 4,
  RAMFLUX_ERROR_CODE_AUTH_FAILED = 5,
  RAMFLUX_ERROR_CODE_DEVICE_REVOKED = 6,
  RAMFLUX_ERROR_CODE_CRYPTO_FAILED = 7,
  RAMFLUX_ERROR_CODE_STORAGE_FAILED = 8,
  RAMFLUX_ERROR_CODE_TRANSPORT_UNAVAILABLE = 9,
  RAMFLUX_ERROR_CODE_TIMEOUT = 10,
  RAMFLUX_ERROR_CODE_REPLAY_REJECTED = 11,
  RAMFLUX_ERROR_CODE_PERMISSION_DENIED = 12,
  RAMFLUX_ERROR_CODE_MCP_GRANT_REJECTED = 13,
  RAMFLUX_ERROR_CODE_OBJECT_TRANSFER_FAILED = 14,
  RAMFLUX_ERROR_CODE_RATE_LIMITED = 15,
  RAMFLUX_ERROR_CODE_INTERNAL = 16,
  RAMFLUX_ERROR_CODE_PANIC_ABORTED = 17,
  /*
   Another process owns the account writer. Retry after the owner releases it.
   */
  RAMFLUX_ERROR_CODE_ACCOUNT_BUSY = 18,
  RAMFLUX_ERROR_CODE_OBJECT_ERASED = 19,
  RAMFLUX_ERROR_CODE_OBJECT_IDENTITY_CONFLICT = 20,
  RAMFLUX_ERROR_CODE_OBJECT_OWNERSHIP_UNVERIFIED = 21,
  RAMFLUX_ERROR_CODE_CUSTODY_FORK_FENCED = 22,
  RAMFLUX_ERROR_CODE_SCHEMA_RESET_REQUIRED = 23,
};
#ifndef __cplusplus
typedef int32_t RamfluxErrorCode;
#endif // __cplusplus

/*
 Additional v2 transport statuses. Existing `RamfluxErrorCode` values 0..23 are unchanged.
 */
enum RamfluxV2Status
#ifdef __cplusplus
  : int32_t
#endif // __cplusplus
 {
  /*
   No terminal completion or event is available. Poll again without resubmitting.
   */
  RAMFLUX_V2_STATUS_PENDING = 24,
  /*
   Cancellation won before carrier admission; no business effects occurred.
   */
  RAMFLUX_V2_STATUS_CANCELLED = 25,
  /*
   The client has closed. Admitted mutations may have effects; reconcile their keys.
   */
  RAMFLUX_V2_STATUS_CLOSED = 26,
  /*
   Event credit was exhausted. Re-read projections and reopen the subscription.
   */
  RAMFLUX_V2_STATUS_RESYNC_REQUIRED = 27,
};
#ifndef __cplusplus
typedef int32_t RamfluxV2Status;
#endif // __cplusplus

struct RamfluxClient {
  uint8_t _private[0];
};

struct RamfluxBuffer {
  unsigned char *ptr;
  size_t len;
};

struct RamfluxEventQueue {
  uint8_t _private[0];
};

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

uint32_t ramflux_sdk_abi_version_major(void);

uint32_t ramflux_sdk_abi_version_minor(void);

uint32_t ramflux_sdk_protocol_version(void);

int32_t ramflux_client_new(const unsigned char *config_json,
                           size_t config_json_len,
                           struct RamfluxClient **out_client,
                           struct RamfluxBuffer **out_error_json);

int32_t ramflux_client_close(struct RamfluxClient *client, struct RamfluxBuffer **out_error_json);

void ramflux_client_free(struct RamfluxClient *client);

void ramflux_buffer_free(struct RamfluxBuffer *buffer);

int32_t ramflux_client_event_queue_new(struct RamfluxClient *client,
                                       struct RamfluxEventQueue **out_queue,
                                       struct RamfluxBuffer **out_error_json);

int32_t ramflux_event_queue_poll(struct RamfluxEventQueue *queue,
                                 uint32_t max_events,
                                 struct RamfluxBuffer **out_events_json,
                                 struct RamfluxBuffer **out_error_json);

void ramflux_event_queue_free(struct RamfluxEventQueue *queue);

int32_t ramflux_client_negotiate_capabilities(struct RamfluxClient *client,
                                              const unsigned char *request_json,
                                              size_t request_json_len,
                                              struct RamfluxBuffer **out_decision_json,
                                              struct RamfluxBuffer **out_error_json);

int32_t ramflux_client_unlock_account(struct RamfluxClient *client,
                                      const unsigned char *request_json,
                                      size_t request_json_len,
                                      struct RamfluxBuffer **out_account_json,
                                      struct RamfluxBuffer **out_error_json);

int32_t ramflux_client_create_device_session(struct RamfluxClient *client,
                                             const unsigned char *request_json,
                                             size_t request_json_len,
                                             struct RamfluxBuffer **out_session_json,
                                             struct RamfluxBuffer **out_error_json);

int32_t ramflux_client_append_event(struct RamfluxClient *client,
                                    const unsigned char *event_json,
                                    size_t event_json_len,
                                    struct RamfluxBuffer **out_event_id_json,
                                    struct RamfluxBuffer **out_error_json);

int32_t ramflux_client_read_projection(struct RamfluxClient *client,
                                       const unsigned char *request_json,
                                       size_t request_json_len,
                                       struct RamfluxBuffer **out_projection_json,
                                       struct RamfluxBuffer **out_error_json);

int32_t ramflux_client_validate_mcp_grant(struct RamfluxClient *client,
                                          const unsigned char *request_json,
                                          size_t request_json_len,
                                          struct RamfluxBuffer **out_decision_json,
                                          struct RamfluxBuffer **out_error_json);

int32_t ramflux_client_submit_envelope(struct RamfluxClient *client,
                                       const unsigned char *envelope_json,
                                       size_t envelope_json_len,
                                       uint64_t *out_operation_id,
                                       struct RamfluxBuffer **out_error_json);

int32_t ramflux_client_put_object(struct RamfluxClient *client,
                                  const unsigned char *request_json,
                                  size_t request_json_len,
                                  uint64_t *out_operation_id,
                                  struct RamfluxBuffer **out_error_json);

/*
 Return ABI v2 metadata, descriptor fingerprint, limits and the operation inventory.
 Pass major=2 and a minimum minor supported by the host. Does not open a data root.
 */
int32_t ramflux_v2_negotiate(uint32_t major, uint32_t min_minor, struct RamfluxBuffer **out);

/*
 Open one supervisor on a dedicated thread. Config is `{data_root,builtin_nodes?}`.
 This may block during startup; invoke off the UI thread. Output is zero on failure.
 */
int32_t ramflux_v2_client_open(const uint8_t *config, size_t len, uint64_t *out_client);

/*
 Stop the supervisor and release its writer lease. Call off the UI thread.
 The first wait expires with Timeout=10; retries return Pending=24 until completion.
 Pending/failed shutdown retains the handle and completion state; only Done=0 removes it.
 */
int32_t ramflux_v2_client_close(uint64_t handle);

/*
 Release a retained failed shutdown after the host has inspected its error.
 Returns Pending=24 until the owner thread has reported a terminal outcome.
 Ordinary successful close already releases its handle; repeated release is harmless.
 */
int32_t ramflux_v2_client_release(uint64_t handle);

/*
 Submit one request, copying input before return. Returns an explicit operation/cancel handle.
 `deadline_ms` is required; `operation_id` is supplied by the caller for lifecycle reconciliation.
 */
int32_t ramflux_v2_execute(uint64_t handle,
                           const uint8_t *request,
                           size_t len,
                           uint64_t *out_operation);

/*
 Poll a completion without blocking. Returns Pending=24 with a null buffer until terminal.
 A successful poll returns JSON {code,response?}; code is a stable numeric SDK error.
 Repeated polls return the same terminal value until `operation_release`.
 */
int32_t ramflux_v2_operation_poll(uint64_t handle, uint64_t id, struct RamfluxBuffer **out);

/*
 Cancel the waiter. Before admission: completion code=25 and effects=none.
 After admission: execution/receipts remain supervisor-owned; poll/reconcile the original key.
 */
int32_t ramflux_v2_operation_cancel(uint64_t handle, uint64_t id);

/*
 Release an operation handle. An admitted operation retains bounded internal credit until terminal.
 */
int32_t ramflux_v2_operation_release(uint64_t handle, uint64_t id);

/*
 Poll one subscription event without blocking. Subscribe using execute(subscription.open/bus.subscribe).
 ResyncRequired=27 explicitly signals event overflow; terminal completions use separate credit.
 */
int32_t ramflux_v2_event_poll(uint64_t handle,
                              struct RamfluxBuffer **out);

/*
 Erase and release a v2 output buffer exactly once. Null is accepted.
 All v2 output buffers, including secret ceremony responses, must use this function.
 */
void ramflux_v2_buffer_free(struct RamfluxBuffer *buffer);

/*
 Clear the latched event gap only for the last successful subscription generation.
 Pass 0 only before the first subscription. Stale generations return InvalidArgument=1.
 Reopen bus.subscribe using the snapshot's journal cursor after this call.
 */
int32_t ramflux_v2_event_reset(uint64_t handle, uint64_t subscription_generation);

/*
 Project shared conversation rows, bounded pages and unread/attention totals without opening a client.
 Inputs are authoritative host snapshot facts; output buffers use `ramflux_v2_buffer_free`.
 */
int32_t ramflux_v2_conversation_project(const uint8_t *input_json,
                                        size_t len,
                                        struct RamfluxBuffer **out);

/*
 Present an authoritative receipt with the shared model; incoming receipts return JSON null.
 This never upgrades acceptance to delivery/read or authorizes an uncertain retry.
 */
int32_t ramflux_v2_receipt_present(const uint8_t *input_json,
                                   size_t len,
                                   struct RamfluxBuffer **out);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* RAMFLUX_SDK_H */

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

/*
 Version 1 host storage operations. References are opaque UTF-8, without a terminating NUL.
 */
enum RamfluxV2CustodyOperation
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint32_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
  RAMFLUX_V2_CUSTODY_OPERATION_PREFLIGHT = 0,
  RAMFLUX_V2_CUSTODY_OPERATION_STORE_PRIMARY = 1,
  RAMFLUX_V2_CUSTODY_OPERATION_LOAD_PRIMARY = 2,
  RAMFLUX_V2_CUSTODY_OPERATION_DELETE = 3,
  RAMFLUX_V2_CUSTODY_OPERATION_STORE_BRANCH = 4,
  RAMFLUX_V2_CUSTODY_OPERATION_LOAD_BRANCH = 5,
  RAMFLUX_V2_CUSTODY_OPERATION_STORE_PROVISIONING = 6,
  RAMFLUX_V2_CUSTODY_OPERATION_LOAD_PROVISIONING = 7,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum RamfluxV2CustodyOperation RamfluxV2CustodyOperation;
#else
typedef uint32_t RamfluxV2CustodyOperation;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/*
 Permanent numeric codes shared by every generated product adapter.
 */
enum GeneratedErrorCode
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int32_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
  GENERATED_ERROR_CODE_INVALID_ARGUMENT = 1,
  GENERATED_ERROR_CODE_INVALID_JSON = 2,
  GENERATED_ERROR_CODE_PEER_UPGRADE_REQUIRED = 3,
  GENERATED_ERROR_CODE_STORAGE_CAPACITY = 4,
  GENERATED_ERROR_CODE_SCHEMA_RESET_REQUIRED = 5,
  GENERATED_ERROR_CODE_RESYNC_REQUIRED = 6,
  GENERATED_ERROR_CODE_EDIT_CONFLICT = 7,
  GENERATED_ERROR_CODE_NOT_AUTHORIZED = 8,
  GENERATED_ERROR_CODE_TARGET_NOT_FOUND = 9,
  GENERATED_ERROR_CODE_TARGET_DELETED = 10,
  GENERATED_ERROR_CODE_PAYLOAD_TOO_LARGE = 11,
  GENERATED_ERROR_CODE_RATE_LIMITED = 12,
  GENERATED_ERROR_CODE_EPHEMERAL_UNAVAILABLE = 13,
  GENERATED_ERROR_CODE_CRYPTO_FAILURE = 14,
  GENERATED_ERROR_CODE_NOT_CONNECTED = 15,
  GENERATED_ERROR_CODE_INTERNAL = 16,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum GeneratedErrorCode GeneratedErrorCode;
#else
typedef int32_t GeneratedErrorCode;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

enum RamfluxErrorCode
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int32_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
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
  RAMFLUX_ERROR_CODE_PAIRING_REFUSED = 28,
  RAMFLUX_ERROR_CODE_PAIRING_STALE = 29,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum RamfluxErrorCode RamfluxErrorCode;
#else
typedef int32_t RamfluxErrorCode;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/*
 Additional v2 transport statuses. Existing `RamfluxErrorCode` values 0..23 are unchanged.
 */
enum RamfluxV2Status
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int32_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
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
#if __STDC_VERSION__ >= 202311L
typedef enum RamfluxV2Status RamfluxV2Status;
#else
typedef int32_t RamfluxV2Status;
#endif // __STDC_VERSION__ >= 202311L
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

/*
 One synchronous storage request. Never write beyond `output_capacity` or retain pointers.
 Store inputs are secret bytes: primary=32, branch=64, provisioning<=4096.
 Loads write the same bytes and set `output_len`; other operations return length 0.
 SDK-owned output memory is erased after use. Hosts erase their own temporary copies.
 */
struct RamfluxV2CustodyRequest {
  RamfluxV2CustodyOperation operation;
  const uint8_t *reference;
  size_t reference_len;
  const uint8_t *input;
  size_t input_len;
  uint8_t *output;
  size_t output_capacity;
  size_t output_len;
};

/*
 Trusted host provider, copied during open. All callbacks are required, thread safe and
 synchronous. They must not unwind or reenter this client. `retain` is called once on
 acceptance; `release` once after the last SDK task using the provider has finished.
 `context` is a host token (for example a JNI global-reference registry id).
 */
struct RamfluxV2CustodyProvider {
  uint32_t abi_version;
  uint64_t context;
  void (*retain)(uint64_t);
  void (*release)(uint64_t);
  /*
   Return 0 on success; 1 missing, 2 corrupt, 3 permission, 4 locked, 5 busy,
   6 unavailable. Unknown statuses fail closed. The request is borrowed for this call.
   */
  int32_t (*invoke)(uint64_t context, struct RamfluxV2CustodyRequest *request);
};

/*
 Nullable host callback; null unregisters and drains outstanding uses.
 */
typedef int32_t (*CredentialProviderCallback)(const uint8_t*,
                                              size_t,
                                              uint8_t*,
                                              size_t,
                                              size_t*,
                                              uint8_t*,
                                              size_t,
                                              size_t*,
                                              void*);

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
 Open one supervisor on a dedicated thread. Config is `{data_root,builtin_nodes?,allow_raw_messages?,allow_secret_exports?}`.
 This may block during startup; invoke off the UI thread. Output is zero on failure.
 */
int32_t ramflux_v2_client_open(const uint8_t *config,
                               size_t len,
                               uint64_t *out_client);

/*
 Open with trusted host OS credential storage (provider ABI version 1).
 The table is borrowed only during this call; retained context lives through shutdown.
 Android M4 supplies non-synchronizing Keystore wrapping; iOS may supply Keychain storage.
 */
int32_t ramflux_v2_client_open_with_custody(const uint8_t *config,
                                            size_t len,
                                            const struct RamfluxV2CustodyProvider *provider,
                                            uint64_t *out_client);

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
 Never use the v1 `ramflux_buffer_free`: it does not erase secret bytes.
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

/*
 Return the SDK-bundled public card trust package, signed descriptor and host presentation assets.
 Hosts independently pin its manifest digest and policy in their signed application release.
 The owned JSON output uses `ramflux_v2_buffer_free`; no account or renderer is opened.
 */
int32_t ramflux_v2_card_trust_package(struct RamfluxBuffer **out);

/*
 Decode and re-encode a generated message request through the shared adapter core.
 */
int32_t ramflux_message_request_adapt(const unsigned char *request_json,
                                      size_t request_json_len,
                                      struct RamfluxBuffer **out_request_json,
                                      struct RamfluxBuffer **out_error_json);

/*
 Decode and re-encode a generated message update through the shared adapter core.
 */
int32_t ramflux_message_update_adapt(const unsigned char *update_json,
                                     size_t update_json_len,
                                     struct RamfluxBuffer **out_update_json,
                                     struct RamfluxBuffer **out_error_json);

/*
 Invoke one closed pairing/transfer DTO using the configured same-user local daemon.
 Configure `pairing_socket` and, for a new target, `pairing_account_id` in client JSON.
 `out` follows existing APIs: pass writable pointer storage, free the returned allocation
 with `ramflux_buffer_free`. Inputs remain readable and the client remains live throughout.
 */
int32_t ramflux_pairing_call(struct RamfluxClient *client,
                             const char *method_name,
                             const uint8_t *body,
                             size_t body_len,
                             struct RamfluxBuffer **out);

/*
 Return one queued public display snapshot or an empty SDK buffer. No callback runs here.
 The caller owns the returned buffer and frees it with `ramflux_buffer_free`.
 */
int32_t ramflux_pairing_event_poll(struct RamfluxClient *client, struct RamfluxBuffer **out);

/*
 Install or unregister (NULL callback) the client's attended input provider.
 Host output capacities are 1024 bytes; SDK storage is zeroized on every path.
 Replacement/unregister/close waits for previous callback invocations to finish.
 The host must keep `user_data` valid until that wait returns and must not reenter
 this client from its callback; cancel its own waiting UI before closing the client.
 */
int32_t ramflux_pairing_set_credential_provider(struct RamfluxClient *client,
                                                CredentialProviderCallback callback,
                                                void *user_data);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* RAMFLUX_SDK_H */

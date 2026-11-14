/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Span Brain
 */
#ifndef RAMFLUX_PAIRING_H
#define RAMFLUX_PAIRING_H
#include "ramflux_sdk.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct RamfluxClient RamfluxClient;
typedef struct RamfluxBuffer RamfluxBuffer;

/* Additive codes; all existing codes and transport statuses 0 through 27 keep their meanings. */
#define RAMFLUX_ERR_PAIRING_REFUSED 28
#define RAMFLUX_ERR_PAIRING_STALE 29

/* Return 0 for provided input, 1 for refusal. Both output capacities are 1024.
 * Respect the capacities and write the actual lengths. Setup requires identical
 * confirmation; unlock and phrase input require a zero confirmation length.
 * The SDK owns and zeroizes these buffers. Do not retain their addresses.
 * Do not reenter this client. Keep user_data live until unregister/replacement/
 * client close returns; cancel host UI waits before requesting that drain.
 */
typedef int32_t (*RamfluxCredentialCallback)(
    const uint8_t *request_json, size_t request_len,
    uint8_t *passphrase, size_t pass_cap, size_t *pass_len,
    uint8_t *confirmation, size_t confirm_cap, size_t *confirm_len,
    void *user_data);

/* Configure pairing_socket and optional pairing_account_id in the JSON accepted
 * by ramflux_client_new. The account root must be the daemon's actual data root.
 * Each method is a device.pair.* or device.transfer.* name; body is the canonical
 * DTO JSON. No private phrase or passphrase belongs in body.
 * The existing allocated-buffer convention is used: the SDK writes *out;
 * callers release it with ramflux_buffer_free. Results are at most 18432 bytes.
 * REFUSED and STALE still write a closed LocalResult error to *out.
 * Other errors leave *out NULL. Keep the client and input memory live until return.
 */
int32_t ramflux_pairing_call(RamfluxClient *client, const char *method,
                            const uint8_t *body, size_t body_len,
                            RamfluxBuffer **out);
/* One queued LocalEvent display snapshot or an empty allocated buffer.
 * This function never asks for private input. Queues retain at most 64 snapshots.
 */
int32_t ramflux_pairing_event_poll(RamfluxClient *client, RamfluxBuffer **out);
int32_t ramflux_pairing_set_credential_provider(RamfluxClient *client,
                            RamfluxCredentialCallback callback, void *user_data);
void ramflux_buffer_free(RamfluxBuffer *buffer);

#ifdef __cplusplus
}
#endif
#endif

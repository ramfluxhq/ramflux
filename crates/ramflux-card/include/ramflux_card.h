/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef RAMFLUX_CARD_H
#define RAMFLUX_CARD_H
#define RAMFLUX_CARD_ABI_VERSION 2
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Require ramflux_card_abi_version() == RAMFLUX_CARD_ABI_VERSION before passing structures.
 * All calls are synchronous on the renderer thread that opened the handle.
 * A nonzero length requires a readable buffer. Inputs are copied during calls.
 * Callback JSON is borrowed only until the callback returns: copy before queuing
 * to a UI thread. No reentry or unwinding from callbacks. user is never retained.
 * All callbacks are required. Success emits exactly one callback; errors emit none.
 * Status: 0 OK, 1 invalid JSON/input, 2 limit (including memory/stack), 3 signature/policy, 4 script/engine, 5 budget,
 * 6 inactive, 7 stale/foreign-thread handle, 8 callback reentry/busy.
 * The host supplies a release-pinned trusted_key, never data received from a peer.
 * Descriptor and separate host-pinned policy are bounded canonical/closed JSON.
 * Serialization/output-cap failure disposes the handle; open returns out=0.
 * Only project-signed bytecode for the pinned engine is accepted. */
typedef struct RamfluxCardBytes { const uint8_t *data; size_t len; } RamfluxCardBytes;
typedef struct RamfluxCardOpen {
    RamfluxCardBytes spec;
    RamfluxCardBytes bytecode;
    RamfluxCardBytes signature;
    RamfluxCardBytes trusted_key;
    RamfluxCardBytes descriptor;
    RamfluxCardBytes policy;
} RamfluxCardOpen;
typedef void (*RamfluxCardCallback)(void *user, const uint8_t *json, size_t len);
uint32_t ramflux_card_abi_version(void);
int32_t ramflux_card_open(const RamfluxCardOpen *input, RamfluxCardCallback callback, void *user, uint64_t *out);
int32_t ramflux_card_update(uint64_t session, RamfluxCardBytes input, RamfluxCardCallback callback, void *user);
int32_t ramflux_card_event(uint64_t session, RamfluxCardBytes input, RamfluxCardCallback callback, void *user);
int32_t ramflux_card_suspend(uint64_t session, RamfluxCardCallback callback, void *user);
int32_t ramflux_card_resume(uint64_t session, RamfluxCardCallback callback, void *user);
int32_t ramflux_card_dispose(uint64_t session);
#ifdef __cplusplus
}
#endif
#endif

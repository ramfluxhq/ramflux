// SPDX-License-Identifier: BSD-3-Clause
// The pinned QuickJS WASM shim's sole C import: epoch microseconds for its clock.
// This runs in the trusted worker glue; it is never installed as a script global.
export function __rquickjs_host_now_us():number {
  return (performance.timeOrigin + performance.now()) * 1000;
}

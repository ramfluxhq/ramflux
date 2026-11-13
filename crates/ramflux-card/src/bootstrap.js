// SPDX-License-Identifier: BSD-3-Clause
// Host-owned bootstrap. Compiled by the pinned build engine, never peer code.
const getDescriptor = Object.getOwnPropertyDescriptor;
const getPrototype = Object.getPrototypeOf;
const ownKeys = Reflect.ownKeys;
const freeze = Object.freeze;
const frozen = Object.isFrozen;
const define = Object.defineProperty;
const global = globalThis;
function classify(error) {
  if ((typeof error !== "object" || error === null) && typeof error !== "function") return "script";
  const descriptor = getDescriptor(error, "message");
  const message = descriptor && descriptor.value;
  if (message === "out of memory") return "memory";
  if (message === "Maximum call stack size exceeded") return "stack";
  return "script";
}
define(global, "__rf_error_kind", { value: classify, configurable: false, writable: false });
const seen = [];
function harden(value) {
  if (value === null || (typeof value !== "object" && typeof value !== "function") || seen.indexOf(value) !== -1) return;
  seen.push(value);
  harden(getPrototype(value));
  for (const key of ownKeys(value)) {
    const descriptor = getDescriptor(value, key);
    if (descriptor) { harden(descriptor.value); harden(descriptor.get); harden(descriptor.set); }
  }
  freeze(value);
  if (!frozen(value)) throw new Error("intrinsic hardening failed");
}
// These constructors/prototypes need not be global bindings.
harden(function () {});
harden(async function () {});
harden(function* () {});
harden(async function* () {});
harden(global);

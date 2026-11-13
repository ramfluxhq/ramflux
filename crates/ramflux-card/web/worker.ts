// SPDX-License-Identifier: BSD-3-Clause
// App-owned worker entry. release.js is generated offline from public release artifacts.
import init, { CardWorker } from "./pkg.js";
import release from "./release.js";
const ready = init({module_or_path:new URL("./pkg/ramflux_card_bg.wasm",import.meta.url)});
let connected = false;
self.addEventListener("message", async (event: MessageEvent) => {
  if (connected || !(event.data?.port instanceof MessagePort)) return;
  connected = true;
  const port: MessagePort = event.data.port;
  try {
    await ready;
    const runtime = new CardWorker(new Uint8Array(release.bytecode), new Uint8Array(release.descriptor),
      new Uint8Array(release.signature), new Uint8Array(release.publicKey), release.policy,JSON.stringify(event.data.presentation));
    port.onmessage = (request: MessageEvent) => {
      const {seq, op, json} = (request.data ?? {}) as {seq?:unknown;op?:unknown;json?:unknown};
      if (typeof seq!=="number" || !Number.isSafeInteger(seq) || seq < 0) return;
      let terminal=false;const wasActive=runtime.is_active();
      try {
        let response: string;
        switch (op) {
          case "open": case "update": case "event": case "present":
            if (typeof json !== "string" || json.length > 16384) throw Error("transport bound");
            response = runtime[op](json); break;
          case "suspend": response = runtime.suspend(); break;
          case "resume": response = runtime.resume(); break;
          case "dispose": runtime.dispose(); port.postMessage({seq, disposed:true}); port.close(); return;
          default: throw Error("unknown card operation");
        }
        if (response.length > 131072) {terminal=true;runtime.dispose();throw Error("output bound");}
        port.postMessage({seq, json:response});
      } catch(error) { port.postMessage({seq, error:"content_unavailable",terminal:terminal || error instanceof WebAssembly.RuntimeError || (wasActive&&!runtime.is_active())}); }
    };
    port.start(); port.postMessage({ready:true});
  } catch { port.postMessage({error:"runtime_unavailable"}); port.close(); }
}, {once:true});

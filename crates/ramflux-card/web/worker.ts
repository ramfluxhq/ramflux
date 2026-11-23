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
      const {seq, op, json, model} = (request.data ?? {}) as {seq?:unknown;op?:unknown;json?:unknown;model?:unknown};
      if (typeof seq!=="number" || !Number.isSafeInteger(seq) || seq < 0) return;
      let terminal=false;const wasActive=runtime.is_active();
      try {
        let response: string;
        switch (op) {
          case "open_preview":
            if(typeof json!=="string"||typeof model!=="string"||[json,model].some(value=>new TextEncoder().encode(value).length>32768))throw Error("transport bound");
            response=runtime.open_preview(json,model);break;
          case "open": case "update": case "event": case "present":
            if (typeof json !== "string" || new TextEncoder().encode(json).length > 32768) throw Error("transport bound");
            response = runtime[op](json); break;
          case "tree": response = runtime.tree(); break;
          case "suspend": response = runtime.suspend(); break;
          case "resume": response = runtime.resume(); break;
          case "dispose": runtime.dispose(); port.postMessage({seq, disposed:true}); port.close(); return;
          default: throw Error("unknown card operation");
        }
        if (new TextEncoder().encode(response).length > 263168) {terminal=true;runtime.dispose();throw Error("output bound");}
        port.postMessage({seq, json:response});
      } catch(error) {
        let refusal:unknown;
        if(typeof error==="string" && error.length<=8192){try{const parsed=JSON.parse(error);if(["protocol","limit","invalid_input","runtime"].includes(parsed.type))refusal=parsed}catch{}}
        port.postMessage({seq, refusal, error:"content_unavailable",terminal:terminal || error instanceof WebAssembly.RuntimeError || (wasActive&&!runtime.is_active())}); }
    };
    port.start(); port.postMessage({ready:true});
  } catch { port.postMessage({error:"runtime_unavailable"}); port.close(); }
}, {once:true});

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Dedicated worker of the leader page. It is the only context that loads the WASM core, and
// therefore the only one that can open OPFS or the gateway WebSocket.
//
// The page talks to it with a transferred MessagePort. This file contains no protocol logic:
// admission, the leader state machine and every wire rule live in the core.

import init, { WebCore } from "../pkg/ramflux_web.js";

interface Boot {
  t: "boot";
  build: string;
}
interface Attach {
  t: "attach";
}
interface Visibility {
  t: "visibility";
  visible: boolean;
}
interface Shutdown {
  t: "shutdown";
}
type PageMessage = Boot | Attach | Visibility | Shutdown;

const scope = self as unknown as DedicatedWorkerGlobalScope;
let core: WebCore | undefined;
const pending: MessageEvent[] = [];

async function boot(build: string): Promise<void> {
  await init();
  core = new WebCore(build);
  core.subscribe((update: Uint8Array) => {
    // Leader progress goes to the owning page only. Updates for attached pages travel on
    // their own ports, under credit, from inside the core.
    scope.postMessage({ t: "update", bytes: update }, [update.buffer]);
  });
  core.start();
  for (const event of pending.splice(0)) {
    handle(event);
  }
}

function handle(event: MessageEvent): void {
  const message = event.data as PageMessage;
  if (core === undefined) {
    if (message.t === "boot") {
      void boot(message.build);
    } else {
      pending.push(event);
    }
    return;
  }
  switch (message.t) {
    case "attach": {
      const port = event.ports[0];
      if (port !== undefined) {
        // The core refuses a port whose delivering event has a foreign origin.
        try {
          core.attach_port(port, event.origin);
        } catch {
          port.close();
        }
      }
      break;
    }
    case "visibility":
      core.set_visible(message.visible);
      break;
    case "shutdown":
      core.report("shutdown");
      break;
    default:
      break;
  }
}

scope.onmessage = handle;

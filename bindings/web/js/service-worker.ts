// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Service worker of the node-hosted web app. It does exactly two things:
//   1. shows a generic notification for a push and posts a wake to open windows;
//   2. carries one MessagePort between a follower page and the leader page (rendezvous).
// It never loads the WASM core, opens the store, holds credentials, decrypts, fetches, or
// carries a CORE-API payload. It has no `fetch` handler, so it cannot serve application code
// from a cache.

const scope = self as unknown as ServiceWorkerGlobalScope;
const APP_PATH = "/";
const NOTIFICATION_TAG = "ramflux-new";
const NOTIFICATION_TEXT = "New message";
const RENDEZVOUS_TTL_MS = 10000;

interface Rendezvous {
  follower: string;
  nonce: string;
  build: string;
  expires: number;
}

// Transient state only. Losing it on a service-worker restart delays an attachment; it can
// never create a second core, because pages create the core only under the writer lock.
let leaderClient: string | undefined;
const waiting = new Map<string, Rendezvous>();

function sameOriginApp(client: Client): boolean {
  const url = new URL(client.url);
  return url.origin === scope.location.origin && url.pathname.startsWith(APP_PATH);
}

scope.addEventListener("install", () => {
  void scope.skipWaiting();
});

scope.addEventListener("activate", (event: ExtendableEvent) => {
  event.waitUntil(scope.clients.claim());
});

scope.addEventListener("message", (event: ExtendableMessageEvent) => {
  const source = event.source;
  if (!(source instanceof Client) || !sameOriginApp(source)) {
    return;
  }
  const data = event.data as { t?: string; nonce?: string; build?: string; client?: string };
  const now = Date.now();
  for (const [key, entry] of waiting) {
    if (entry.expires < now) {
      waiting.delete(key);
    }
  }
  if (data.t === "rendezvous_leader") {
    leaderClient = source.id;
    return;
  }
  if (data.t === "rendezvous_request" && typeof data.nonce === "string" && typeof data.build === "string") {
    waiting.set(data.nonce, { follower: source.id, nonce: data.nonce, build: data.build, expires: now + RENDEZVOUS_TTL_MS });
    event.waitUntil(offer(data.nonce, data.build, source.id));
    return;
  }
  if (data.t === "rendezvous_port" && typeof data.nonce === "string") {
    const entry = waiting.get(data.nonce);
    const port = event.ports[0];
    waiting.delete(data.nonce);
    // Both ends are checked: the offer must come from the registered leader, and the port
    // goes only to the client that asked with this nonce.
    if (entry === undefined || port === undefined || source.id !== leaderClient) {
      return;
    }
    event.waitUntil(deliver(entry, port));
  }
});

async function offer(nonce: string, build: string, follower: string): Promise<void> {
  if (leaderClient === undefined) {
    return;
  }
  const leader = await scope.clients.get(leaderClient);
  if (leader === undefined || !sameOriginApp(leader)) {
    leaderClient = undefined;
    return;
  }
  leader.postMessage({ t: "rendezvous_offer", nonce, build, client: follower });
}

async function deliver(entry: Rendezvous, port: MessagePort): Promise<void> {
  const follower = await scope.clients.get(entry.follower);
  if (follower === undefined || !sameOriginApp(follower)) {
    port.close();
    return;
  }
  follower.postMessage({ t: "rendezvous_port", nonce: entry.nonce }, [port]);
}

scope.addEventListener("push", (event: PushEvent) => {
  event.waitUntil(onPush(event));
});

async function onPush(event: PushEvent): Promise<void> {
  // Only the three documented fields are read; anything else is ignored.
  let wakeId: string | undefined;
  try {
    const body = event.data?.json() as { v?: unknown; wake_id?: unknown; class?: unknown } | undefined;
    if (body !== undefined && body.v === 1 && typeof body.wake_id === "string" && body.class === "message") {
      wakeId = body.wake_id;
    }
  } catch {
    wakeId = undefined;
  }
  const windows = await scope.clients.matchAll({ type: "window", includeUncontrolled: false });
  let focused = false;
  for (const client of windows) {
    if (!sameOriginApp(client)) {
      continue;
    }
    if (wakeId !== undefined) {
      client.postMessage({ type: "wake", wake_id: wakeId });
    }
    focused = focused || (client.visibilityState === "visible" && client.focused);
  }
  if (!focused) {
    // Generic text, fixed tag: no sender, no preview, and repeats replace each other.
    await scope.registration.showNotification(NOTIFICATION_TEXT, { tag: NOTIFICATION_TAG });
  }
}

scope.addEventListener("notificationclick", (event: NotificationEvent) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const windows = await scope.clients.matchAll({ type: "window" });
      const existing = windows.find(sameOriginApp);
      if (existing !== undefined) {
        await existing.focus();
      } else {
        await scope.clients.openWindow(APP_PATH);
      }
    })(),
  );
});

scope.addEventListener("pushsubscriptionchange", (event: Event) => {
  // The service worker has no credentials. It only tells open pages; the leader re-registers
  // the route on its next authenticated session.
  (event as ExtendableEvent).waitUntil(
    (async () => {
      const windows = await scope.clients.matchAll({ type: "window" });
      for (const client of windows) {
        client.postMessage({ type: "push_subscription_changed" });
      }
    })(),
  );
});

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Page side of the web client. A page never loads the WASM core. It either owns the dedicated
// worker (leader page) or holds a MessagePort to the leader's worker (follower page), obtained
// through the service-worker rendezvous. Requests, replies, updates and credit travel on that
// port only.

export const WRITER_LOCK = "ramflux.writer.v1";
export const PRESENCE_CHANNEL = "ramflux.presence.v1";
const LEADER_PING_TIMEOUT_MS = 5000;
const UPDATE_CREDIT_BATCH = 64;

/** The only shape the presence channel carries: no user data, no identifiers, no ports. */
export interface Presence {
  t: "leader" | "hello" | "bye";
  tab: string;
  visible: boolean;
  build: string;
}

export type ClientState = "starting" | "leader" | "follower" | "leader_unavailable" | "reload_required";

export interface ClientOptions {
  /** Release id of this build. A tab from another build does not attach. */
  build: string;
  /** URL of the compiled worker script, same origin. */
  workerUrl: URL;
  onUpdate(frame: Uint8Array): void;
  onState(state: ClientState): void;
}

interface Waiter {
  resolve(frame: Uint8Array): void;
  reject(error: Error): void;
}

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function requestId(frame: Uint8Array): string {
  // The carrier does not parse bodies; the page reads only the routing field of its own frames.
  const parsed = JSON.parse(new TextDecoder().decode(frame)) as { request_id?: unknown };
  if (typeof parsed.request_id !== "string" || parsed.request_id.length === 0) {
    throw new Error("frame has no request_id");
  }
  return parsed.request_id;
}

export class RamfluxWebClient {
  private readonly tab = randomId();
  private readonly presence = new BroadcastChannel(PRESENCE_CHANNEL);
  private readonly waiters = new Map<string, Waiter>();
  private worker: Worker | undefined;
  private port: MessagePort | undefined;
  private updatesSinceCredit = 0;
  private pingTimer: ReturnType<typeof setTimeout> | undefined;
  private nextPing = 1;
  private leading = false;

  constructor(private readonly options: ClientOptions) {
    this.presence.onmessage = (event: MessageEvent<Presence>) => this.onPresence(event.data);
    document.addEventListener("visibilitychange", () => this.onVisibility());
    addEventListener("pagehide", () => this.announce("bye"));
  }

  /** Start as leader when no leader exists, otherwise attach to the leader as a follower. */
  async start(): Promise<void> {
    this.options.onState("starting");
    const free = await navigator.locks.request(
      WRITER_LOCK,
      { mode: "exclusive", ifAvailable: true },
      (lock) => lock !== null,
    );
    // Every page queues its own worker for the writer lock with an ordinary request, so a
    // successor exists when the leader goes away. Until that worker holds the lock and has
    // opened the store, this page is a follower of the current leader, if there is one.
    this.startWorker();
    if (!free) {
      await this.attachAsFollower();
    }
  }

  /**
   * Ask the user agent to keep this origin's storage. Must run in the page after linking (a
   * user gesture): `StorageManager.persist()` does not exist in workers. A refusal is normal;
   * the caller shows it and never treats it as an error.
   */
  async requestPersistence(): Promise<boolean> {
    if (navigator.storage === undefined || navigator.storage.persist === undefined) {
      return false;
    }
    return navigator.storage.persist();
  }

  /** One request frame in, one response or error frame out. */
  execute(frame: Uint8Array): Promise<Uint8Array> {
    const port = this.port;
    if (port === undefined) {
      return Promise.reject(new Error("leader unavailable"));
    }
    const id = requestId(frame);
    return new Promise<Uint8Array>((resolve, reject) => {
      this.waiters.set(id, { resolve, reject });
      const body = frame.slice().buffer;
      port.postMessage(body, [body]);
    });
  }

  private startWorker(): void {
    // The worker queues for the lock with an ordinary request; it never steals.
    const worker = new Worker(this.options.workerUrl, { type: "module", name: "ramflux-core" });
    this.worker = worker;
    worker.onmessage = (event: MessageEvent) => {
      const data = event.data as { t?: string; bytes?: Uint8Array };
      if (data.t !== "update" || data.bytes === undefined) {
        return;
      }
      const update = JSON.parse(new TextDecoder().decode(data.bytes)) as { t?: string; action?: string };
      // The worker leads only once the lock is held and the store is open.
      if (update.t === "leader_action" && update.action === "OpenGatewaySession" && !this.leading) {
        this.leading = true;
        clearTimeout(this.pingTimer);
        this.port?.close();
        this.openPort((port) => worker.postMessage({ t: "attach" }, [port]));
        this.options.onState("leader");
        this.announce("leader");
        void this.offerPortsToFollowers();
      } else if (update.t === "leader_action" && update.action === "ReleaseLock" && this.leading) {
        this.leading = false;
        this.failAll("leader handed over");
        void this.attachAsFollower();
      }
    };
    worker.postMessage({ t: "boot", build: this.options.build });
  }

  private openPort(send: (remote: MessagePort) => void): void {
    const channel = new MessageChannel();
    this.port = channel.port1;
    channel.port1.onmessage = (event: MessageEvent) => this.onPortMessage(event);
    send(channel.port2);
  }

  /** Follower: ask the service worker to carry one port from the leader page. Port only. */
  private async attachAsFollower(): Promise<void> {
    const registration = await navigator.serviceWorker.ready;
    const controller = registration.active;
    if (controller === null) {
      // Without a controller the follower waits. It never creates another core.
      this.options.onState("leader_unavailable");
      return;
    }
    const nonce = randomId();
    navigator.serviceWorker.addEventListener("message", (event: MessageEvent) => {
      const data = event.data as { t?: string; nonce?: string };
      const port = event.ports[0];
      if (event.origin !== location.origin || data.t !== "rendezvous_port" || data.nonce !== nonce || port === undefined) {
        return;
      }
      this.port = port;
      port.onmessage = (inner: MessageEvent) => this.onPortMessage(inner);
      this.options.onState("follower");
      this.schedulePing();
    });
    controller.postMessage({ t: "rendezvous_request", nonce, build: this.options.build });
    this.announce("hello");
  }

  /** Leader page: hand a fresh port to each follower the service worker names. */
  private async offerPortsToFollowers(): Promise<void> {
    navigator.serviceWorker.addEventListener("message", (event: MessageEvent) => {
      const data = event.data as { t?: string; nonce?: string; client?: string; build?: string };
      if (event.origin !== location.origin || data.t !== "rendezvous_offer" || this.worker === undefined || !this.leading) {
        return;
      }
      if (data.build !== this.options.build) {
        return;
      }
      const channel = new MessageChannel();
      this.worker.postMessage({ t: "attach" }, [channel.port1]);
      event.source?.postMessage({ t: "rendezvous_port", nonce: data.nonce, client: data.client }, [channel.port2]);
    });
    const registration = await navigator.serviceWorker.ready;
    registration.active?.postMessage({ t: "rendezvous_leader", build: this.options.build });
  }

  private onPortMessage(event: MessageEvent): void {
    const data: unknown = event.data;
    if (data instanceof ArrayBuffer) {
      this.onFrame(new Uint8Array(data));
      return;
    }
    const control = data as { t?: string; id?: number };
    if (control.t === "pong") {
      this.schedulePing();
    } else if (control.t === "draining") {
      this.failAll("leader is handing over");
    }
  }

  private onFrame(frame: Uint8Array): void {
    const parsed = JSON.parse(new TextDecoder().decode(frame)) as { kind?: string; request_id?: string };
    const waiter = parsed.request_id === undefined ? undefined : this.waiters.get(parsed.request_id);
    if ((parsed.kind === "response" || parsed.kind === "error") && waiter !== undefined) {
      this.waiters.delete(parsed.request_id as string);
      waiter.resolve(frame);
      return;
    }
    this.options.onUpdate(frame);
    this.updatesSinceCredit += 1;
    if (this.updatesSinceCredit >= UPDATE_CREDIT_BATCH) {
      this.port?.postMessage({ t: "credit", updates: this.updatesSinceCredit });
      this.updatesSinceCredit = 0;
    }
  }

  /** A five-second unanswered ping reports an unavailable leader. It authorizes nothing else. */
  private schedulePing(): void {
    clearTimeout(this.pingTimer);
    this.port?.postMessage({ t: "ping", id: this.nextPing++ });
    this.pingTimer = setTimeout(() => {
      this.options.onState("leader_unavailable");
      this.failAll("leader unavailable");
    }, LEADER_PING_TIMEOUT_MS);
  }

  private failAll(reason: string): void {
    for (const waiter of this.waiters.values()) {
      waiter.reject(new Error(reason));
    }
    this.waiters.clear();
  }

  private onVisibility(): void {
    const visible = document.visibilityState === "visible";
    this.worker?.postMessage({ t: "visibility", visible });
    this.port?.postMessage({ t: "visibility", visible });
    this.announce(this.leading ? "leader" : "hello");
  }

  private onPresence(message: Presence): void {
    if (message.build !== this.options.build && message.t === "leader") {
      this.options.onState("reload_required");
    }
  }

  private announce(kind: Presence["t"]): void {
    const message: Presence = {
      t: kind,
      tab: this.tab,
      visible: document.visibilityState === "visible",
      build: this.options.build,
    };
    this.presence.postMessage(message);
  }
}

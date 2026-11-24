// SPDX-License-Identifier: BSD-3-Clause
import type { HostPresentation, Strings } from "./settings";
import { CardFrame } from "./card/frame";
import type { CardNode, RenderOptions } from "./card/types";
// A fixed DOM mutation adapter. Rust in the dedicated worker owns card validation.
export type Token = {
    session: number;
    signedVersion: number;
    editSeq: number;
    treeVersion: number;
    key: string;
};
export type HostSlot = {
    id: string;
    kind: "approval" | "modal" | "link_open" | "image";
    key: string;
    token: Token;
    [field: string]: unknown;
};
type Node = CardNode;
type Mutation = {
    op: "remove";
    key: string;
} | {
    op: "upsert";
    parent: string | null;
    index: number;
    node: Node;
};
type Batch = {
    schema: string;
    session: number;
    previous_version: number;
    version: number;
    signed_version: number;
    signed_hash: string;
    edit_seq: number;
    mutations: Mutation[];
    host_slots: HostSlot[];
    lifecycle?: string;
    generating?: boolean;
};
type Reply = {
    session: number;
    version: number;
    value: Batch | {
        result: string;
        batch?: Batch;
        action?: unknown;
    } | null;
};
type Edit = {
    key: string;
    version: number;
};
type Pending = {
    op: string;
    edit?: Edit;
    presentation?: HostPresentation;
    resolve: (value: Reply | null) => void;
    reject: (reason: Error) => void;
};
// Each WASM instance has its own Rust resident counter. Bound worker instances
// at the app adapter too, so separate heaps cannot bypass the two-VM policy.
let workers = 0;
let workerPolicy: {
    createScriptURL: (value: string) => unknown;
} | undefined;
function createWorker(url: URL, strings: Strings): Worker {
    const expected = new URL("./worker.js", import.meta.url).href;
    if (url.href !== expected)
        throw Error(strings.runtime_unavailable);
    const trusted = (globalThis as typeof globalThis & {
        trustedTypes?: {
            createPolicy: (name: string, rules: {
                createScriptURL: (value: string) => string;
            }) => {
                createScriptURL: (value: string) => unknown;
            };
        };
    }).trustedTypes;
    if (trusted && !workerPolicy)
        workerPolicy = trusted.createPolicy("rf-card-worker", { createScriptURL: value => { if (value !== expected)
                throw Error(strings.runtime_unavailable); return value; } });
    const source = workerPolicy ? workerPolicy.createScriptURL(expected) as URL : url;
    if (workers >= 2)
        throw Error(strings.capacity);
    const worker = new Worker(source, { type: "module", name: "card-renderer" });
    workers++;
    return worker;
}
export class CardView {
    private readonly worker: Worker;
    private readonly frame: CardFrame;
    private currentSlots: HostSlot[] = [];
    private flags: {
        lifecycle?: string;
        generating?: boolean;
    } = {};
    private readonly port: MessagePort;
    private readonly nodes = new Map<string, HTMLElement>();
    private readonly pending = new Map<number, Pending>();
    private readonly displayed = new Map<string, Node>();
    private sequence = 0;
    private session = 0;
    private version = 0;
    private mountedSession = 0;
    private signedVersion = 0;
    private editSeq = 0;
    private readonly editQueue = new Map<string, {
        kind: string;
        value?: unknown;
        index?: number;
    }>();
    private editing = false;
    private disposed = false;
    private released = false;
    private readonly ready: Promise<void>;
    private rejectReady: (reason: Error) => void = () => { };
    constructor(private readonly root: HTMLElement, workerURL: URL, private readonly intent: (action: unknown, fields?: unknown) => void, private readonly hostSlots: (slots: readonly HostSlot[]) => void, private readonly failure: (message: string) => void, private presentation: HostPresentation, private readonly observe?: (entry: {
        op: string;
        request?: unknown;
        reply?: unknown;
        refusal?: unknown;
    }) => void) {
        if (this.root.childElementCount)
            throw Error(this.ui("root_not_empty"));
        this.worker = createWorker(workerURL, presentation.strings);
        this.root.inert = false;
        this.frame = new CardFrame(root);
        const channel = new MessageChannel();
        this.port = channel.port1;
        this.ready = new Promise((resolve, reject) => {
            this.rejectReady = reject;
            this.port.onmessage = event => {
                if (event.data?.ready) {
                    resolve();
                    return;
                }
                if (event.data?.seq === undefined) {
                    const error = Error(this.ui("runtime_unavailable"));
                    reject(error);
                    this.abort(error);
                    return;
                }
                this.receive(event.data);
            };
            this.worker.onerror = () => { const error = Error(this.ui("runtime_unavailable")); reject(error); this.abort(error); };
        });
        void this.ready.catch(() => undefined);
        this.worker.postMessage({ port: channel.port2, presentation }, [channel.port2]);
        this.port.start();
    }
    configure(options: RenderOptions): void {
        const active=document.activeElement as HTMLInputElement|null,key=active?.dataset.controlKey;
        const start=active?.selectionStart,end=active?.selectionEnd;
        this.frame.configure(options);
        if(this.displayed.size)this.redraw();
        if(key){
            const control=Array.from(this.root.querySelectorAll<HTMLInputElement>('[data-control-key]')).find(e=>e.dataset.controlKey===key);
            const dialog=this.root.querySelector('[role=dialog]');
            if(control&&(!dialog||dialog.contains(control))){control.focus();if(control.type==='text'&&start!=null&&end!=null)control.setSelectionRange(start,end)}
        }
    }
    send(token: Token, event: {
        kind: string;
        value?: unknown;
        index?: number;
    }): Promise<Reply | null> { return this.request("event", JSON.stringify({ token, event }), { key: token.key, version: token.treeVersion }); }
    private redraw(): void { this.frame.render(this.displayed, this.presentation, this.currentSlots, (key, event) => this.event(key, event), this.flags); this.nodes.clear(); for (const element of this.root.querySelectorAll<HTMLElement>("[data-card-key]"))
        this.nodes.set(element.dataset.cardKey ?? "", element); }
    private ui(key: keyof Strings): string { return this.presentation.strings[key]; }
    present(presentation: HostPresentation): Promise<Reply | null> { return this.request("present", JSON.stringify(presentation), undefined, presentation); }
    preview(input: string, model: string): Promise<Reply | null> { return this.request("open_preview", input, undefined, undefined, model); }
    tree(): Promise<Reply | null> { return this.request("tree"); }
    open(selectedJSON: string): Promise<Reply | null> { return this.request("open", selectedJSON); }
    update(selectedJSON: string): Promise<Reply | null> { return this.request("update", selectedJSON); }
    suspend(): Promise<Reply | null> { return this.request("suspend"); }
    resume(): Promise<Reply | null> { return this.request("resume"); }
    dispose(): void {
        if (this.disposed)
            return;
        this.disposed = true;
        this.abort(Error(this.ui("disposed")), false);
        this.port.close();
        this.releaseWorker();
        this.frame.dispose();
        this.nodes.clear();
        this.displayed.clear();
        this.root.replaceChildren();
        this.hostSlots([]);
    }
    private releaseWorker(): void {
        if (this.released)
            return;
        this.released = true;
        this.worker.terminate();
        workers--;
    }
    private abort(error: Error, notify = true): void {
        this.rejectReady(error);
        for (const pending of this.pending.values())
            pending.reject(error);
        this.pending.clear();
        if (notify) {
            this.port.close();
            this.releaseWorker();
            this.root.inert = true;
            this.hostSlots([]);
            this.failure(error.message);
        }
    }
    private async request(op: string, json?: string, edit?: Edit, presentation?: HostPresentation, model?: string): Promise<Reply | null> {
        if (this.disposed || this.released)
            throw Error(this.ui("disposed"));
        if (json !== undefined && (typeof json !== "string" || new TextEncoder().encode(json).length > 32768))
            throw Error(this.ui("input_bound"));
        if (this.pending.size >= 32)
            throw Error(this.ui("busy"));
        // Reserve before awaiting readiness so the pre-init queue is bounded too.
        const seq = ++this.sequence;
        const response = new Promise<Reply | null>((resolve, reject) => this.pending.set(seq, { op, resolve, reject, edit, presentation }));
        this.refreshButtons();
        try {
            await this.ready;
            if (this.disposed)
                throw Error(this.ui("disposed"));
            this.observe?.({ op, request: op === "event" && json !== undefined ? JSON.parse(json) : json });
            this.port.postMessage({ seq, op, json, model });
        }
        catch (error) {
            this.pending.get(seq)?.reject(error instanceof Error ? error : Error(this.ui("runtime_unavailable")));
            this.pending.delete(seq);
        }
        return response;
    }
    private receive(message: {
        seq: number;
        json?: string;
        error?: string;
        terminal?: boolean;
        disposed?: boolean;
        refusal?: unknown;
    }): void {
        const pending = this.pending.get(message.seq);
        if (!pending)
            return;
        this.pending.delete(message.seq);
        if (message.error) {
            this.observe?.({ op: "refused", refusal: message.refusal });
            const failure = Error(this.ui(message.error === "runtime_unavailable" ? "runtime_unavailable" : "content_unavailable"));
            pending.reject(failure);
            if (message.terminal)
                this.abort(failure);
            this.refreshButtons();
            return;
        }
        try {
            if (message.disposed) {
                pending.resolve(null);
                return;
            }
            if (typeof message.json !== "string" || new TextEncoder().encode(message.json).length > 263168)
                throw Error(this.ui("output_unavailable"));
            const reply = JSON.parse(message.json) as Reply;
            this.observe?.({ op: pending.op, reply });
            if (pending.presentation)
                this.presentation = pending.presentation;
            this.session = reply.session;
            const value = reply.value;
            if (value && "mutations" in value)
                this.apply(value);
            else if (value && "batch" in value && value.batch) {
                this.apply(value.batch);
                if (value.result === "submit" && value.action)
                    this.intent(value.action);
            }
            if (value && "result" in value && value.result === "stale_dropped" && pending.edit) {
                this.reconcile(pending.edit.key);
                this.localError(pending.edit.key, this.ui("stale_edit"));
                this.failure(this.ui("stale_edit"));
            }
            this.refreshButtons();
            pending.resolve(reply);
        }
        catch (error) {
            const failure = error instanceof Error ? error : Error(this.ui("output_unavailable"));
            pending.reject(failure);
            this.abort(failure);
        }
    }
    private editsPending(): boolean { return [...this.pending.values()].some(pending => pending.edit !== undefined); }
    private refreshButtons(): void {
        for (const [key, node] of this.displayed)
            if (node.kind === "Button") {
                const element = this.nodes.get(key);
                const button = element?.tagName === "BUTTON" ? element as HTMLButtonElement : element?.querySelector("button");
                if (button)
                    button.disabled = !!node.attrs.disabled || this.editsPending() || ["busy", "consumed", "closed", "expired", "superseded", "streaming"].includes(this.root.dataset.lifecycle ?? "") || !!this.flags.generating || !!this.flags.lifecycle && this.flags.lifecycle !== "open";
            }
    }
    private reconcile(key: string): void { const element = this.nodes.get(key), shown = this.displayed.get(key); if (element && shown)
        this.redraw(); }
    private localError(key: string, message: string): void {
        const node = this.displayed.get(key);
        if (node) {
            node.attrs.errors = [message];
            this.frame.touch(key);
        }
    }
    private event(key: string, event: {
        kind: string;
        value?: unknown;
        index?: number;
    }): void {
        if (event.kind !== "activate") {
            this.editQueue.set(key, event);
            this.pumpEdits();
            return;
        }
        if (this.editing || this.editQueue.size || this.editsPending()) {
            this.failure(this.ui("busy"));
            return;
        }
        void this.request("event", JSON.stringify({ token: this.token(key), event })).catch(error => this.failure(String(error)));
    }
    private token(key: string): Token { return { session: this.session, signedVersion: this.signedVersion, editSeq: this.editSeq, treeVersion: this.version, key }; }
    private pumpEdits(): void {
        if (this.editing || this.disposed || this.released)
            return;
        const next = this.editQueue.entries().next().value;
        if (!next)
            return;
        const [key, event] = next;
        this.editQueue.delete(key);
        this.editing = true;
        void this.request("event", JSON.stringify({ token: this.token(key), event }), { key, version: this.version })
            .catch(error => { this.reconcile(key); this.failure(String(error)); })
            .finally(() => { this.editing = false; this.refreshButtons(); this.pumpEdits(); });
    }
    private apply(batch: Batch): void {
        const reset = batch.previous_version === 0 && batch.session !== this.mountedSession;
        if (batch.schema !== "ramflux.card.mutations.v1" || (!reset && (batch.session !== this.mountedSession || batch.previous_version !== this.version)))
            throw Error(this.ui("resync"));
        const next = new Map<string, Node>();
        if (!reset)
            for (const [key, node] of this.displayed)
                next.set(key, { ...node, children: [...node.children] });
        // Stage the complete batch and edges before modifying mounted DOM or callbacks.
        for (const mutation of batch.mutations) {
            const key = mutation.op === "remove" ? mutation.key : mutation.node.key;
            for (const node of next.values())
                node.children = node.children.filter(child => child !== key);
            if (mutation.op === "remove") {
                next.delete(key);
                continue;
            }
            const existing = next.get(key), node = { ...mutation.node, children: existing?.children ?? [] };
            next.set(key, node);
            if (mutation.parent !== null) {
                const parent = next.get(mutation.parent);
                if (!parent || mutation.index > parent.children.length)
                    throw Error(this.ui("parent_unavailable"));
                parent.children.splice(mutation.index, 0, key);
            }
        }
        for (const node of next.values())
            if (node.children.some(key => !next.has(key)))
                throw Error(this.ui("parent_unavailable"));
        const active = document.activeElement as HTMLInputElement | null, focused = active?.dataset.controlKey;
        const start = active?.selectionStart, end = active?.selectionEnd, typed = active?.value;
        const wasTab = active?.getAttribute('role') === 'tab';
        this.displayed.clear();
        for (const [key, node] of next)
            this.displayed.set(key, node);
        if (batch.session === this.mountedSession && batch.signed_version > this.signedVersion)
            this.frame.configure({ state: undefined });
        this.version = batch.version;
        this.mountedSession = batch.session;
        this.signedVersion = batch.signed_version;
        this.editSeq = batch.edit_seq;
        this.currentSlots = batch.host_slots;
        this.flags = { lifecycle: batch.lifecycle, generating: batch.generating };
        this.redraw();
        if (focused) {
            const input = Array.from(this.root.querySelectorAll<HTMLInputElement>("[data-control-key]")).find(input => input.dataset.controlKey === focused);
            const dialog=this.root.querySelector('[role=dialog]');
            if(dialog&&input&&!dialog.contains(input)){
                // A newly opened host sheet owns focus over its old trigger.
            } else if (wasTab) {
                this.nodes.get(focused?.split('-tab-')[0] ?? '')?.querySelector<HTMLElement>('[role=tab][aria-selected=true]')?.focus();
            }
            else
                input?.focus();
            if (input && this.editQueue.has(focused ?? '') && typed !== undefined)
                input.value = typed;
            if (input?.type === "text" && start !== null && end !== null)
                input.setSelectionRange(start ?? 0, end ?? 0);
        }
        this.hostSlots(batch.host_slots);
    }
}

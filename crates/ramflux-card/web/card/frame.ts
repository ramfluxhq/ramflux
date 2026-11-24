// SPDX-License-Identifier: BSD-3-Clause
import type { HostPresentation } from '../settings';
import type { HostSlot } from '../adapter';
import type { CardNode, Context, KindRenderer, RenderOptions } from './types';
import { tokens } from './tokens';
import { motion } from './motion';
import { Overlay } from './parts/overlay';
import { el, chip, button, tip } from './parts/primitives';
import { render as Text } from './kinds/text';
import { render as Icon } from './kinds/icon';
import { render as Row } from './kinds/row';
import { render as Column } from './kinds/column';
import { render as List } from './kinds/list';
import { render as Card } from './kinds/card';
import { render as Tabs } from './kinds/tabs';
import { render as Modal } from './kinds/modal';
import { render as Divider } from './kinds/divider';
import { render as Button } from './kinds/button';
import { render as TextField } from './kinds/text-field';
import { render as CheckBox } from './kinds/check-box';
import { render as ChoicePicker } from './kinds/choice-picker';
import { render as Slider } from './kinds/slider';
import { render as DateTimeInput } from './kinds/date-time-input';
import { render as Image } from './kinds/image';
import { render as Approval } from './kinds/approval';
import { render as Task } from './kinds/task';
import { render as Chart } from './kinds/chart';
import { render as Table } from './kinds/table';
const kinds: Record<string, KindRenderer> = { Text, Icon, Row, Column, List, Card, Tabs, Modal, Divider, Button, TextField, CheckBox, ChoicePicker, Slider, DateTimeInput, Image, Approval, Task, Chart, Table };
export class CardFrame {
    private observer?: ResizeObserver;
    private overlays: Overlay;
    private timer: ReturnType<typeof setInterval>;
    private selected = new Map<string, number>();
    private touched = new Set<string>();
    private ctx?: Context;
    private nodes = new Map<string, CardNode>();
    private shownLinks = new Set<string>();
    private openModal?: {
        key: string;
        contentKey: string;
    };
    private lifecycle = 'open';
    private generating = false;
    constructor(private root: HTMLElement, private options: RenderOptions = {}) { root.classList.add('rf-frame'); root.dataset.width = 'regular'; this.overlays = new Overlay(root); if (typeof ResizeObserver !== 'undefined') {
        this.observer = new ResizeObserver(entries => { const w = entries[0]?.borderBoxSize?.[0]?.inlineSize ?? root.getBoundingClientRect().width; root.dataset.width = w < 400 ? 'compact' : w < 600 ? 'regular' : 'wide'; });
        this.observer.observe(root);
    } this.timer = setInterval(() => { for (const timer of root.querySelectorAll<HTMLElement>('[data-expires]')) {
        const seconds = Math.max(0, Number(timer.dataset.expires) - Math.floor(Date.now() / 1000));
        timer.textContent = seconds ? 'Expires in ' + Math.floor(seconds / 60) + ':' + String(seconds % 60).padStart(2, '0') : 'Expired';
        timer.classList.toggle('rf-warning', seconds < 60);
    } }, 1000); }
    configure(options: RenderOptions): void { this.options = { ...this.options, ...options }; }
    touch(key: string): void { this.touched.add(key); const node = this.nodes.get(key), element = Array.from(this.root.querySelectorAll<HTMLElement>('[data-card-key]')).find(e => e.dataset.cardKey === key); if (node && element && this.ctx) {
        const fresh = this.node(node, this.ctx);
        element.replaceWith(fresh);
    } }
    render(nodes: Map<string, CardNode>, p: HostPresentation, slots: readonly HostSlot[], event: Context['event'], flags: {
        lifecycle?: string;
        generating?: boolean;
    } = {}): void {
        this.overlays.close(false);
        if (!nodes.size) {
            this.root.replaceChildren();
            return;
        }
        this.nodes = nodes;
        for (const key of this.selected.keys())
            if (!nodes.has(key))
                this.selected.delete(key);
        for (const key of this.touched)
            if (!nodes.has(key))
                this.touched.delete(key);
        this.lifecycle = flags.lifecycle ?? 'open';
        this.generating = flags.generating ?? false;
        tokens(this.root, p);
        motion(this.root);
        const readOnly = this.lifecycle !== 'open' || this.generating || ['read-only', 'busy', 'consumed', 'closed', 'expired', 'superseded', 'streaming'].includes(this.options.state ?? '');
        const ctx: Context = { presentation: p, options: this.options, slots, selected: this.selected, touched: this.touched, readOnly, event, render: key => { const n = nodes.get(key); return n ? this.node(n, ctx) : el('span'); }, rerender: () => this.render(nodes, p, slots, event, flags), touch: key => this.touch(key), label: n => String(n.attrs.label ?? n.attrs.title ?? n.attrs.text ?? n.kind), overlay: (title, body, trigger) => this.overlays.open(title, body, trigger), modal: (key, trigger, contentKey) => { this.openModal = { key, contentKey }; event(key, { kind: 'modal_open' }); } };
        this.ctx = ctx;
        const header = el('header', 'rf-card__header');
        header.append(el('span', 'rf-card__avatar', 'N'), el('span', 'rf-card__author', 'Nova · Agent' + (this.options.owner || this.options.state === 'other-owner' ? ' · ' + (this.options.owner ?? 'Zhou Ning') : '')));
        const state = this.options.state ?? (this.generating ? 'streaming' : this.lifecycle);
        const label = ({ busy: 'Submitting…', consumed: 'Waiting for confirmation', closed: 'Closed', retired: 'Closed', expired: 'Expired', superseded: 'Updated', streaming: 'Generating', 'out-of-sync': 'Out of sync' } as Record<string, string>)[state];
        if (label)
            header.append(chip(label));
        const info = button('ⓘ', () => { const body = el('div', 'rf-column'); body.append(tip('Reference renderer · no production authority'), el('p', 'rf-secondary', 'Signed library verified by the Rust worker. Host-owned actions still require SDK authorization.')); this.overlays.open('Origin and verification', body, info); }, 'icon');
        info.setAttribute('aria-label', 'Origin and verification');
        header.append(info);
        const content = el('div', 'rf-card__body');
        content.inert = state === 'busy';
        content.addEventListener('pointerdown',e=>{
            if(!(e.target instanceof Element)||!e.target.closest('button[data-kind=Button]:disabled'))return;
            const invalid=Array.from(nodes.values()).find(n=>n.attrs.input_pointer&&n.attrs.errors?.length&&!n.attrs.disabled);
            if(!invalid)return;
            this.touch(invalid.key);
            const field=Array.from(this.root.querySelectorAll<HTMLElement>('[data-card-key]')).find(n=>n.dataset.cardKey===invalid.key);
            field?.querySelector<HTMLElement>('input,textarea,button,[role=slider]')?.focus();
        },true);
        if (this.options.title)
            content.append(el('h2', 'rf-card__title', this.options.title));
        if (state === 'superseded')
            content.append(tip('Content updated. The version you saw has changed. Review the new version before deciding.'));
        if (state === 'stale')
            content.append(tip('This content changed. Check it and try again.', 'danger'));
        if (state === 'draft-replaced')
            content.append(tip('Your edit was replaced by a newer version.'));
        for (const n of nodes.values())
            if (n.parent_key === null)
                content.append(ctx.render(n.key));
        if (state === 'out-of-sync')
            content.append(button('Resync', () => this.options.onReference?.({ type: 'reference_resync' })));
        if (state === 'failed' && !Array.from(nodes.values()).some(n=>n.parent_key===null&&['Chart','Image'].includes(n.kind)))
            content.append(tip('Could not send. Your input is kept.', 'danger'), button('Retry', () => this.options.onReference?.({ type: 'reference_retry' })));
        this.root.dataset.lifecycle = state;
        this.root.inert=state==='busy';
        this.root.replaceChildren(header, content);
        if (this.options.referenceHost) {
            const slot = slots.find(s => s.kind === 'link_open' && !this.shownLinks.has(s.id));
            if (slot) {
                this.shownLinks.add(slot.id);
                const body = el('div', 'rf-column');
                body.append(el('p', 'rf-secondary', 'Reference host · author Nova'), el('code', '', String(slot.url)), tip('Opening a link may share your network address with the destination.'));
                const cancel = button('Cancel', () => this.overlays.close());
                const open = button('Open', () => { this.options.onReference?.({ type: 'reference_link_open', url: slot.url }); this.overlays.close(); }, 'primary');
                const actions = el('div', 'rf-actions');
                actions.append(cancel, open);
                body.append(actions);
                this.overlays.open('Open external link · reference', body, this.root);
            }
        }
        if (this.openModal) {
            const modal = this.openModal, node = nodes.get(modal.key);
            if (node) {
                const body = ctx.render(modal.contentKey);
                const trigger = Array.from(this.root.querySelectorAll<HTMLElement>('[data-card-key]')).find(e => e.dataset.cardKey === modal.key)?.querySelector<HTMLElement>('button') ?? this.root;
                this.overlays.open('Details', body, trigger, () => { this.openModal = undefined; event(modal.key, { kind: 'modal_close' }); });
            }
            else
                this.openModal = undefined;
        }
    }
    private node(node: CardNode, ctx: Context): HTMLElement { if (this.options.state === 'disabled')
        node = { ...node, attrs: { ...node.attrs, disabled: true } }; const render = kinds[node.kind]; const element = render ? render(node, ctx) : el('p', 'rf-secondary', 'Content unavailable'); element.dataset.cardKey = node.key; element.dataset.kind = node.kind; const a = node.attrs.accessibility; if (a?.label && node.kind !== 'Button')
        element.setAttribute('aria-label', a.label); if (a?.hidden)
        element.setAttribute('aria-hidden', 'true'); if (a?.live)
        element.setAttribute('aria-live', a.live); if (typeof node.attrs.weight === 'number')
        element.style.flexGrow = String(node.attrs.weight); return element; }
    dispose(): void { this.observer?.disconnect(); clearInterval(this.timer); this.overlays.close(); }
}

// SPDX-License-Identifier: BSD-3-Clause
import type { CardNode, Context } from '../types';
export function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls = '', text?: string): HTMLElementTagNameMap[K] { const e = document.createElement(tag); e.className = cls; if (text !== undefined)
    e.textContent = text; return e; }
export function button(text: string, action: () => void, variant = 'default'): HTMLButtonElement { const b = el('button', 'rf-button rf-button--' + variant, text); b.type = 'button'; b.onclick = action; return b; }
export function chip(text: string, tone = 'neutral'): HTMLElement { return el('span', 'rf-chip rf-chip--' + tone, text); }
export function spinner(): HTMLElement { const s = el('span', 'rf-spinner'); s.setAttribute('aria-hidden', 'true'); return s; }
export function skeleton(): HTMLElement { const e = el('div', 'rf-skeletons'); e.setAttribute('aria-label', 'Loading'); for (const width of ['100%', '70%', '40%']) {
    const s = el('span', 'rf-skeleton');
    s.style.inlineSize = width;
    e.append(s);
} return e; }
export function field(node: CardNode, ctx: Context, control: HTMLElement): HTMLElement {
    const a = node.attrs;
    const required = a.required || String(a.label ?? '').endsWith(' *');
    const wrap = el('div', 'rf-field');
    const label = el('label', 'rf-field__label', ctx.label(node) + (a.required ? ' *' : ''));
    const id = 'rf-field-' + encodeURIComponent(node.key);
    control.id = id;
    label.htmlFor = id;
    control.dataset.controlKey = node.key;
    control.setAttribute('aria-label', ctx.label(node));
    if (required)
        control.setAttribute('aria-required', 'true');
    const invalid = (ctx.touched.has(node.key) || ctx.options.state === 'error' || ctx.options.state === 'stale') && (a.errors?.length || ctx.options.state === 'stale');
    control.setAttribute('aria-invalid', String(!!invalid));
    wrap.dataset.invalid = String(!!invalid);
    wrap.append(label, control);
    control.addEventListener('focusout', () => ctx.touch(node.key));
    if (a.helper)
        wrap.append(el('span', 'rf-field__helper', String(a.helper)));
    if (invalid) {
        const error = el('span', 'rf-field__error', ctx.options.state === 'stale' ? 'This content changed. Check it and try again.' : a.errors.join(' '));
        error.id = id + '-error';
        error.setAttribute('role', 'alert');
        wrap.append(error);
        control.setAttribute('aria-describedby', error.id);
    }
    return wrap;
}
export function disclosure(label: string, body: HTMLElement): HTMLElement { const d = el('details', 'rf-disclosure'); d.append(el('summary', 'rf-disclosure__label', label), body); return d; }
export function tip(text: string, tone = 'neutral'): HTMLElement { const e = el('div', 'rf-tip rf-tip--' + tone, text); e.setAttribute('role', 'status'); return e; }
export function number(value: number, ctx: Context): string { return new Intl.NumberFormat(ctx.presentation.locale === 'en-XA' ? 'en' : ctx.presentation.locale).format(value); }

// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, button } from '../parts/primitives';
export const render: KindRenderer = (n, c) => { const e = el('div', 'rf-tabs'), list = el('div', 'rf-tabs__list' + ((n.attrs.tabs?.length ?? 0) > 4 ? ' rf-tabs__list--underline' : '')); list.setAttribute('role', 'tablist'); list.setAttribute('aria-label', 'Card sections'); const selected = c.selected.get(n.key) ?? 0; for (const [i, tab] of (n.attrs.tabs as {
    title: string;
}[]).entries()) {
    const activate = () => { c.selected.set(n.key, i); c.event(n.key, { kind: 'select_tab', index: i }); };
    const b = button(tab.title, activate, 'borderless');
    b.className = 'rf-tabs__tab';
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', String(i === selected));
    b.tabIndex = i === selected ? 0 : -1;
    b.dataset.controlKey = n.key + '-tab-' + i;
    b.onkeydown = ev => { let next: number | undefined; if (['ArrowLeft', 'ArrowRight'].includes(ev.key))
        next = (i + (ev.key === 'ArrowRight' ? 1 : -1) * (c.presentation.direction === 'rtl' ? -1 : 1) + n.children.length) % n.children.length; if (ev.key === 'Home')
        next = 0; if (ev.key === 'End')
        next = n.children.length - 1; if (next !== undefined) {
        ev.preventDefault();
        c.selected.set(n.key, next);
        c.event(n.key, { kind: 'select_tab', index: next });
    } };
    list.append(b);
} const panel = el('div', 'rf-tabs__panel'); panel.setAttribute('role', 'tabpanel'); const key = n.children[selected]; if (key)
    panel.append(c.render(key)); e.append(list, panel); return e; };

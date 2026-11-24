// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, button } from '../parts/primitives';
export const render: KindRenderer = (n, c) => { const e = el('div', 'rf-list'), horizontal = n.attrs.direction === 'horizontal'; const list = el('div', 'rf-list__items' + (horizontal ? ' rf-list__items--horizontal' : '')); list.setAttribute('role', 'list'); const draw = (all = false) => { list.replaceChildren(); for (const k of n.children.slice(0, all || horizontal ? undefined : 5)) {
    const row = el('div', 'rf-list__item');
    row.setAttribute('role', 'listitem');
    row.append(c.render(k));
    list.append(row);
} }; draw(); e.append(list); if (!n.children.length)
    e.append(el('p', 'rf-list__empty rf-secondary', 'Nothing to show')); if (n.children.length > 5 && !horizontal) {
    const more = button('Show all (' + n.children.length + ')', () => { draw(true); more.remove(); }, 'borderless');
    e.append(more);
} if (horizontal) {
    const nav = el('div', 'rf-list__navigation');
    nav.append(button('Previous', () => list.scrollBy({ left: c.presentation.direction === 'rtl' ? 208 : -208, behavior: 'smooth' }), 'borderless'), button('Next', () => list.scrollBy({ left: c.presentation.direction === 'rtl' ? -208 : 208, behavior: 'smooth' }), 'borderless'));
    e.append(nav);
} return e; };

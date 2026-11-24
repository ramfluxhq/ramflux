// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el } from '../parts/primitives';
export const render: KindRenderer = (n, c) => { const e = el('div', 'rf-row'); e.style.justifyContent = ({ start: 'flex-start', end: 'flex-end', center: 'center', spaceBetween: 'space-between', spaceAround: 'space-around', stretch: 'space-between' } as Record<string, string>)[n.attrs.justify] ?? 'flex-start'; e.style.alignItems = n.attrs.align ?? 'stretch'; for (const k of n.children)
    e.append(c.render(k)); if (n.attrs.justify === 'stretch')
    e.classList.add('rf-row--equal'); return e; };

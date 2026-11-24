// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, field } from '../parts/primitives';
import { icon } from './icon';
export const render: KindRenderer = (n, c) => { const b = el('button', 'rf-check'), box = el('span', 'rf-check__box'); b.type = 'button'; b.setAttribute('role', 'checkbox'); b.setAttribute('aria-checked', String(n.attrs.value === true)); b.disabled = !!n.attrs.disabled || c.readOnly; if (n.attrs.value)
    box.append(icon('check')); b.append(box, el('span', 'rf-check__label', c.label(n))); b.onclick = () => c.event(n.key, { kind: 'input', value: !n.attrs.value }); const f = field(n, c, b); f.querySelector('label')?.remove(); return f; };

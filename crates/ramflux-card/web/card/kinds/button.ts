// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { button, spinner } from '../parts/primitives';
import { icon } from './icon';
export const render: KindRenderer = (n, c) => { const b = button('', () => c.event(n.key, { kind: 'activate' }), n.attrs.variant ?? 'default'); for (const k of n.children)
    b.append(c.render(k)); const label = n.attrs.accessibility?.label ?? b.textContent?.trim(); if (!label)
    b.disabled = true;
else
    b.setAttribute('aria-label', label); b.title = label ?? ''; b.disabled = b.disabled || !!n.attrs.disabled || c.readOnly; const state = c.options.state; if (state === 'busy') {
    b.replaceChildren(spinner(), document.createTextNode('Submitting…'));
    b.disabled = true;
    b.setAttribute('aria-busy', 'true');
} if (['hover', 'pressed', 'focus'].includes(state ?? ''))
    b.dataset.preview = state; if (n.attrs.action?.openUrl || c.options.state === 'link')
    b.append(icon('openInNew')); return b; };

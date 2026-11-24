// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el } from '../parts/primitives';
export const render: KindRenderer = (n, c) => { const e = el('section', n.parent_key ? 'rf-card__inset' : 'rf-card__content'); for (const k of n.children)
    e.append(c.render(k)); return e; };

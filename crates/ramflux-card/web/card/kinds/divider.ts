// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el } from '../parts/primitives';
export const render: KindRenderer = n => { const e = el('div', 'rf-divider rf-divider--' + (n.attrs.axis ?? 'horizontal')); e.setAttribute('aria-hidden', 'true'); return e; };

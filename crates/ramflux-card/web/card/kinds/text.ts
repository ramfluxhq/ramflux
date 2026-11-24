// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el } from '../parts/primitives';
// The catalog's small Markdown subset is built as text nodes, never HTML.
export const render: KindRenderer = (node) => { const e = el('div', 'rf-text rf-text--' + (node.attrs.variant ?? 'body')); const text = String(node.attrs.text ?? '');
    if(!text){e.hidden=true;return e} for (const [i, line] of text.split('\n').entries()) {
    if (i)
        e.append(el('br'));
    const target = /^[-*] /.test(line) ? el('div', 'rf-text__bullet') : el('span');
    let cursor = 0;
    const re = /(\*\*([^*]+)\*\*|`([^`]+)`|\*([^*]+)\*)/g;
    const value = line.replace(/^[-*] /, '');
    for (const match of value.matchAll(re)) {
        target.append(document.createTextNode(value.slice(cursor, match.index)));
        target.append(el(match[2] ? 'strong' : match[3] ? 'code' : 'em', '', match[2] ?? match[3] ?? match[4]));
        cursor = (match.index ?? 0) + match[0].length;
    }
    target.append(document.createTextNode(value.slice(cursor)));
    e.append(target);
} return e; };

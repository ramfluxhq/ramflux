// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer, Context } from '../types';
import { el, button, number } from '../parts/primitives';
import { icon } from './icon';
export function table(columns: {
    label: string;
}[], rows: unknown[][], ctx: Context, limit = 8): HTMLElement { const wrap = el('div', 'rf-table'), t = el('table'), thead = el('thead'), head = el('tr'); for (const col of columns) {
    const th = el('th', '', col.label);
    th.scope = 'col';
    head.append(th);
} thead.append(head); t.append(thead); const body = el('tbody'); for (const row of rows.slice(0, limit)) {
    const tr = el('tr');
    for (const value of row) {
        const cell = el('td');
        cell.dataset.type = typeof value;
        if (typeof value === 'boolean') {
            const spoken = el('span', 'rf-sr-only', value ? 'Yes' : 'No');
            cell.append(spoken, value ? icon('check') : el('span', 'rf-secondary', '—'));
        }
        else
            cell.textContent = typeof value === 'number' ? number(value, ctx) : String(value ?? '');
        tr.append(cell);
    }
    body.append(tr);
} if (!rows.length) {
    const tr = el('tr'), td = el('td', 'rf-table__empty', 'No rows');
    td.colSpan = columns.length;
    tr.append(td);
    body.append(tr);
} t.append(body); wrap.append(t); if (rows.length > limit) {
    const footer = el('div', 'rf-table__footer', 'Showing ' + limit + ' of ' + rows.length);
    const expand = button('Expand', () => { const full = table(columns, rows, ctx, rows.length); full.append(button('Copy as text', () => { void navigator.clipboard?.writeText([columns.map(c => c.label).join('\t'), ...rows.map(row => row.join('\t'))].join('\n')); }, 'borderless')); ctx.overlay('Table', full, expand); }, 'borderless');
    footer.append(expand);
    wrap.append(footer);
} return wrap; }
export const render: KindRenderer = (n, c) => table(n.attrs.columns ?? [], (n.attrs.rows as {
    cells: unknown[];
}[] ?? []).map(r => r.cells), c);

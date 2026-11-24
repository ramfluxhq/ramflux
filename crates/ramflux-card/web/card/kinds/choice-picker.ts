// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, button, field } from '../parts/primitives';
import { icon } from './icon';
export const render: KindRenderer = (n, c) => {
    const a = n.attrs, exclusive = a.variant === 'mutuallyExclusive', chips = a.displayStyle === 'chips', options = a.options as {
        label: string;
        value: string;
    }[], values = Array.isArray(a.value) ? a.value : [];
    const group = el('div', 'rf-choice' + (chips ? ' rf-choice--chips' : ''));
    group.setAttribute('role', exclusive ? 'radiogroup' : 'group');
    group.setAttribute('aria-label', c.label(n));
    const rows = el('div', 'rf-choice__rows');
    const build = (filter = '') => { rows.replaceChildren(); for (const [i, o] of options.entries()) {
        if (!o.label.toLocaleLowerCase().includes(filter.toLocaleLowerCase()))
            continue;
        const checked = values.includes(o.value);
        const b = button('', () => { c.event(n.key, { kind: 'input', value: exclusive ? [o.value] : checked ? values.filter(v => v !== o.value) : [...values, o.value] }); }, 'borderless');
        b.dataset.controlKey=n.key+'-choice-'+o.value;
                b.className = 'rf-choice__option' + (chips ? ' rf-choice__option--chip' : '');
        b.setAttribute('role', exclusive ? 'radio' : 'checkbox');
        b.setAttribute('aria-checked', String(checked));
        b.disabled = !!a.disabled || c.readOnly;
        b.tabIndex = exclusive ? (checked || (!values.length && i === 0) ? 0 : -1) : 0;
        const mark = el('span', exclusive ? 'rf-choice__radio' : 'rf-check__box');
        if (checked)
            mark.append(exclusive ? el('span', 'rf-choice__dot') : icon('check'));
        b.append(mark, document.createTextNode(o.label));
        if (exclusive)
            b.onkeydown = e => { const delta = (e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : e.key === 'ArrowUp' || e.key === 'ArrowLeft' ? -1 : 0) * (c.presentation.direction === 'rtl' && e.key.startsWith('Arrow') && !['ArrowDown', 'ArrowUp'].includes(e.key) ? -1 : 1); if (delta) {
                e.preventDefault();
                const next = options[(i + delta + options.length) % options.length];
                if (next) {
                    b.dataset.controlKey=n.key+'-choice-'+next.value;
                    c.event(n.key, { kind: 'input', value: [next.value] });
                }
            } };
        rows.append(b);
    } if (!rows.childElementCount)
        rows.append(el('p', 'rf-meta', 'No matches')); };
    build();
    const contents = el('div', 'rf-choice__menu');
    if (a.filterable) {
        const search = el('input', 'rf-field__input rf-choice__search');
        search.type = 'text';
        search.placeholder = 'Search options';
        search.setAttribute('aria-label', 'Search options');
        search.oninput = () => build(search.value);
        contents.append(search);
    }
    contents.append(rows);
    if (options.length > 6 && !chips) {
        const trigger = button(options.filter(o => values.includes(o.value)).map(o => o.label).join(', ') || 'Choose an option', () => c.overlay(c.label(n), contents, trigger));
        trigger.className = 'rf-field__input rf-choice__trigger';
        trigger.append(icon('expandMore'));
        trigger.disabled = !!a.disabled || c.readOnly;
        group.append(trigger);
    }
    else
        group.append(contents);
    return field(n, c, group);
};

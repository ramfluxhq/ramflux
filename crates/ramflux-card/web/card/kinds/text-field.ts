// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, field } from '../parts/primitives';
export const render: KindRenderer = (n, c) => { const a = n.attrs; const input = a.variant === 'longText' ? el('textarea', 'rf-field__input rf-field__input--long') : el('input', 'rf-field__input'); if (input instanceof HTMLInputElement) {
    input.type = 'text';
    if (a.variant === 'number') {
        input.inputMode = 'decimal';
        input.classList.add('rf-field__input--number');
    }
} input.value = String(a.value ?? ''); input.placeholder = a.placeholder ?? (a.variant === 'number' ? '0' : 'Enter ' + c.label(n).toLowerCase()); input.disabled = !!a.disabled && !c.readOnly; input.readOnly = c.readOnly; input.onchange = () => c.event(n.key, { kind: 'input', value: input.value }); input.oninput = () => { c.event(n.key, { kind: 'input', value: input.value }); if (input.tagName === 'TEXTAREA') {
    input.style.blockSize = 'auto';
    input.style.blockSize = Math.min(input.scrollHeight, 194) + 'px';
} }; const e = field(n, c, input); if (a.variant === 'longText') {
    const counter = el('span', 'rf-field__counter', input.value.length + ' characters');
    input.addEventListener('input', () => { counter.textContent = input.value.length + ' characters'; });
    e.append(counter);
} return e; };

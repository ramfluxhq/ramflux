// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, button, field } from '../parts/primitives';
import { icon } from './icon';
export const render: KindRenderer = (n, c) => { const a = n.attrs; let date = new Date((/^\d{2}:\d{2}/.test(String(a.value ?? '')) ? '2026-11-24T' + String(a.value) : String(a.value || '2026-11-24')) + (String(a.value ?? '').length === 10 ? 'T12:00:00' : '')); if (!Number.isFinite(date.getTime()))
    date = new Date('2026-11-24T12:00:00'); const dateEnabled = a.enableDate === true, timeEnabled = a.enableTime === true; const trigger = button('', () => { if (c.readOnly)
    return; const pop = el('div', 'rf-date__popover'); let month = new Date(date.getFullYear(), date.getMonth(), 1); const draw = () => { pop.replaceChildren(); const heading = el('div', 'rf-date__heading'), prev = button('‹', () => { month.setMonth(month.getMonth() - 1); draw(); }, 'icon'), next = button('›', () => { month.setMonth(month.getMonth() + 1); draw(); }, 'icon'); heading.append(prev, el('strong', 'rf-meta', month.toLocaleDateString(c.presentation.locale, { month: 'long', year: 'numeric' })), next); if (dateEnabled) {
    pop.append(heading);
    const grid = el('div', 'rf-date__grid');
    grid.setAttribute('role', 'grid');
    for (const d of ['M', 'T', 'W', 'T', 'F', 'S', 'S'])
        grid.append(el('span', 'rf-caption', d));
    const offset = (month.getDay() + 6) % 7;
    for (let i = 0; i < offset; i++)
        grid.append(el('span'));
    for (let d = 1; d <= new Date(month.getFullYear(), month.getMonth() + 1, 0).getDate(); d++) {
        const picked = new Date(month.getFullYear(), month.getMonth(), d, 12);
        const iso = [picked.getFullYear(), String(picked.getMonth() + 1).padStart(2, '0'), String(d).padStart(2, '0')].join('-');
        const cell = button(String(d), () => { date.setFullYear(picked.getFullYear(), picked.getMonth(), d);
                        trigger.focus(); c.event(n.key, { kind: 'input', value: timeEnabled ? iso + 'T' + String(date.getHours()).padStart(2, '0') + ':' + String(date.getMinutes()).padStart(2, '0') : iso }); c.options.onReference?.({ type: 'date_selected', value: iso }); }, 'borderless');
        cell.className = 'rf-date__day';
        cell.setAttribute('role', 'gridcell');
        cell.setAttribute('aria-label', picked.toLocaleDateString(c.presentation.locale, { dateStyle: 'full' }));
        cell.setAttribute('aria-selected', String(picked.toDateString() === date.toDateString()));
        cell.disabled = !!(a.min && iso < String(a.min).slice(0, 10) || a.max && iso > String(a.max).slice(0, 10));
        cell.onkeydown = e => { const buttons = Array.from(grid.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')); const index = buttons.indexOf(cell), delta = ({ ArrowRight: 1, ArrowLeft: -1, ArrowDown: 7, ArrowUp: -7 } as Record<string, number>)[e.key]; if (delta !== undefined) {
            e.preventDefault();
            buttons[index + delta]?.focus();
        } if (['PageUp', 'PageDown'].includes(e.key)) {
            e.preventDefault();
            month.setMonth(month.getMonth() + (e.key === 'PageUp' ? -1 : 1));
            draw();
        } };
        grid.append(cell);
    }
    pop.append(grid);
} if (timeEnabled) {
    const time = el('div', 'rf-date__time');
    for (const [name, max] of [['Hours', 23], ['Minutes', 59]] as const) {
        const group = el('div', 'rf-date__stepper');
        const value = name === 'Hours' ? date.getHours() : date.getMinutes();
        const change = (delta: number) => { if (name === 'Hours')
            date.setHours((value + delta + 24) % 24);
        else
            date.setMinutes((value + delta + 60) % 60); draw(); };
        group.append(el('span', 'rf-meta', name), button('−', () => change(-1), 'icon'), el('output', 'rf-meta', String(value).padStart(2, '0')), button('+', () => change(1), 'icon'));
        time.append(group);
    }
    time.append(button('Apply time', () => c.event(n.key, { kind: 'input', value: dateEnabled ? date.toISOString().slice(0, 16) : date.toTimeString().slice(0, 5) }), 'primary'));
    pop.append(time);
} }; draw(); c.overlay(dateEnabled ? 'Choose date' : 'Choose time', pop, trigger); }); trigger.className = 'rf-field__input rf-date__trigger'; trigger.setAttribute('role', 'combobox'); trigger.setAttribute('aria-haspopup', 'dialog'); trigger.setAttribute('aria-readonly', String(c.readOnly)); trigger.disabled = !!a.disabled && !c.readOnly || !dateEnabled && !timeEnabled; trigger.append(el('span', '', a.value ? (dateEnabled ? date.toLocaleString(c.presentation.locale, { year: 'numeric', month: 'short', day: 'numeric', ...(timeEnabled ? { hour: '2-digit', minute: '2-digit' } : {}) }) : date.toLocaleTimeString(c.presentation.locale, { hour: '2-digit', minute: '2-digit' })) : 'Choose a date'), icon(timeEnabled ? 'event' : 'calendarToday')); return field(n, c, trigger); };

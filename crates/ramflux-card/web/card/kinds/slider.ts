// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, field, number } from '../parts/primitives';
export const render: KindRenderer = (n, c) => { const a = n.attrs, min = Number(a.min ?? 0), max = Number(a.max ?? 100), steps = Number(a.steps ?? 0), step = steps > 0 ? (max - min) / steps : (max - min) / 100; let value = Number(a.value ?? min); const e = el('div', 'rf-slider'), control = el('div', 'rf-slider__control'), track = el('div', 'rf-slider__track'), fill = el('div', 'rf-slider__fill'), thumb = el('span', 'rf-slider__thumb'), output = el('output', 'rf-slider__value'); track.append(fill); control.append(track, thumb); control.dataset.controlKey=n.key+'-slider';
    control.setAttribute('role', 'slider'); control.tabIndex = a.disabled || c.readOnly ? -1 : 0; for (const [k, v] of Object.entries({ 'aria-valuemin': min, 'aria-valuemax': max, 'aria-label': c.label(n), 'aria-disabled': !!a.disabled || c.readOnly }))
    control.setAttribute(k, String(v)); const show = () => { const pct = (value - min) / (max - min || 1) * 100; fill.style.inlineSize = pct + '%'; thumb.style.insetInlineStart = pct + '%'; control.setAttribute('aria-valuenow', String(value)); control.setAttribute('aria-valuetext', number(value, c)); output.value = number(value, c); }; show(); const commit = (v: number) => { if (a.disabled || c.readOnly)
    return; value = Math.max(min, Math.min(max, Math.round((v - min) / step) * step + min)); show(); c.event(n.key, { kind: 'input', value }); }; control.onkeydown = e => { const sign = c.presentation.direction === 'rtl' ? -1 : 1; const v = ({ ArrowRight: value + step * sign, ArrowLeft: value - step * sign, ArrowUp: value + step, ArrowDown: value - step, PageUp: value + (max - min) / 10, PageDown: value - (max - min) / 10, Home: min, End: max } as Record<string, number>)[e.key]; if (v !== undefined) {
    e.preventDefault();
    commit(v);
} }; control.onpointerdown = e => { if (a.disabled || c.readOnly)
    return; control.focus(); control.setPointerCapture(e.pointerId); const move = (x: number) => { const rect = control.getBoundingClientRect(); let pct = (x - rect.x) / rect.width; if (c.presentation.direction === 'rtl')
    pct = 1 - pct; value = Math.max(min, Math.min(max, Math.round(pct * (max - min) / step) * step + min)); show(); }; move(e.clientX); control.onpointermove = p => move(p.clientX); control.onpointerup = () => { control.onpointermove = null; control.onpointerup = null; commit(value); }; }; e.append(output, control); if (steps > 0 && steps <= 20) {
    const ticks = el('div', 'rf-slider__ticks');
    for (let i = 0; i <= steps; i++)
        ticks.append(el('i'));
    e.append(ticks);
} return field(n, c, e); };

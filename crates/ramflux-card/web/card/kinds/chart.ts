// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, button, spinner, number } from '../parts/primitives';
import { table } from './table';
import { icon } from './icon';
export const render: KindRenderer = (n, c) => {
    const a = n.attrs, series = a.series as {
        label: string;
        points: {
            label: string;
            value: number;
        }[];
    }[] ?? [], scale = Number(a.scale) || 1, e = el('section', 'rf-chart'), head = el('div', 'rf-chart__header'), title = el('div');
    title.append(el('strong', 'rf-chart__title', 'Response time'), el('p', 'rf-secondary', String(a.unit ?? '') + ' · This week'));
    const body = el('div', 'rf-chart__body'), legend = el('div', 'rf-chart__legend');
    const rows = () => { const labels = [...new Set(series.flatMap(s => s.points.map(p => p.label)))]; return labels.map(label => [label, ...series.map(s => { const p = s.points.find(p => p.label === label); return p ? number(p.value / scale, c) + ' ' + String(a.unit ?? '') : '—'; })]); };
    const showTable = () => { body.replaceChildren(table([{ label: 'Period' }, ...series.map(s => ({ label: s.label }))], rows(), c, 5)); };
    let mode = false;
    const toggle = button('Table', () => { mode = !mode; if (mode)
        showTable();
    else
        draw(); toggle.textContent = mode ? 'Chart' : 'Table'; }, 'borderless');
    const expand = button('Expand', () => { const full = el('div', 'rf-chart__expanded'); full.append(body.cloneNode(true), table([{ label: 'Period' }, ...series.map(s => ({ label: s.label }))], rows(), c, 16)); c.overlay('Response time', full, expand); }, 'borderless');
    head.append(title, toggle, expand);
    e.append(head, legend, body);
    series.forEach((s, i) => { const item = el('span', 'rf-chart__legend-item'); const dot = el('i', 'rf-chart__dot rf-chart__series-' + i); item.append(dot, el('span', '', s.label), el('strong', '', number((s.points.at(-1)?.value ?? 0) / scale, c) + ' ' + String(a.unit ?? ''))); legend.append(item); });
    const draw = () => {
        body.replaceChildren();
        if (c.options.state === 'loading') {
            const loading = el('div', 'rf-chart__state');
            loading.append(spinner(), document.createTextNode('Loading data…'));
            body.append(loading);
            return;
        }
        if (c.options.state === 'failed') {
            const failed = el('div', 'rf-chart__state');
            failed.append(icon('warning'), el('p', 'rf-secondary', 'Could not load data'), button('Retry', () => { c.options.state = 'default'; draw(); }));
            body.append(failed);
            return;
        }
        if (!series.some(s => s.points.length)) {
            const empty = el('div', 'rf-chart__state');
            empty.append(icon('info'), el('p', 'rf-secondary', 'No data for this period'));
            body.append(empty);
            return;
        }
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 400 175');
        svg.classList.add('rf-chart__plot');
        svg.setAttribute('aria-hidden', 'true');
        svg.setAttribute('direction', 'ltr');
        const make = (tag: string, attrs: Record<string, string | number>, text?: string) => { const item = document.createElementNS(svg.namespaceURI, tag); for (const [k, v] of Object.entries(attrs))
            item.setAttribute(k, String(v)); if (text)
            item.textContent = text; svg.append(item); return item; };
        const values = series.flatMap(s => s.points.map(p => p.value)), min = Math.min(0, ...values), max = Math.max(1, ...values), range = max - min;
        const y = (v: number) => 145 - (v - min) / range * 130;
        const count = Math.max(...series.map(s => s.points.length));
        const x = (i: number) => 40 + (count === 1 ? 160 : i / (count - 1) * 340);
        for (let i = 0; i < 4; i++) {
            const v = min + range * i / 3, position = y(v);
            make('line', { x1: 40, x2: 390, y1: position, y2: position, class: 'rf-chart__grid' });
            make('text', { x: 32, y: position + 4, 'text-anchor': 'end', class: 'rf-chart__axis' }, number(v / scale, c));
        }
        if (min < 0)
            make('line', { x1: 40, x2: 390, y1: y(0), y2: y(0), class: 'rf-chart__zero' });
        series.forEach((s, si) => { if (a.kind === 'bar')
            s.points.forEach((p, i) => { const pitch = 340 / count, xx = 40 + (i + .5) * pitch + (si - (series.length - 1) / 2) * 13; make('rect', { x: xx - 5.5, y: Math.min(y(p.value), y(0)), width: 11, height: Math.max(1, Math.abs(y(p.value) - y(0))), rx: 2, class: 'rf-chart__bar rf-chart__series-' + si }); });
        else {
            make('polyline', { points: s.points.map((p, i) => x(i) + ',' + y(p.value)).join(' '), class: 'rf-chart__line rf-chart__series-' + si });
            s.points.forEach((p, i) => { if (i === s.points.length - 1)
                make(si === 0 ? 'circle' : 'rect', si === 0 ? { cx: x(i), cy: y(p.value), r: 3, class: 'rf-chart__marker rf-chart__series-' + si } : { x: x(i) - 3, y: y(p.value) - 3, width: 6, height: 6, class: 'rf-chart__marker rf-chart__series-' + si }); });
        } });
        let maxLines=1;
        for (const i of [...new Set([0, Math.round((count - 1) / 3), Math.round(2 * (count - 1) / 3), count - 1])]) {
            const label=series[0]?.points[i]?.label??'';
            const words=label.match(/.{1,12}(?:\s|$)|\S{1,12}/g)??[label];
            maxLines=Math.max(maxLines,words.length);
            const text=make('text',{x:x(i),y:169,'text-anchor':i===0?'start':i===count-1?'end':'middle',class:'rf-chart__axis'});
            for(const [line,word]of words.entries()){
                const span=document.createElementNS(svg.namespaceURI,'tspan');span.setAttribute('x',String(x(i)));span.setAttribute('dy',line?'13':'0');span.textContent=word.trim();text.append(span);
            }
        }
        svg.setAttribute('viewBox','0 0 400 '+(175+(maxLines-1)*13));
        svg.style.blockSize=(175+(maxLines-1)*13)+'px';
        body.append(svg);
        const tooltip = el('div', 'rf-chart__tooltip');
        tooltip.hidden = true;
        tooltip.setAttribute('role', 'status');
        body.append(tooltip);
        const focus = el('div', 'rf-chart__interaction');
        focus.tabIndex = 0;
        focus.setAttribute('aria-label', 'Chart. Use arrow keys to inspect values.');
        let point = 0;
        const inspect = (i: number) => { point = Math.max(0, Math.min(count - 1, i)); tooltip.hidden = false; tooltip.textContent = series.map(s => { const p = s.points[point]; return p ? p.label + ' · ' + s.label + ': ' + number(p.value / scale, c) + ' ' + String(a.unit ?? '') : ''; }).join(' / '); };
        focus.onkeydown = ev => { if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(ev.key)) {
            ev.preventDefault();
            inspect(ev.key === 'Home' ? 0 : ev.key === 'End' ? count - 1 : point + (ev.key === 'ArrowRight' ? 1 : -1));
        } };
        focus.onfocus = () => inspect(point);
        focus.onpointermove = ev => { const rect = focus.getBoundingClientRect(); inspect(Math.round((ev.clientX - rect.x) / rect.width * (count - 1))); };
        focus.onclick = () => inspect(point);
        body.append(focus);
        const accessible = table([{ label: 'Period' }, ...series.map(s => ({ label: s.label }))], rows(), c, 16);
        accessible.classList.add('rf-sr-only');
        body.append(accessible);
    };
    draw();
    return e;
};

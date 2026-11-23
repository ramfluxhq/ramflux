// SPDX-License-Identifier: BSD-3-Clause
import copy from './gallery.en.json';
import { CardView } from './adapter';
import { PresentationRegistry } from './settings';
import type { HostPresentation } from './settings';
import data from 'gallery-data';
type Story = typeof data.stories[number];
const byId = <T extends HTMLElement = HTMLElement>(id: string): T => {
    const element = document.getElementById(id);
    if (!element)
        throw Error(copy.missing_gallery_element + id);
    return element as T;
};
const registry = new PresentationRegistry();
const english = registry.resolve('en', 'light', false).strings;
registry.addLocale('en-XA', 'ltr', Object.fromEntries(Object.entries(english).map(([key, value]) => [key, '[ ' + value + ' · ' + value + ' ]'])));
const locales = ['ar', 'de', 'en', 'es', 'fr', 'hi', 'id', 'it', 'ja', 'ko', 'pt-BR', 'ru', 'tr', 'zh-CN', 'zh-TW', 'en-XA'];
const locale = byId<HTMLSelectElement>('locale'), theme = byId<HTMLSelectElement>('theme'), width = byId<HTMLSelectElement>('width'), direction = byId<HTMLSelectElement>('direction'), state = byId<HTMLSelectElement>('state');
const input = byId<HTMLTextAreaElement>('input'), model = byId<HTMLTextAreaElement>('model');
for (const tag of locales) {
    const option = document.createElement('option');
    option.value = tag;
    option.textContent = tag === 'en-XA' ? copy.pseudo_locale : tag === 'ar' ? 'ar · RTL' : tag;
    locale.append(option);
}
const initial = new URLSearchParams(location.search);
function selectKnown(select: HTMLSelectElement, value: string | null, fallback: string): void { select.value = Array.from(select.options).some(o => o.value === value) ? value ?? fallback : fallback; }
selectKnown(locale, initial.get('locale'), 'en');
selectKnown(theme, initial.get('theme'), 'light');
selectKnown(width, initial.get('width'), 'dock');
selectKnown(direction, initial.get('direction'), 'auto');
let story = data.stories.find(s => s.id === initial.get('story')) ?? data.stories.find(s => s.kind === initial.get('kind') && s.variant === initial.get('variant') && s.state === (initial.get('state') ?? 'default')) ?? data.stories.find(s => s.id === 'example/complete_form') ?? data.stories[0];
if (!story)
    throw Error(copy.empty_story_inventory);
let card: CardView | undefined;
let busy = false;
let renderGeneration = 0;
let events: unknown[] = [];
let typedRefusal: unknown;
const pretty = (value: unknown) => JSON.stringify(value, null, 2);
function log(entry: unknown): void { events.push(entry); events = events.slice(-100); byId('events').textContent = pretty(events); byId('event-count').textContent = String(events.length); }
function presentation(): HostPresentation {
    const value = registry.resolve(locale.value, theme.value, false);
    return { ...value, direction: direction.value === 'auto' ? value.direction : direction.value as 'ltr' | 'rtl' };
}
function currentURL(selected: Story): string {
    const params = new URLSearchParams({ story: selected.id, kind: selected.kind, variant: selected.variant, state: selected.state, locale: locale.value, theme: theme.value, width: width.value, direction: direction.value });
    return '?' + params.toString();
}
function syncURL(push = false): void { if (story)
    history[push ? 'pushState' : 'replaceState'](null, '', currentURL(story)); }
function navigation(): void {
    const search = byId<HTMLInputElement>('search').value.trim().toLowerCase();
    const nav = byId('stories');
    nav.replaceChildren();
    for (const group of ['Components', copy.composed_examples, copy.agent_scenarios]) {
        const matches = data.stories.filter(s => s.group === group && search.split(/\s+/).every(term => `${s.kind} ${s.variant} ${s.state} ${s.id}`.toLowerCase().includes(term)));
        if (!matches.length)
            continue;
        const heading = document.createElement('h2');
        heading.textContent = group;
        nav.append(heading);
        const parent = new Map<string, HTMLElement>();
        for (const item of matches) {
            let target: HTMLElement = nav;
            if (group === 'Components') {
                for (const [key, label] of [[item.kind, item.kind], [item.kind + '/' + item.variant, item.variant]] as const) {
                    let branch = parent.get(key);
                    if (!branch) {
                        const details = document.createElement('details');
                        details.open = !!search || story?.kind === item.kind;
                        const summary = document.createElement('summary');
                        summary.textContent = label;
                        details.append(summary);
                        target.append(details);
                        parent.set(key, details);
                        branch = details;
                    }
                    target = branch;
                }
            }
            const link = document.createElement('a');
            link.href = currentURL(item);
            link.dataset.storyId = item.id;
            link.textContent = group === 'Components' ? item.state + (item.outcome === 'refused' ? ' · refused' : '') : item.variant.replaceAll('_', ' ').replaceAll('-', ' ');
            if (item.id === story?.id)
                link.setAttribute('aria-current', 'page');
            link.onclick = event => { if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey)
                return; event.preventDefault(); if (busy)
                return; choose(item, true); };
            target.append(link);
        }
    }
    byId('count').textContent = data.stories.length + ' stories';
}
function resetEditors(): void {
    if (!story)
        return;
    const value = structuredClone(story.input);
    // A pseudo-locale expands author display literals; formatting still runs in Rust.
    if (locale.value === 'en-XA')
        for (const component of value.snapshot.components)
            for (const key of ['text', 'label', 'title', 'description', 'explanation'])
                if (typeof component[key] === 'string')
                    component[key] = '[ ' + component[key] + ' — ' + component[key] + ' ]';
    input.value = pretty(value);
    model.value = pretty(value.snapshot.dataModel);
}
function choose(selected: Story, push = false): void {
    story = selected;
    byId('category').textContent = selected.group.toUpperCase();
    byId('title').textContent = selected.kind === 'Example' ? 'Composed / ' + selected.variant.replaceAll('_', ' ') : selected.kind === 'Agent' ? 'Agent / ' + selected.variant.replaceAll('-', ' ') : selected.kind;
    byId('subtitle').textContent = selected.id + ' · ' + (selected.outcome === 'refused' ? copy.expected_typed_refusal : copy.live_semantic_story);
    state.replaceChildren();
    for (const sibling of data.stories.filter(s => s.kind === selected.kind && s.variant === selected.variant)) {
        const option = document.createElement('option');
        option.value = sibling.id;
        option.textContent = sibling.state;
        state.append(option);
    }
    state.value = selected.id;
    syncURL(push);
    navigation();
    resetEditors();
    documentation();
    void render();
}
function showRefusal(value: unknown): void { activateTab(byId<HTMLButtonElement>('tab-input')); typedRefusal = value; byId('refusal').hidden = false; byId('refusal').textContent = pretty(value); byId('status').textContent = copy.input_refused; log({ type: 'refusal', value }); }
async function render(): Promise<void> {
    if (busy)
        return;
    busy = true;
    for (const control of [locale, theme, width, direction, state])
        control.disabled = true;
    const generation = ++renderGeneration;
    typedRefusal = undefined;
    const renderButton = byId<HTMLButtonElement>('render');
    renderButton.disabled = true;
    byId('refusal').hidden = true;
    byId('status').textContent = copy.resolving;
    byId('tree').textContent = copy.no_resolved_tree;
    try {
        card?.dispose();
        const root = byId('card');
        root.replaceChildren();
        const p = presentation();
        document.body.dataset.theme = theme.value;
        root.style.width = ({ phone: 360, dock: 480, wide: 960 }[width.value] ?? 480) + 'px';
        byId('canvas-label').textContent = `LIVE CANVAS / ${width.options[width.selectedIndex]?.text} / ${p.locale} / ${p.direction.toUpperCase()}`;
        card = new CardView(root, new URL('./worker.js', import.meta.url), action => log({ type: 'action_frame', action }), slots => {
            byId('slots').textContent = pretty(slots);
            byId('host-note').textContent = slots.length ? `${slots.length} host slot(s) · inspect the host-owned contract below. No authority is granted here.` : '';
        }, message => { log({ type: 'adapter_message', message }); }, p, entry => {
            if (generation !== renderGeneration)
                return;
            if (entry.op === 'refused' && entry.refusal)
                showRefusal(entry.refusal);
            if (entry.op === 'event') {
                log({ type: entry.request ? 'host_event' : 'event_result', ...entry });
                if (entry.reply)
                    queueMicrotask(() => { void readTree(generation); });
            }
        });
        await card.preview(input.value, model.value);
        await readTree(generation);
        byId('status').textContent = copy.ready_admitted;
    }
    catch (error) {
        if (!typedRefusal)
            showRefusal({ type: error instanceof SyntaxError ? 'editor_json' : 'runtime', message: error instanceof Error ? error.message : String(error) });
    }
    finally {
        busy = false;
        renderButton.disabled = false;
        for (const control of [locale, theme, width, direction, state])
            control.disabled = false;
    }
}
async function readTree(generation: number): Promise<void> {
    try {
        const result = await card?.tree();
        if (result && generation === renderGeneration)
            byId('tree').textContent = pretty(result.value);
    }
    catch (error) {
        log({ type: 'tree_unavailable', message: String(error) });
    }
}
// Resolve catalog references for documentation only, never for admission.
function referenced(schema: Record<string, any>): Record<string, any> {
    if (typeof schema.$ref !== 'string')
        return schema;
    const [file, fragment] = schema.$ref.split('#');
    let value: any = file ? data.common : data.catalog;
    for (const part of (fragment ?? '').split('/').filter(Boolean))
        value = value?.[part];
    return value ?? schema;
}
function shape(schema: Record<string, any>, depth = 0): {
    properties: Record<string, any>;
    required: string[];
} {
    if (depth > 8)
        return { properties: {}, required: [] };
    const value = referenced(schema);
    const result = { properties: { ...value.properties }, required: [...value.required ?? []] };
    for (const part of value.allOf ?? []) {
        const child = shape(part, depth + 1);
        Object.assign(result.properties, child.properties);
        result.required.push(...child.required);
    }
    return result;
}
function documentation(): void {
    const panel = byId('docs');
    panel.replaceChildren();
    const heading = document.createElement('h2');
    heading.textContent = 'Catalog / ' + (story?.kind ?? '');
    panel.append(heading);
    const notice = document.createElement('p');
    notice.textContent = copy.catalog_intro;
    panel.append(notice);
    const kinds = story?.group === 'Components' ? [story.kind] : [...new Set(story?.input.snapshot.components.map(c => String(c.component)))];
    for (const kind of kinds) {
        const schema = data.catalog.components[kind];
        if (!schema)
            continue;
        const title = document.createElement('h3');
        title.textContent = kind;
        panel.append(title);
        const details = shape({allOf: [{$ref: 'common_types.json#/$defs/ComponentCommon'}, schema]}), table = document.createElement('table'), head = document.createElement('tr');
        for (const label of ['Property', copy.allowed_values_type, 'Default', 'Limits / notes']) {
            const th = document.createElement('th');
            th.textContent = label;
            head.append(th);
        }
        table.append(head);
        for (const [name, property] of Object.entries(details.properties)) {
            const p = property as Record<string, any>, value = referenced(p), row = document.createElement('tr');
            const constraints = Object.fromEntries(Object.entries(value).filter(([key]) => /^(min|max|pattern|format|oneOf|anyOf|items)/.test(key)));
            for (const text of [name + (details.required.includes(name) ? ' *' : ''), pretty(value.enum ?? value.const ?? value.type ?? p.$ref ?? copy.structured_value), p.default === undefined ? '—' : pretty(p.default), (p.description ?? value.description ?? '') + (Object.keys(constraints).length ? ' ' + pretty(constraints) : '')]) {
                const td = document.createElement('td');
                td.textContent = text;
                row.append(td);
            }
            table.append(row);
        }
        panel.append(table);
        const raw = document.createElement('details'), summary = document.createElement('summary'), pre = document.createElement('pre');
        summary.textContent = copy.complete_catalog_schema;
        pre.textContent = pretty(schema);
        raw.append(summary, pre);
        panel.append(raw);
    }
    const budgets = document.createElement('p');
    budgets.textContent = copy.budgets;
    panel.append(budgets);
}
for (const select of [locale, theme, width, direction])
    select.onchange = () => { if (busy)
        return; syncURL(); navigation(); resetEditors(); void render(); };
state.onchange = () => { const selected = data.stories.find(s => s.id === state.value); if (selected && !busy)
    choose(selected, true); };
byId<HTMLInputElement>('search').oninput = navigation;
byId('render').onclick = () => void render();
byId('reset').onclick = () => { if (!busy) {
    resetEditors();
    void render();
} };
byId('clear-events').onclick = () => { events = []; byId('events').textContent = copy.empty_json; byId('event-count').textContent = copy.zero_count; };
byId('copy-url').onclick = () => { void navigator.clipboard?.writeText(location.href).then(() => { byId('status').textContent = copy.story_link_copied; }).catch(() => { byId('status').textContent = copy.copy_the_story_url_from_the_address_bar; }); };
const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('[role=tab]'));
function activateTab(tab: HTMLButtonElement): void { for (const other of tabs) {
    const active = other === tab;
    other.setAttribute('aria-selected', String(active));
    other.tabIndex = active ? 0 : -1;
    byId(other.getAttribute('aria-controls') ?? '').hidden = !active;
} }
for (const [index, tab] of tabs.entries()) {
    tab.tabIndex = index === 0 ? 0 : -1;
    tab.onclick = () => activateTab(tab);
    tab.onkeydown = event => { let next: number | undefined; if (event.key === 'ArrowRight')
        next = (index + 1) % tabs.length; if (event.key === 'ArrowLeft')
        next = (index + tabs.length - 1) % tabs.length; if (event.key === 'Home')
        next = 0; if (event.key === 'End')
        next = tabs.length - 1; if (next !== undefined) {
        event.preventDefault();
        const selected = tabs[next];
        if (selected) {
            activateTab(selected);
            selected.focus();
        }
    } };
}
window.addEventListener('popstate', () => {
    const query = new URLSearchParams(location.search), selected = data.stories.find(s => s.id === query.get('story'));
    if (!selected)
        return;
    selectKnown(locale, query.get('locale'), 'en');
    selectKnown(theme, query.get('theme'), 'light');
    selectKnown(width, query.get('width'), 'dock');
    selectKnown(direction, query.get('direction'), 'auto');
    choose(selected);
});
window.addEventListener('pagehide', () => card?.dispose(), { once: true });
choose(story);

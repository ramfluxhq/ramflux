// SPDX-License-Identifier: BSD-3-Clause
// Build-time story inventory. IDs are a public cross-host capture contract.
import { readFile } from 'node:fs/promises';
const load = async (path) => JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'));
function expandText(value) {
    if (Array.isArray(value)) {
        for (const item of value)
            expandText(item);
        return;
    }
    if (!value || typeof value !== 'object')
        return;
    for (const [key, child] of Object.entries(value)) {
        if (['text', 'label', 'title', 'description', 'explanation'].includes(key) && typeof child === 'string')
            value[key] = (child + ' — A longer reference message for reviewing wrapping and reading order.').repeat(3);
        else if (key !== 'action' && key !== '@checks')
            expandText(child);
    }
}
export async function galleryData() {
    const index = await load('../host-fixtures/index.json');
    const catalog = await load('../../ramflux-protocol/catalogs/rf-card-v1.json');
    const common = await load('../../ramflux-protocol/vendor/a2ui/specification/v1_0/json/common_types.json');
    const stories = [];
    const add = (id, kind, variant, state, group, input, source, outcome = 'tree') => stories.push({ id, kind, variant, state, group, input, source, outcome });
    for (const row of index.cases) {
        const input = await load('../host-fixtures/' + row.fixture), variant = row.variant ?? 'unset';
        const base = `component/${row.kind}/${variant}`;
        add(base + '/default', row.kind, variant, 'default', 'Components', input, row.fixture, row.outcome);
        if (row.outcome === 'refused')
            continue;
        const states = ['Icon', 'Divider'].includes(row.kind) ? [] : ['long-text'];
        if (row.kind === 'Button')
            states.push('disabled');
        if (['TextField', 'CheckBox', 'ChoicePicker', 'Slider', 'DateTimeInput'].includes(row.kind))
            states.push('error');
        if (['TextField', 'List', 'Table', 'Chart'].includes(row.kind))
            states.push('empty');
        if (row.kind === 'Task')
            states.push('loading');
        for (const state of states) {
            const value = structuredClone(input), root = value.snapshot.components.find(c => c.id === 'root');
            if (state === 'long-text')
                expandText(value.snapshot.components);
            if (state === 'disabled' || state === 'error') {
                value.snapshot.dataModel.galleryValid = false;
                root['@checks'] = [{ condition: { '@path': '/galleryValid' }, message: 'Review the required value before continuing.' }];
            }
            if (state === 'empty') {
                if (row.kind === 'TextField')
                    value.snapshot.dataModel.name = '';
                if (row.kind === 'List') {
                    root.children = [];
                    value.snapshot.components = [root];
                }
                if (row.kind === 'Table')
                    root.rows = [];
                if (row.kind === 'Chart')
                    for (const series of root.series)
                        series.points = [];
            }
            if (state === 'loading') {
                root.status = 'pending';
                root.progress = null;
                root.steps = [];
            }
            add(base + '/' + state, row.kind, variant, state, 'Components', value, row.fixture);
        }
    }
    for (const name of ['approval', 'chart', 'form', 'complete_form', 'task'])
        add(`example/${name}`, 'Example', name, 'default', 'Composed examples', await load('../fixtures/' + name + '.json'), 'fixtures/' + name + '.json');
    for (const [variant, file] of [['approval-request', 'approval'], ['permission-request', 'approval'], ['task-progress', 'task']]) {
        const input = await load('../fixtures/' + file + '.json'), root = input.snapshot.components.find(c => c.id === 'root');
        if (file === 'approval') {
            root.requestRef = 'gallery-' + variant;
            root.explanation = variant === 'permission-request' ? 'The agent requests permission to read a selected project folder. Host-verified facts and approval controls belong to the native host.' : 'The agent requests approval to publish the prepared release. Review the host-owned request record before deciding.';
        }
        else {
            root.title = 'Prepare release notes';
            root.progress = 64;
            root.steps = [{ id: 'collect', text: 'Collect changes', status: 'completed' }, { id: 'summarize', text: 'Summarize changes', status: 'running' }];
        }
        add(`agent/${variant}`, 'Agent', variant, 'default', 'Agent scenarios', input, 'fixtures/' + file + '.json');
    }
    return { schema: 'ramflux.card.stories.v1', stories, catalog, common };
}

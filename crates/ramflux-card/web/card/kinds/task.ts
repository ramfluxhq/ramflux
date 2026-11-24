// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, chip, button, disclosure, skeleton } from '../parts/primitives';
import { icon } from './icon';
export const render: KindRenderer = (n, c) => {
    const a = n.attrs, e = el('section', 'rf-task'), state = String(a.status ?? 'pending'), labels: Record<string, string> = { pending: 'Waiting to start', delivered: 'Delivered', running: 'Running', completed: 'Completed', refused: 'Refused', cancelled: 'Cancelled' };
    e.append(el('span', 'rf-host-label', 'AGENT-REPORTED ACTIVITY'), chip(labels[state] ?? state, state === 'completed' ? 'success' : state === 'refused' ? 'danger' : 'neutral'), el('h2', 'rf-card__title', 'Nova · ' + String(a.title ?? 'Prepare release notes')), el('p', 'rf-secondary', 'Requested by Lin · message at 10:40'));
    if (state === 'pending' && !a.steps?.length && a.progress == null)
        e.append(skeleton());
    else {
        const progress = el('div', 'rf-task__progress'), track = el('div', 'rf-task__track'), fill = el('span', 'rf-task__fill');
        track.setAttribute('role', 'progressbar');
        track.setAttribute('aria-label', 'Task progress');
        track.setAttribute('aria-valuemin', '0');
        track.setAttribute('aria-valuemax', '100');
        if (typeof a.progress === 'number') {
            fill.style.inlineSize = a.progress + '%';
            track.setAttribute('aria-valuenow', String(a.progress));
            progress.append(el('span', 'rf-meta', a.progress + ' %'));
        }
        else
            track.classList.add('rf-task__track--indeterminate');
        track.append(fill);
        progress.prepend(track);
        e.append(progress);
    }
    const steps = el('ol', 'rf-task__steps');
    const list = a.steps as {
        text: string;
        status: string;
    }[] ?? [];
    for (const step of list) {
        const row = el('li', 'rf-task__step');
        row.dataset.status = step.status;
        row.append(icon(step.status === 'completed' ? 'checkCircle' : step.status === 'refused' ? 'cancel' : 'schedule'), el('span', 'rf-secondary', step.text));
        steps.append(row);
    }
    if (list.length > 3) {
        const summary = el('div', 'rf-task__step-preview');
        let index = list.findIndex(s => s.status === 'running');
        if (index < 0)
            index = 0;
        for (const row of Array.from(steps.children).slice(index, index + 2))
            summary.append(row.cloneNode(true));
        e.append(summary, disclosure('Steps (' + list.filter(s => s.status === 'completed').length + ' of ' + list.length + ')', steps));
    }
    else
        e.append(steps);
    if (state === 'completed')
        e.append(el('p', 'rf-secondary', 'Result: Release notes are ready to review.'));
    if (state === 'refused')
        e.append(el('p', 'rf-secondary', 'The task ended. Steps are kept.'));
    const actions = el('div', 'rf-actions');
    if (['running', 'pending'].includes(state)) {
        const cancel = button('Cancel', () => c.options.onReference?.({ type: 'reference_task_cancel' }));
        cancel.disabled = c.readOnly;
        actions.append(cancel);
    }
    const details = button('Details', () => { const body = el('div', 'rf-column'); body.append(el('h3', 'rf-card__title', String(a.title ?? 'Prepare release notes')), steps.cloneNode(true), el('p', 'rf-secondary', 'Agent-reported activity · reference presentation')); c.overlay('Task details', body, details); });
    actions.append(details);
    e.append(actions);
    return e;
};

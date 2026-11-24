// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, chip, button, disclosure, tip } from '../parts/primitives';
import { icon } from './icon';
export const render: KindRenderer = (n, c) => {
    const e = el('section', 'rf-approval'), slot = c.slots.find(s => s.kind === 'approval' && s.key === n.key);
    if (!c.options.referenceHost) {
        e.append(tip('Approval controls are supplied by the host.'), el('blockquote', 'rf-secondary', String(n.attrs.explanation ?? '')));
        return e;
    }
    const facts = slot?.facts as {
        requester?: string;
        action?: string;
        scope?: {
            name: string;
            value: string;
        }[];
        risk?: string;
        expires_at?: number;
    } | undefined;
    const state = c.options.state ?? 'pending', resolved = ['approved', 'denied', 'expired', 'superseded', 'withdrawn'].includes(state), permission = String(n.attrs.requestRef).includes('permission');
    e.setAttribute('aria-label', (facts?.action ?? (permission ? 'Allow Nova to read the Project folder' : 'Read the Research folder')) + ' · ' + state);
    e.setAttribute('role', 'region');
    e.append(el('div', 'rf-host-label', 'REFERENCE HOST PRESENTATION · ' + (facts ? 'host facts' : 'mock facts')));
    const head = el('div', 'rf-approval__heading');
    head.append(el('h2', 'rf-card__title', facts?.action ?? (permission ? 'Allow Nova to read the Project folder' : 'Read the “Research” folder')), chip(({ approved: 'Allowed', denied: 'Denied', expired: 'Expired', superseded: 'Replaced', withdrawn: 'Withdrawn' } as Record<string, string>)[state] ?? 'Waiting for you'));
    e.append(head);
    if (n.attrs.taskBinding)
        e.append(el('p', 'rf-secondary', 'Step 2 of task Prepare release notes'));
    const inset = el('div', 'rf-card__inset');
    inset.append(el('strong', 'rf-secondary', 'Scope of this request'));
    const scope = facts?.scope ?? [{ name: 'Tool', value: 'File read' }, { name: 'Access', value: 'Read only' }, { name: 'Duration', value: permission ? 'Until revoked' : 'This request only' }];
    inset.append(el('p', 'rf-secondary', scope.map(row => row.name + ': ' + row.value).join(' · ')));
    const risk = el('div', 'rf-approval__risk'), level = facts?.risk ?? (state === 'high-risk' ? 'High' : state === 'medium-risk' ? 'Medium' : 'Low');
    const riskChip = chip(level, level.toLowerCase() === 'high' ? 'danger' : level.toLowerCase() === 'medium' ? 'warning' : 'neutral');
    riskChip.prepend(icon(level.toLowerCase() === 'low' ? 'info' : 'warning'));
    const countdown = el('span', 'rf-meta', 'Expires in 4:59');
    countdown.setAttribute('role', 'timer');
    if (resolved)
        countdown.textContent = state === 'expired' ? 'Expired at 10:42' : 'Request recorded at 10:40';
    else
        countdown.dataset.expires = String(facts?.expires_at ?? Math.floor(Date.now() / 1000) + 299);
    risk.append(riskChip, countdown);
    inset.append(risk);
    e.append(inset);
    const quote = el('blockquote', 'rf-approval__explanation', 'The agent says: “' + String(n.attrs.explanation ?? 'Read the project notes to prepare a release summary.') + '”');
    if (quote.textContent && quote.textContent.length > 180) {
        const more = button('Read more', () => { quote.classList.toggle('rf-approval__explanation--expanded'); }, 'borderless');
        e.append(quote, more);
    }
    else
        e.append(quote);
    const args = el('div', 'rf-card__inset');
    for (const [k, v] of [['Path', '/Project/Research'], ['Operation', 'read'], ['Requester', facts?.requester ?? 'Nova']]) {
        const row = el('div', 'rf-fact');
        row.append(el('strong', 'rf-secondary', k), el('code', 'rf-secondary', v));
        args.append(row);
    }
    e.append(disclosure('Show details', args));
    if (resolved) {
        e.append(el('p', 'rf-secondary', ({ approved: 'Lin allowed · 10:42', denied: 'Lin denied · 10:42 · Nova did not run this step', expired: 'Expired at 10:42 · no decision was made', superseded: 'Replaced by a newer request · 10:42', withdrawn: 'Nova withdrew the request · 10:42' } as Record<string, string>)[state]));
        if (state === 'superseded')
            e.append(button('Go to the new request', () => c.options.onReference?.({ type: 'replacement_reference' }), 'borderless'));
    }
    else if (c.options.owner || state === 'other-owner')
        e.append(el('p', 'rf-secondary', 'Waiting for ' + (c.options.owner ?? 'Zhou Ning') + ' to decide'));
    else {
        const actions = el('div', 'rf-actions');
        const deny = button('Deny', () => c.options.onReference?.({ type: 'reference_decision', outcome: 'denied' }));
        const allow = button('Allow', () => { const body = el('div', 'rf-column'); body.append(tip('Reference only · no request is authorized or dispatched.'), el('h3', 'rf-card__title', facts?.action ?? 'Read the “Research” folder'), inset.cloneNode(true)); body.append(button('Confirm', () => c.options.onReference?.({ type: 'reference_decision', outcome: 'approved' }), 'primary')); c.overlay('Confirm request · reference host', body, allow); }, 'primary');
        deny.disabled = allow.disabled = c.readOnly;
        actions.append(deny, allow);
        e.append(actions);
    }
    return e;
};

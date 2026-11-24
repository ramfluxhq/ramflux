// SPDX-License-Identifier: BSD-3-Clause
import type { HostPresentation } from '../settings';
import spec from './render-metrics.json';
export function tokens(root: HTMLElement, presentation: HostPresentation): void {
    for (const [name, value] of Object.entries(presentation.tokens))
        root.style.setProperty('--rf-' + name, typeof value === 'number' ? value + 'px' : value);
    for (const [name, value] of Object.entries(spec.foundations.type_styles))
        if (typeof value === 'object' && 'size' in value) {
            root.style.setProperty('--rf-type-' + name.replaceAll('.', '-'), `${value.size}px`);
            root.style.setProperty('--rf-line-' + name.replaceAll('.', '-'), `${value.line}px`);
        }
    const flatten = (value: unknown, path: string[]) => { if (typeof value === 'number')
        root.style.setProperty('--rf-spec-' + path.join('-'), value + 'px');
    else if (value && typeof value === 'object' && !Array.isArray(value))
        for (const [key, child] of Object.entries(value))
            flatten(child, [...path, key]); };
    flatten(spec, []);
    root.lang = presentation.locale;
    root.dir = presentation.direction;
}
export const metrics = spec;

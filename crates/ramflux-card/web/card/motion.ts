// SPDX-License-Identifier: BSD-3-Clause
import { metrics } from './tokens';
export function motion(root: HTMLElement): void {
    const motion = metrics.foundations.motion;
    for (const [name, value] of Object.entries(motion.easing))
        root.style.setProperty('--rf-ease-' + name, String(value));
    for (const [name, value] of Object.entries(motion)) {
        const duration = typeof value === 'number' ? value : typeof value === 'object' && 'ms' in value ? value.ms : undefined;
        if (typeof duration === 'number')
            root.style.setProperty('--rf-motion-' + name, duration + 'ms');
    }
}

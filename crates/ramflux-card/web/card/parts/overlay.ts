// SPDX-License-Identifier: BSD-3-Clause
import { el, button } from './primitives';
export class Overlay {
    private active?: {
        element: HTMLElement;
        close: (notify?: boolean) => void;
    };
    constructor(private root: HTMLElement) { }
    close(notify = true): void { this.active?.close(notify); }
    open(title: string, body: HTMLElement, trigger: HTMLElement, onClose?: () => void): void {
        this.close(false);
        if (trigger.getAttribute('role') === 'combobox')
            trigger.setAttribute('aria-expanded', 'true');
        const scrim = el('div', 'rf-sheet__scrim'), sheet = el('section', 'rf-sheet');
        sheet.setAttribute('role', 'dialog');
        sheet.setAttribute('aria-modal', 'true');
        sheet.setAttribute('aria-label', title);
        sheet.tabIndex = -1;
        const oldFocus = document.activeElement as HTMLElement | null;
        const parent = this.root.parentElement;
        const siblings = parent ? Array.from(parent.children).filter((e): e is HTMLElement => e instanceof HTMLElement && e !== this.root) : [];
        const inert = siblings.map(e => e.inert);
        for (const e of siblings)
            e.inert = true;
        const close = (notify = true) => { if (trigger.getAttribute('role') === 'combobox')
            trigger.setAttribute('aria-expanded', 'false'); scrim.remove(); this.active = undefined; for (const [i, e] of siblings.entries())
            e.inert = inert[i] ?? false; (trigger.isConnected ? trigger : oldFocus)?.focus(); if (notify)
            onClose?.(); };
        const header = el('div', 'rf-sheet__header');
        header.append(el('h2', 'rf-sheet__title', title), button('×', () => close(), 'icon'));
        sheet.append(el('span', 'rf-sheet__handle'), header, body);
        scrim.append(sheet);
        this.root.append(scrim);
        this.active = { element: scrim, close };
        scrim.onclick = e => { if (e.target === scrim)
            close(); };
        sheet.onkeydown = e => { if (e.key === 'Escape') {
            e.preventDefault();
            close();
        } if (e.key === 'Tab') {
            const focusable = Array.from(sheet.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), textarea:not(:disabled), [tabindex="0"], summary'));
            const first = focusable[0] ?? sheet, last = focusable.at(-1) ?? sheet;
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            }
            else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        } };
        let y = 0;
        sheet.addEventListener('touchstart', e => { y = e.touches[0]?.clientY ?? 0; }, { passive: true });
        sheet.addEventListener('touchend', e => { if ((e.changedTouches[0]?.clientY ?? 0) - y > 100)
            close(); }, { passive: true });
        (sheet.querySelector<HTMLElement>('button,input,[tabindex="0"]') ?? sheet).focus();
    }
}

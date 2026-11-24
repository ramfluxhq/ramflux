// SPDX-License-Identifier: BSD-3-Clause
// Preserve the gallery's native value model; draw and operate the menu ourselves.
export function toolbarSelect(select: HTMLSelectElement): void { select.hidden = true; select.tabIndex = -1; const trigger = document.createElement('button'); trigger.type = 'button'; trigger.className = 'gallery-picker'; trigger.setAttribute('role', 'combobox'); trigger.setAttribute('aria-haspopup', 'listbox'); trigger.setAttribute('aria-expanded', 'false'); select.after(trigger); const update = () => { trigger.textContent = (select.selectedOptions[0]?.textContent ?? 'Choose') + ' ⌄'; trigger.disabled = select.disabled; trigger.setAttribute('aria-label', (select.parentElement?.firstChild?.textContent ?? 'Setting') + ': ' + trigger.textContent); }; let menu: HTMLElement | undefined; const close = () => { menu?.remove(); menu = undefined; trigger.setAttribute('aria-expanded', 'false'); }; trigger.onclick = () => { if (menu) {
    close();
    return;
} menu = document.createElement('div'); menu.className = 'gallery-picker__menu'; menu.setAttribute('role', 'listbox'); trigger.setAttribute('aria-expanded', 'true'); for (const option of select.options) {
    const item = document.createElement('button');
    item.type = 'button';
    item.textContent = option.textContent;
    item.setAttribute('role', 'option');
    item.setAttribute('aria-selected', String(option.selected));
    item.onclick = () => { select.value = option.value; select.dispatchEvent(new Event('change')); update(); close(); trigger.focus(); };
    item.onkeydown = e => { const items = Array.from(menu?.querySelectorAll('button') ?? []); const index = items.indexOf(item); if (e.key === 'Escape') {
        close();
        trigger.focus();
    } if (e.key === 'ArrowDown') {
        e.preventDefault();
        items[(index + 1) % items.length]?.focus();
    } if (e.key === 'ArrowUp') {
        e.preventDefault();
        items[(index + items.length - 1) % items.length]?.focus();
    } };
    menu.append(item);
} trigger.after(menu); menu.querySelector<HTMLElement>('[aria-selected=true]')?.focus(); }; document.addEventListener('pointerdown', e => { if (e.target instanceof Node && !trigger.parentElement?.contains(e.target))
    close(); }); new MutationObserver(update).observe(select, { attributes: true, childList: true, subtree: true }); select.addEventListener('change', update); update(); }

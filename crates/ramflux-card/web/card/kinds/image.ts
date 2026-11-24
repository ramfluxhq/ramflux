// SPDX-License-Identifier: BSD-3-Clause
import type { KindRenderer } from '../types';
import { el, button } from '../parts/primitives';
import { icon } from './icon';
export const render: KindRenderer = (n, c) => { const a = n.attrs, variant = String(a.variant ?? 'mediumFeature'), desc = String(a.description ?? 'Attachment'), state = c.options.state; const frame = button('', () => { const body = el('div', 'rf-image__expanded'); if (c.options.imageURL) {
    const img = el('img');
    img.src = c.options.imageURL;
    img.alt = desc;
    body.append(img);
}
else
    body.append(icon('photo')); body.append(el('p', 'rf-secondary', desc)); c.overlay('Image · reference host slot', body, frame); }, 'borderless'); frame.disabled = c.options.referenceHost === false; frame.className = 'rf-image rf-image--' + variant; frame.setAttribute('aria-label', desc); frame.title = desc; if (c.options.imageURL && state !== 'loading' && state !== 'failed') {
    const image = el('img');
    image.src = c.options.imageURL;
    image.alt = desc;
    image.style.objectFit = a.fit === 'fit' ? 'contain' : 'cover';
    image.onerror = () => { frame.replaceChildren(icon('photo'), el('span', 'rf-meta', 'Image unavailable')); };
    frame.append(image);
}
else {
    frame.append(icon('photo'));
    if (state === 'failed')
        frame.append(el('span', 'rf-meta', 'Image unavailable'));
    else if (state === 'loading') {
        frame.classList.add('rf-skeleton');
        frame.setAttribute('aria-busy', 'true');
    }
    else
        frame.append(el('span', 'rf-meta', 'Host image slot'));
} return frame; };

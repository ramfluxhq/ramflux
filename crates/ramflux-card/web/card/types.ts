// SPDX-License-Identifier: BSD-3-Clause
import type { HostPresentation } from '../settings';
import type { HostSlot } from '../adapter';
export type CardNode = {
    key: string;
    kind: string;
    component_id: string;
    source_instance: string[];
    scope: string;
    parent_key: string | null;
    slot: {
        slot: string;
        position?: number;
    };
    children: string[];
    attrs: Record<string, any>;
};
export type RenderOptions = {
    referenceHost?: boolean;
    state?: string;
    title?: string;
    owner?: string;
    imageURL?: string;
    onReference?: (entry: unknown) => void;
};
export type Context = {
    presentation: HostPresentation;
    options: RenderOptions;
    slots: readonly HostSlot[];
    selected: Map<string, number>;
    touched: Set<string>;
    readOnly: boolean;
    render: (key: string) => HTMLElement;
    event: (key: string, event: {
        kind: string;
        value?: unknown;
        index?: number;
    }) => void;
    rerender: () => void;
    touch: (key: string) => void;
    overlay: (title: string, body: HTMLElement, trigger: HTMLElement) => void;
    modal: (key: string, trigger: HTMLElement, contentKey: string) => void;
    label: (node: CardNode) => string;
};
export type KindRenderer = (node: CardNode, ctx: Context) => HTMLElement;

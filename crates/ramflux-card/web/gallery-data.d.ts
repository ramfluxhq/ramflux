// SPDX-License-Identifier: BSD-3-Clause
declare module 'gallery-data' {
    type Input = {
        snapshot: {
            components: Record<string, any>[];
            dataModel: unknown;
        };
        [key: string]: unknown;
    };
    type Story = {
        id: string;
        kind: string;
        variant: string;
        state: string;
        group: string;
        source: string;
        outcome: string;
        input: Input;
    };
    const data: {
        schema: string;
        stories: Story[];
        catalog: Record<string, any>;
        common: Record<string, any>;
    };
    export default data;
}

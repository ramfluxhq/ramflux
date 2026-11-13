// SPDX-License-Identifier: BSD-3-Clause
// Project-owned semantic JSX, without a browser or framework runtime.
declare function __rf_commit(tree: string): void;
type Kind = "column" | "form" | "text_field" | "submit";
type Node = { key: string; kind: Kind; text: string; value: string; action: string | null; children: Node[] };
type Props = { key: string; text?: string; value?: string; action?: string };
type Form = Readonly<{ id: string; title: string; label: string; value: string; submit: string }>;
declare global { namespace JSX { interface IntrinsicElements {
  column: Props; form: Props; text_field: Props; submit: Props;
} } }
function h(kind: Kind, props: Props, ...children: Node[]): Node {
  return { kind, key: props.key, text: props.text ?? "", value: props.value ?? "",
    action: props.action ?? null, children: children.flat() };
}
export function render(input: string): void {
  const forms: Form[] = JSON.parse(input);
  for (const form of forms) Object.freeze(form);
  Object.freeze(forms);
  const children = forms.map(form => <form key={form.id} text={form.title}>
    <text_field key={form.id + ":field"} text={form.label} value={form.value} />
    <submit key={form.id + ":submit"} text={form.submit} action={form.submit} />
  </form>);
  __rf_commit(JSON.stringify({ root: <column key="root">{children}</column> }));
}

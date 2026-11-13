// SPDX-License-Identifier: BSD-3-Clause
// form.tsx
function h(kind, props, ...children) {
  return {
    kind,
    key: props.key,
    text: props.text ?? "",
    value: props.value ?? "",
    action: props.action ?? null,
    children: children.flat()
  };
}
function render(input) {
  const forms = JSON.parse(input);
  for (const form of forms) Object.freeze(form);
  Object.freeze(forms);
  const children = forms.map((form) => /* @__PURE__ */ h("form", { key: form.id, text: form.title }, /* @__PURE__ */ h("text_field", { key: form.id + ":field", text: form.label, value: form.value }), /* @__PURE__ */ h("submit", { key: form.id + ":submit", text: form.submit, action: form.submit })));
  __rf_commit(JSON.stringify({ root: /* @__PURE__ */ h("column", { key: "root" }, children) }));
}
export {
  render
};

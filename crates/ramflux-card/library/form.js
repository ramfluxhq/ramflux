// SPDX-License-Identifier: BSD-3-Clause
// primitives.ts
var tokens;
function setTokens(value) {
  tokens = value;
}
function node(kind, id, text = "", value = "", children = []) {
  return { key: id, kind, text, value, action: null, children };
}
function control(kind, p) {
  const n = node(kind, p.id, p.label ?? p.text ?? p.title ?? "", typeof p.value === "number" ? p.value.toString() : p.value ?? "");
  n.attrs = {
    required: p.required,
    disabled: p.disabled,
    error: p.error,
    options: p.options,
    style: { color: p.color ?? tokens.text, background: p.background, border: p.border, gap: p.gap === void 0 ? void 0 : tokens.gap, padding: p.padding === void 0 ? void 0 : tokens.gap }
  };
  return n;
}
function Text(p) {
  return control("text", p);
}
function TextField(p) {
  return control("text_field", p);
}
function Select(p) {
  return control("select", p);
}
function Toggle(p) {
  const n = control("toggle", p);
  n.value = p.checked ? "true" : "false";
  return n;
}
function Submit(p) {
  const n = control("submit", p);
  n.action = p.event?.action ?? null;
  return n;
}
function Progress(p) {
  const n = control("progress", p);
  n.value = "";
  n.attrs = { ...n.attrs, progress: typeof p.value === "number" ? p.value : void 0 };
  return n;
}
function Table(p) {
  const n = control("table", p);
  const columns = p.columns ?? [];
  n.attrs = { ...n.attrs, columns: columns.map((c) => c.label), rows: (p.rows ?? []).map((r) => columns.map((c) => readCell(r.cells, c.id))) };
  return n;
}
function ChartFrame(p, ...children) {
  const n = control("chart", p);
  n.children = children;
  return n;
}
function readCell(record, key) {
  if (key === "constructor" || key === "prototype" || key === "__proto__") return "";
  return record[key] ?? "";
}

// ../../../src/generated/RFCardComponents.tsx
function RFCardText(props) {
  return Text({ id: props.id, text: props.text, color: props.theme.text });
}
function RFCardField(props) {
  return TextField({
    id: props.id,
    label: props.label,
    value: props.value,
    required: props.required,
    disabled: props.disabled,
    error: props.error,
    event: props.event,
    background: props.theme.surface_white
  });
}
function RFCardSelect(props) {
  return Select({
    id: props.id,
    label: props.label,
    value: props.value,
    options: props.options,
    disabled: props.disabled,
    event: props.event,
    background: props.theme.surface_white
  });
}
function RFCardToggle(props) {
  return Toggle({
    id: props.id,
    label: props.label,
    checked: props.checked,
    disabled: props.disabled,
    event: props.event,
    color: props.theme.primary
  });
}
function RFCardButton(props) {
  return Submit({
    id: props.id,
    label: props.label,
    disabled: props.disabled,
    event: props.event,
    background: props.kind === "danger" ? props.theme.danger : props.kind === "primary" ? props.theme.primary : props.theme.surface_white,
    color: props.kind === "secondary" ? props.theme.text : props.theme.on_primary
  });
}
function RFCardProgress(props) {
  return Progress({ id: props.id, label: props.label, value: props.value, color: props.theme.primary });
}
function RFCardTable(props) {
  return Table({
    id: props.id,
    label: props.label,
    columns: props.columns,
    rows: props.rows,
    border: props.theme.line,
    gap: 16,
    padding: 20
  });
}
function RFCardChartFrame(props) {
  return ChartFrame({
    id: props.id,
    title: props.title,
    summary: props.summary,
    background: props.theme.surface_white,
    border: props.theme.line,
    padding: 16
  }, ...props.content);
}

// format.ts
function format(pattern, values) {
  const pieces = pattern.split("{");
  const first = pieces.shift() ?? "";
  return first + pieces.map((piece) => {
    const close = piece.indexOf("}");
    if (close < 0) return "{" + piece;
    const name = piece.slice(0, close);
    return (values.find((value) => value[0] === name)?.[1] ?? "") + piece.slice(close + 1);
  }).join("");
}
function grouped(value, separator) {
  const raw = value.toString(), negative = raw.startsWith("-"), digits = negative ? raw.slice(1) : raw;
  return (negative ? "-" : "") + digits.split("").map((c, index) => (index > 0 && (digits.length - index) % 3 === 0 ? separator : "") + c).join("");
}

// form.tsx
function label(status, strings) {
  switch (status) {
    case "pending":
      return strings.task_pending;
    case "delivered":
      return strings.task_delivered;
    case "running":
      return strings.task_running;
    case "completed":
      return strings.task_completed;
    case "refused":
      return strings.task_refused;
    case "cancelled":
      return strings.task_cancelled;
    default:
      return "";
  }
}
function form(c, theme, strings) {
  const children = c.resolved_fields.map(({ field: f, value }) => {
    const id = c.id + ":" + f.id;
    const disabled = c.disabled || f.disabled;
    const event = {};
    const text = typeof value === "string" ? value : value.toString();
    let n = f.kind === "select" ? RFCardSelect({ id, label: f.label, value: text, options: f.options, disabled, event, theme }) : f.kind === "toggle" ? RFCardToggle({ id, label: f.label, checked: value === true, disabled, event, theme }) : RFCardField({ id, label: f.label, value: text, required: f.required, disabled, error: f.error ?? void 0, event, theme });
    if (f.kind === "number") n.kind = "number";
    n.attrs = {
      ...n.attrs,
      required: f.required,
      disabled,
      error: f.error ?? void 0,
      options: f.options,
      minimum: f.minimum ?? void 0,
      maximum: f.maximum ?? void 0
    };
    return n;
  });
  children.push(RFCardButton({ id: c.id + ":submit", label: strings.form_submit, kind: "primary", disabled: c.disabled, event: { action: c.submit }, theme }));
  return node("form", c.id, c.title, "", children);
}
function task(c, theme, strings) {
  const status = label(c.status, strings);
  const progress = RFCardProgress({ id: c.id + ":progress", label: status, value: c.progress ?? void 0, theme });
  progress.attrs = { ...progress.attrs, status };
  return node("task", c.id, c.title, c.task_ref, [
    RFCardText({ id: c.id + ":people", text: format(strings.task_people, [["requester", c.requester], ["owner", c.owner]]), theme }),
    progress,
    ...c.steps.map((s) => {
      const n = RFCardText({ id: c.id + ":step-" + s.id, text: s.text, theme });
      n.attrs = { ...n.attrs, status: label(s.status, strings) };
      return n;
    })
  ]);
}
function scaled(value, scale, unit, strings) {
  return format(scale === 1 ? strings.number_unit : strings.number_scaled, [["value", grouped(value, strings.number_group)], ["scale", grouped(scale, strings.number_group)], ["unit", unit]]).trim();
}
function chart(c, theme, strings) {
  const first = c.series[0];
  if (!first) return node("chart", c.id, c.title);
  const columns = [{ id: "@label", label: strings.chart_label }, ...c.series.map((s, index) => ({ id: s.id, label: s.label }))];
  const rows = first.points.map((point, index) => ({ id: point.label, cells: c.series.reduce((cells, series) => {
    const current = series.points.find((_p, i) => i === index);
    return { ...cells, [series.id]: current ? scaled(current.value, c.scale, c.unit, strings) : "" };
  }, { "@label": point.label }) }));
  const table = RFCardTable({ id: c.id + ":table", label: format(strings.chart_table, [["title", c.title]]), columns, rows, theme });
  const design = RFCardText({ id: c.id + ":design", text: strings.chart_pending, theme });
  const n = RFCardChartFrame({ id: c.id, title: c.title, summary: strings.chart_summary, content: [design, table], theme });
  n.attrs = { ...n.attrs, style: { ...n.attrs?.style, color: theme.chart_1 }, plot: { kind: c.kind, unit: c.unit, scale: c.scale, series: c.series } };
  return n;
}
function render(input) {
  const data = JSON.parse(input);
  const theme = data.presentation.tokens, strings = data.presentation.strings;
  setTokens(theme);
  const children = data.components.map((c) => {
    if (c.component === "rf.form") return form(c, theme, strings);
    if (c.component === "rf.task") return task(c, theme, strings);
    if (c.component === "rf.chart") return chart(c, theme, strings);
    return node("approval_info", c.id, strings.approval_heading, "", c.explanation ? [RFCardText({ id: c.id + ":explanation", text: c.explanation, theme })] : []);
  });
  __rf_commit(JSON.stringify({ root: node("column", "root", "", "", children) }));
}
export {
  render
};

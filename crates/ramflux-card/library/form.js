// SPDX-License-Identifier: BSD-3-Clause
// primitives.ts
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
    style: { color: p.color, background: p.background, border: p.border, gap: p.gap, padding: p.padding }
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
  n.attrs = { ...n.attrs, columns: columns.map((c) => c.label), rows: (p.rows ?? []).map((r) => columns.map((c) => (c.id === "label" ? r.cells.label : c.id === "first" ? r.cells.first : r.cells.second) ?? "")) };
  return n;
}
function ChartFrame(p, ...children) {
  const n = control("chart", p);
  n.children = children;
  return n;
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

// ../../../src/generated/rf-tokens.ts
var light = Object.freeze({
  accent: "#161616",
  agent_av: "#222224",
  avatar_person: "#E7E7E7",
  badge: "#222224",
  bg: "#FCFBF9",
  bubble_max: 600,
  chart_1: "#2A78D6",
  chart_2: "#EB6834",
  column_max: 880,
  composer_min: 48,
  control: "#8E8E8E",
  danger: "#C62828",
  danger_bg: "#FCEBEB",
  focus: "#222224",
  font: "Noto Sans SC",
  font_latin: "Hanken Grotesk",
  font_mono: "JetBrains Mono",
  font_serif: "Hanken Grotesk",
  gap: 16,
  incoming: "#EFEFEF",
  incoming_meta: "#5C5C5C",
  incoming_quote: "#E3E3E3",
  input: "#FFFFFF",
  input_border: "#E0E0E0",
  line: "#E6E6E6",
  line_nav: "#E2E2E1",
  line_soft: "#EFEFEF",
  line_strong: "#D4D4D4",
  menu_item_height: 38,
  mobile_bubble_max: 300,
  nav: "#F5F4F1",
  on_accent: "#FFFFFF",
  on_agent_av: "#FFFFFF",
  on_avatar_person: "#161616",
  on_badge: "#FFFFFF",
  on_danger: "#FFFFFF",
  on_primary: "#FFFFFF",
  on_success: "#FFFFFF",
  on_tooltip: "#FFFFFF",
  outgoing: "#222224",
  outgoing_meta: "#ABABAB",
  outgoing_quote: "#343436",
  outgoing_text: "#F6F6F6",
  overlay: "#FFFFFF",
  overlay_border: "#E2E2E2",
  primary: "#222224",
  radius_bubble: 12,
  radius_bubble_joined: 4,
  radius_button: 4,
  radius_card: 8,
  radius_chip: 4,
  radius_dialog: 12,
  radius_full: 999,
  radius_input: 4,
  radius_lg: 12,
  radius_md: 8,
  radius_menu: 12,
  radius_sheet: 12,
  radius_sm: 6,
  radius_xl: 16,
  radius_xs: 4,
  rail: "#EDECE8",
  rail_active: "#E2E1DE",
  row_conversation: 64,
  scrim: "#0000004D",
  secondary: "#585858",
  selected: "#E6E5E2",
  shadow: "#0000001F",
  size_body: 15,
  size_button: 14,
  size_caption: 11,
  size_meta: 12,
  size_metric: 32,
  size_mobile_body: 17,
  size_mobile_caption: 11,
  size_mobile_large_title: 32,
  size_page: 24,
  size_secondary: 13,
  size_subheading: 17,
  size_title: 20,
  success: "#2E7D32",
  success_bg: "#E8F2E9",
  surface: "#EFEFEF",
  surface_white: "#FFFFFF",
  text: "#161616",
  tooltip: "#222224",
  warning: "#9A5800",
  warning_bg: "#FBF0DE"
});
var dark = Object.freeze({
  accent: "#EBEBEB",
  agent_av: "#EBEBEB",
  avatar_person: "#2A2A2A",
  badge: "#EBEBEB",
  bg: "#171716",
  bubble_max: 600,
  chart_1: "#3987E5",
  chart_2: "#D95926",
  column_max: 880,
  composer_min: 48,
  control: "#7A7A7A",
  danger: "#FF6B6B",
  danger_bg: "#2E1818",
  focus: "#C8C8C8",
  font: "Noto Sans SC",
  font_latin: "Hanken Grotesk",
  font_mono: "JetBrains Mono",
  font_serif: "Hanken Grotesk",
  gap: 16,
  incoming: "#242424",
  incoming_meta: "#A2A2A2",
  incoming_quote: "#2E2E2E",
  input: "#1C1C1C",
  input_border: "#2C2C2C",
  line: "#262626",
  line_nav: "#1E1E1E",
  line_soft: "#1E1E1E",
  line_strong: "#3A3A3A",
  menu_item_height: 38,
  mobile_bubble_max: 300,
  nav: "#121211",
  on_accent: "#121211",
  on_agent_av: "#121211",
  on_avatar_person: "#EBEBEB",
  on_badge: "#121211",
  on_danger: "#121211",
  on_primary: "#121211",
  on_success: "#121211",
  on_tooltip: "#121211",
  outgoing: "#3A3A3C",
  outgoing_meta: "#C4C4C4",
  outgoing_quote: "#4A4A4C",
  outgoing_text: "#F7F7F7",
  overlay: "#1E1E1E",
  overlay_border: "#303030",
  primary: "#EBEBEB",
  radius_bubble: 12,
  radius_bubble_joined: 4,
  radius_button: 4,
  radius_card: 8,
  radius_chip: 4,
  radius_dialog: 12,
  radius_full: 999,
  radius_input: 4,
  radius_lg: 12,
  radius_md: 8,
  radius_menu: 12,
  radius_sheet: 12,
  radius_sm: 6,
  radius_xl: 16,
  radius_xs: 4,
  rail: "#0D0D0C",
  rail_active: "#222221",
  row_conversation: 64,
  scrim: "#0000008C",
  secondary: "#9E9E9E",
  selected: "#222221",
  shadow: "#0000007A",
  size_body: 15,
  size_button: 14,
  size_caption: 11,
  size_meta: 12,
  size_metric: 32,
  size_mobile_body: 17,
  size_mobile_caption: 11,
  size_mobile_large_title: 32,
  size_page: 24,
  size_secondary: 13,
  size_subheading: 17,
  size_title: 20,
  success: "#5FD27A",
  success_bg: "#14251A",
  surface: "#212121",
  surface_white: "#1E1E1E",
  text: "#EBEBEB",
  tooltip: "#EBEBEB",
  warning: "#F2B94B",
  warning_bg: "#2B2210"
});

// form.tsx
function label(status) {
  return status.charAt(0).toUpperCase() + status.slice(1);
}
function form(c, theme) {
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
  children.push(RFCardButton({ id: c.id + ":submit", label: c.submit, kind: "primary", disabled: c.disabled, event: { action: c.submit }, theme }));
  return node("form", c.id, c.title, "", children);
}
function task(c, theme) {
  const status = label(c.status);
  const progress = RFCardProgress({ id: c.id + ":progress", label: status, value: c.progress ?? void 0, theme });
  progress.attrs = { ...progress.attrs, status };
  return node("task", c.id, c.title, c.task_ref, [
    RFCardText({ id: c.id + ":people", text: "Reported requester: " + c.requester + " \xB7 Reported owner: " + c.owner, theme }),
    progress,
    ...c.steps.map((s) => {
      const n = RFCardText({ id: c.id + ":step-" + s.id, text: s.text, theme });
      n.attrs = { ...n.attrs, status: label(s.status) };
      return n;
    })
  ]);
}
function scaled(value, scale, unit) {
  return (scale === 1 ? value.toString() : value.toString() + " / " + scale.toString()) + (unit ? " " + unit : "");
}
function chart(c, theme) {
  const first = c.series[0];
  if (!first) return node("chart", c.id, c.title);
  const columns = [{ id: "label", label: "Label" }, ...c.series.map((s, index) => ({ id: index === 0 ? "first" : "second", label: s.label }))];
  const second = c.series[1];
  const rows = first.points.map((point, index) => {
    const other = second?.points.find((_p, i) => i === index);
    return {
      id: point.label,
      cells: { label: point.label, first: scaled(point.value, c.scale, c.unit), second: other ? scaled(other.value, c.scale, c.unit) : "" }
    };
  });
  const table = RFCardTable({ id: c.id + ":table", label: c.title + " \u2014 data table", columns, rows, theme });
  const design = RFCardText({ id: c.id + ":design", text: "Chart design pending \xB7 data table available", theme });
  const n = RFCardChartFrame({ id: c.id, title: c.title, summary: "Data table available", content: [design, table], theme });
  n.attrs = { ...n.attrs, style: { ...n.attrs?.style, color: theme.chart_1 }, plot: { kind: c.kind, unit: c.unit, scale: c.scale, series: c.series } };
  return n;
}
function render(input) {
  const data = JSON.parse(input);
  const theme = data.theme === "dark" ? dark : light;
  const children = data.components.map((c) => {
    if (c.component === "rf.form") return form(c, theme);
    if (c.component === "rf.task") return task(c, theme);
    if (c.component === "rf.chart") return chart(c, theme);
    return node("approval_info", c.id, "Request message", "", c.explanation ? [RFCardText({ id: c.id + ":explanation", text: c.explanation, theme })] : []);
  });
  __rf_commit(JSON.stringify({ root: node("column", "root", "", "", children) }));
}
export {
  render
};

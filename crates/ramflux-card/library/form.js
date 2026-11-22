// SPDX-License-Identifier: BSD-3-Clause
// primitives.ts
function Text(n) {
  return { ...n, kind: "Text" };
}
function Icon(n) {
  return { ...n, kind: "Icon" };
}
function Row(n) {
  return { ...n, kind: "Row" };
}
function Column(n) {
  return { ...n, kind: "Column" };
}
function List(n) {
  return { ...n, kind: "List" };
}
function Card(n) {
  return { ...n, kind: "Card" };
}
function Tabs(n) {
  return { ...n, kind: "Tabs" };
}
function Modal(n) {
  return { ...n, kind: "Modal" };
}
function Divider(n) {
  return { ...n, kind: "Divider" };
}
function Button(n) {
  return { ...n, kind: "Button" };
}
function TextField(n) {
  return { ...n, kind: "TextField" };
}
function CheckBox(n) {
  return { ...n, kind: "CheckBox" };
}
function ChoicePicker(n) {
  return { ...n, kind: "ChoicePicker" };
}
function Slider(n) {
  return { ...n, kind: "Slider" };
}
function DateTimeInput(n) {
  return { ...n, kind: "DateTimeInput" };
}
function Image(n) {
  return { ...n, kind: "Image" };
}
function Approval(n) {
  return { ...n, kind: "Approval" };
}
function Task(n) {
  return { ...n, kind: "Task" };
}
function Chart(n) {
  return { ...n, kind: "Chart" };
}
function Table(n) {
  return { ...n, kind: "Table" };
}

// form.tsx
function component(n) {
  switch (n.kind) {
    case "Text":
      return Text(n);
    case "Icon":
      return Icon(n);
    case "Row":
      return Row(n);
    case "Column":
      return Column(n);
    case "List":
      return List(n);
    case "Card":
      return Card(n);
    case "Tabs":
      return Tabs(n);
    case "Modal":
      return Modal(n);
    case "Divider":
      return Divider(n);
    case "Button":
      return Button(n);
    case "TextField":
      return TextField(n);
    case "CheckBox":
      return CheckBox(n);
    case "ChoicePicker":
      return ChoicePicker(n);
    case "Slider":
      return Slider(n);
    case "DateTimeInput":
      return DateTimeInput(n);
    case "Image":
      return Image(n);
    case "Approval":
      return Approval(n);
    case "Task":
      return Task(n);
    case "Chart":
      return Chart(n);
    case "Table":
      return Table(n);
    default:
      throw "component";
  }
}
function render(input) {
  const tree = JSON.parse(input);
  __rf_commit(JSON.stringify({ ...tree, nodes: tree.nodes.map(component) }));
}
export {
  render
};

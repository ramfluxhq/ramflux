// SPDX-License-Identifier: BSD-3-Clause
//! Data/ownership projection used to validate the complete interpreter commit.
use crate::{Attrs, CardError, CardSpec, Component, FieldKind, Node, NodeKind, Plot, Tree};

pub(crate) fn node(kind: NodeKind, key: String, text: String, value: String) -> Node {
    Node { key, kind, text, value, action: None, children: Vec::new(), attrs: Attrs::default() }
}
pub(crate) fn expected(spec: &CardSpec) -> Result<Tree, CardError> {
    let mut root = node(NodeKind::Column, "root".into(), String::new(), String::new());
    for component in &spec.components {
        let mut result = match component {
            Component::Form(form) => {
                let mut form_node =
                    node(NodeKind::Form, form.id.clone(), form.title.clone(), String::new());
                for field in form.normalized_fields() {
                    let value = spec
                        .model
                        .get(field.binding.strip_prefix('/').ok_or(CardError::Invalid("binding"))?)
                        .ok_or(CardError::Invalid("model"))?;
                    let kind = match field.kind {
                        FieldKind::Input => NodeKind::TextField,
                        FieldKind::Number => NodeKind::Number,
                        FieldKind::Select => NodeKind::Select,
                        FieldKind::Toggle => NodeKind::Toggle,
                    };
                    let mut control = node(
                        kind,
                        format!("{}:{}", form.id, field.id),
                        field.label,
                        value.display(),
                    );
                    control.attrs = Attrs {
                        required: field.required,
                        disabled: form.disabled || field.disabled,
                        error: field.error,
                        options: field.options,
                        minimum: field.minimum,
                        maximum: field.maximum,
                        ..Attrs::default()
                    };
                    form_node.children.push(control);
                }
                let mut submit = node(
                    NodeKind::Submit,
                    format!("{}:submit", form.id),
                    form.submit.clone(),
                    String::new(),
                );
                submit.action = Some(form.submit.clone());
                submit.attrs.disabled = form.disabled;
                form_node.children.push(submit);
                form_node
            }
            Component::Task(task) => {
                let mut task_node = node(
                    NodeKind::Task,
                    task.id.clone(),
                    task.title.clone(),
                    task.task_ref.clone(),
                );
                task_node.children.push(node(
                    NodeKind::Text,
                    format!("{}:people", task.id),
                    format!("Requester: {} · Owner: {}", task.requester, task.owner),
                    String::new(),
                ));
                let mut progress = node(
                    NodeKind::Progress,
                    format!("{}:progress", task.id),
                    task.status.label().into(),
                    String::new(),
                );
                progress.attrs.progress = task.progress;
                progress.attrs.status = Some(task.status.label().into());
                task_node.children.push(progress);
                for step in &task.steps {
                    let mut n = node(
                        NodeKind::Text,
                        format!("{}:step-{}", task.id, step.id),
                        step.text.clone(),
                        String::new(),
                    );
                    n.attrs.status = Some(step.status.label().into());
                    task_node.children.push(n);
                }
                task_node
            }
            Component::Chart(chart) => {
                let mut chart_node =
                    node(NodeKind::Chart, chart.id.clone(), chart.title.clone(), String::new());
                chart_node.attrs.plot = Some(Plot {
                    kind: chart.kind,
                    unit: chart.unit.clone(),
                    scale: chart.scale,
                    series: chart.series.clone(),
                });
                chart_node.children.push(node(
                    NodeKind::Text,
                    format!("{}:design", chart.id),
                    "Chart design pending · data table available".into(),
                    String::new(),
                ));
                let mut table = node(
                    NodeKind::Table,
                    format!("{}:table", chart.id),
                    format!("{} — data table", chart.title),
                    String::new(),
                );
                table.attrs.columns.push("Label".into());
                table.attrs.columns.extend(chart.series.iter().map(|s| s.label.clone()));
                let first = chart.series.first().ok_or(CardError::Invalid("chart series"))?;
                for (index, point) in first.points.iter().enumerate() {
                    let mut row = vec![point.label.clone()];
                    for s in &chart.series {
                        let p = s.points.get(index).ok_or(CardError::Invalid("chart point"))?;
                        row.push(scaled(p.value, chart.scale, &chart.unit));
                    }
                    table.attrs.rows.push(row);
                }
                chart_node.children.push(table);
                chart_node
            }
            Component::Approval(approval) => {
                let mut info = node(
                    NodeKind::ApprovalInfo,
                    approval.id.clone(),
                    "Request message".into(),
                    String::new(),
                );
                if !approval.explanation.is_empty() {
                    info.children.push(node(
                        NodeKind::Text,
                        format!("{}:explanation", approval.id),
                        approval.explanation.clone(),
                        String::new(),
                    ));
                }
                info
            }
        };
        result.attrs.style = None;
        root.children.push(result);
    }
    Ok(Tree { root })
}
pub(crate) fn scaled(value: i64, scale: u32, unit: &str) -> String {
    if scale == 1 {
        format!("{value} {unit}").trim().to_owned()
    } else {
        format!("{value} / {scale} {unit}").trim().to_owned()
    }
}

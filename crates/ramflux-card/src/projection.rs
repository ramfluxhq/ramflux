// SPDX-License-Identifier: BSD-3-Clause
//! Data/ownership projection used to validate the complete interpreter commit.
use crate::{Attrs, CardError, CardSpec, Component, FieldKind, Node, NodeKind, Plot, Tree};

pub(crate) fn node(kind: NodeKind, key: String, text: String, value: String) -> Node {
    Node { key, kind, text, value, action: None, children: Vec::new(), attrs: Box::default() }
}
pub(crate) fn expected(spec: &CardSpec) -> Result<Tree, CardError> {
    let presentation = spec.presentation()?;
    let mut root = node(NodeKind::Column, "root".into(), String::new(), String::new());
    for component in &spec.components {
        let mut result = match component {
            Component::Form(value) => form(value, spec)?,
            Component::Task(value) => task(value, &presentation),
            Component::Chart(value) => chart(value, &presentation)?,
            Component::Approval(value) => approval(value, &presentation),
        };
        result.attrs.style = None;
        root.children.push(result);
    }
    Ok(Tree { root })
}
fn form(form: &crate::Form, spec: &CardSpec) -> Result<Node, CardError> {
    let mut form_node = node(NodeKind::Form, form.id.clone(), form.title.clone(), String::new());
    for field in form.fields.clone() {
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
        let mut control =
            node(kind, format!("{}:{}", form.id, field.id), field.label, value.display());
        control.attrs = Box::new(Attrs {
            required: field.required,
            disabled: form.disabled || field.disabled,
            error: field.error,
            options: field.options,
            minimum: field.minimum,
            maximum: field.maximum,
            ..Attrs::default()
        });
        form_node.children.push(control);
    }
    let mut submit = node(
        NodeKind::Submit,
        format!("{}:submit", form.id),
        spec.presentation()?.text("form_submit").into(),
        String::new(),
    );
    submit.action = Some(form.submit.clone());
    submit.attrs.disabled = form.disabled;
    form_node.children.push(submit);
    Ok(form_node)
}

fn task(task: &crate::Task, presentation: &crate::Presentation) -> Node {
    let mut task_node =
        node(NodeKind::Task, task.id.clone(), task.title.clone(), task.task_ref.clone());
    task_node.children.push(node(
        NodeKind::Text,
        format!("{}:people", task.id),
        presentation
            .format("task_people", &[("requester", &task.requester), ("owner", &task.owner)]),
        String::new(),
    ));
    let mut progress = node(
        NodeKind::Progress,
        format!("{}:progress", task.id),
        presentation.text(&format!("task_{}", task.status.key())).into(),
        String::new(),
    );
    progress.attrs.progress = task.progress;
    progress.attrs.status = Some(presentation.text(&format!("task_{}", task.status.key())).into());
    task_node.children.push(progress);
    for step in &task.steps {
        let mut n = node(
            NodeKind::Text,
            format!("{}:step-{}", task.id, step.id),
            step.text.clone(),
            String::new(),
        );
        n.attrs.status = Some(presentation.text(&format!("task_{}", step.status.key())).into());
        task_node.children.push(n);
    }
    task_node
}

fn chart(chart: &crate::Chart, presentation: &crate::Presentation) -> Result<Node, CardError> {
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
        presentation.text("chart_pending").into(),
        String::new(),
    ));
    let mut table = node(
        NodeKind::Table,
        format!("{}:table", chart.id),
        presentation.format("chart_table", &[("title", &chart.title)]),
        String::new(),
    );
    table.attrs.columns.push(presentation.text("chart_label").into());
    table.attrs.columns.extend(chart.series.iter().map(|s| s.label.clone()));
    let first = chart.series.first().ok_or(CardError::Invalid("chart series"))?;
    for (index, point) in first.points.iter().enumerate() {
        let mut row = vec![point.label.clone()];
        for s in &chart.series {
            let p = s.points.get(index).ok_or(CardError::Invalid("chart point"))?;
            row.push(scaled(p.value, chart.scale, &chart.unit, presentation));
        }
        table.attrs.rows.push(row);
    }
    chart_node.children.push(table);
    Ok(chart_node)
}

fn approval(approval: &crate::Approval, presentation: &crate::Presentation) -> Node {
    let mut info = node(
        NodeKind::ApprovalInfo,
        approval.id.clone(),
        presentation.text("approval_heading").into(),
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

pub(crate) fn scaled(
    value: i64,
    scale: u32,
    unit: &str,
    presentation: &crate::Presentation,
) -> String {
    let value = grouped(&value.to_string(), presentation.text("number_group"));
    let scale = grouped(&scale.to_string(), presentation.text("number_group"));
    presentation
        .format(
            if scale == "1" { "number_unit" } else { "number_scaled" },
            &[("value", &value), ("scale", &scale), ("unit", unit)],
        )
        .trim()
        .to_owned()
}
fn grouped(value: &str, separator: &str) -> String {
    let (sign, digits) = value.strip_prefix('-').map_or(("", value), |v| ("-", v));
    let mut out = String::from(sign);
    for (index, c) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push_str(separator);
        }
        out.push(c);
    }
    out
}

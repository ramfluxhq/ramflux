// SPDX-License-Identifier: BSD-3-Clause
//! Closed first-batch presentation data; none of these fields confer authority.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    Text(String),
    Number(i64),
    Toggle(bool),
}
impl From<String> for Scalar {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}
impl From<&str> for Scalar {
    fn from(value: &str) -> Self {
        Self::Text(value.into())
    }
}
impl Scalar {
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Text(v) => v.clone(),
            Self::Number(v) => v.to_string(),
            Self::Toggle(v) => v.to_string(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "component", deny_unknown_fields)]
pub enum Component {
    #[serde(rename = "rf.form")]
    Form(Form),
    #[serde(rename = "rf.task")]
    Task(Task),
    #[serde(rename = "rf.chart")]
    Chart(Chart),
    #[serde(rename = "rf.approval")]
    Approval(Approval),
}
impl Component {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Form(v) => &v.id,
            Self::Task(v) => &v.id,
            Self::Chart(v) => &v.id,
            Self::Approval(v) => &v.id,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Form {
    pub id: String,
    pub title: String,
    pub submit: String,
    /// Legacy one-text-field spelling remains accepted without mixing both shapes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub binding: String,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub disabled: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    #[default]
    Input,
    Number,
    Select,
    Toggle,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub id: String,
    pub label: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub id: String,
    pub kind: FieldKind,
    pub label: String,
    pub binding: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub options: Vec<Choice>,
    #[serde(default)]
    pub minimum: Option<i64>,
    #[serde(default)]
    pub maximum: Option<i64>,
}
impl Form {
    pub(crate) fn normalized_fields(&self) -> Vec<Field> {
        if self.fields.is_empty() && !self.binding.is_empty() {
            vec![Field {
                id: "field".into(),
                kind: FieldKind::Input,
                label: self.label.clone(),
                binding: self.binding.clone(),
                required: false,
                disabled: false,
                error: None,
                options: Vec::new(),
                minimum: None,
                maximum: None,
            }]
        } else {
            self.fields.clone()
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Delivered,
    Running,
    Completed,
    Refused,
    Cancelled,
}
impl TaskStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Delivered => "Delivered",
            Self::Running => "Running",
            Self::Completed => "Completed",
            Self::Refused => "Refused",
            Self::Cancelled => "Cancelled",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub task_ref: String,
    pub requester: String,
    pub owner: String,
    pub status: TaskStatus,
    #[serde(default)]
    pub progress: Option<u8>,
    #[serde(default)]
    pub steps: Vec<TaskStep>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskStep {
    pub id: String,
    pub text: String,
    pub status: TaskStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChartKind {
    Line,
    Bar,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Point {
    pub label: String,
    pub value: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Series {
    pub id: String,
    pub label: String,
    pub points: Vec<Point>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chart {
    pub id: String,
    pub title: String,
    pub kind: ChartKind,
    pub unit: String,
    /// Values are integers; display value = value / scale. No floating point data.
    pub scale: u32,
    pub series: Vec<Series>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub id: String,
    pub request_ref: String,
    #[serde(default)]
    pub task_binding: Option<String>,
    #[serde(default)]
    pub explanation: String,
}
/// Outside the card tree: untrusted references for a host-owned security surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSecuritySlot {
    pub component: String,
    pub request_ref: String,
    pub task_binding: Option<String>,
}

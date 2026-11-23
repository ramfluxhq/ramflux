// SPDX-License-Identifier: BSD-3-Clause
//! Native kinds mirror the sole offline A2UI profile; no executable peer components.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    Text,
    Icon,
    Row,
    Column,
    List,
    Card,
    Tabs,
    Modal,
    Divider,
    Button,
    TextField,
    CheckBox,
    ChoicePicker,
    Slider,
    DateTimeInput,
    Image,
    Approval,
    Task,
    Chart,
    Table,
}

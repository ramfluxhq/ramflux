// SPDX-License-Identifier: BSD-3-Clause
// Each primitive consumes a resolved Rust instance. Peer expressions never run here.
export type CardNode={key:string;kind:string;component_id:string;source_instance:string[];scope:string;
 parent_key:string|null;slot:unknown;children:string[];attrs:Record<string,unknown>};
export function Text(n:CardNode):CardNode{return {...n,kind:"Text"}}
export function Icon(n:CardNode):CardNode{return {...n,kind:"Icon"}}
export function Row(n:CardNode):CardNode{return {...n,kind:"Row"}}
export function Column(n:CardNode):CardNode{return {...n,kind:"Column"}}
export function List(n:CardNode):CardNode{return {...n,kind:"List"}}
export function Card(n:CardNode):CardNode{return {...n,kind:"Card"}}
export function Tabs(n:CardNode):CardNode{return {...n,kind:"Tabs"}}
export function Modal(n:CardNode):CardNode{return {...n,kind:"Modal"}}
export function Divider(n:CardNode):CardNode{return {...n,kind:"Divider"}}
export function Button(n:CardNode):CardNode{return {...n,kind:"Button"}}
export function TextField(n:CardNode):CardNode{return {...n,kind:"TextField"}}
export function CheckBox(n:CardNode):CardNode{return {...n,kind:"CheckBox"}}
export function ChoicePicker(n:CardNode):CardNode{return {...n,kind:"ChoicePicker"}}
export function Slider(n:CardNode):CardNode{return {...n,kind:"Slider"}}
export function DateTimeInput(n:CardNode):CardNode{return {...n,kind:"DateTimeInput"}}
export function Image(n:CardNode):CardNode{return {...n,kind:"Image"}}
export function Approval(n:CardNode):CardNode{return {...n,kind:"Approval"}}
export function Task(n:CardNode):CardNode{return {...n,kind:"Task"}}
export function Chart(n:CardNode):CardNode{return {...n,kind:"Chart"}}
export function Table(n:CardNode):CardNode{return {...n,kind:"Table"}}

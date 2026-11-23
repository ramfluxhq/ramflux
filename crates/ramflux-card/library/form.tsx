// SPDX-License-Identifier: BSD-3-Clause
import {Text,Icon,Row,Column,List,Card,Tabs,Modal,Divider,Button,TextField,CheckBox,ChoicePicker,Slider,DateTimeInput,Image,Approval,Task,Chart,Table} from "./primitives";
import type {CardNode} from "./primitives";
declare function __rf_commit(tree:string):void;
function component(n:CardNode):CardNode {
 switch(n.kind){
 case "Text":return Text(n);case "Icon":return Icon(n);case "Row":return Row(n);case "Column":return Column(n);
 case "List":return List(n);case "Card":return Card(n);case "Tabs":return Tabs(n);case "Modal":return Modal(n);
 case "Divider":return Divider(n);case "Button":return Button(n);case "TextField":return TextField(n);
 case "CheckBox":return CheckBox(n);case "ChoicePicker":return ChoicePicker(n);case "Slider":return Slider(n);
 case "DateTimeInput":return DateTimeInput(n);case "Image":return Image(n);case "Approval":return Approval(n);
 case "Task":return Task(n);case "Chart":return Chart(n);case "Table":return Table(n);
 default:throw "component";
 }
}
export function render(input:string):void {
 const tree=JSON.parse(input) as {nodes:CardNode[]};
 __rf_commit(JSON.stringify({...tree,nodes:tree.nodes.map(component)}));
}

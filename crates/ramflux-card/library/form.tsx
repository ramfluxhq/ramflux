// SPDX-License-Identifier: BSD-3-Clause
import { RFCardField, RFCardSelect, RFCardToggle, RFCardButton, RFCardProgress, RFCardText, RFCardTable, RFCardChartFrame } from "../../../src/generated/RFCardComponents";
import { light, dark } from "../../../src/generated/rf-tokens";
import type { RFTheme } from "../../../src/generated/rf-tokens";
import { node } from "./primitives";
import type { CardNode } from "./primitives";
declare function __rf_commit(tree:string):void;
type Field={id:string;kind:"input"|"number"|"select"|"toggle";label:string;required:boolean;disabled:boolean;error:string|null;
  options:{id:string;label:string}[];minimum:number|null;maximum:number|null};
type Resolved={field:Field;value:string|number|boolean};
type Step={id:string;text:string;status:string};
type Series={id:string;label:string;points:{label:string;value:number}[]};
type Component={component:string;id:string;title:string;submit:string;disabled:boolean;resolved_fields:Resolved[];
  task_ref:string;requester:string;owner:string;status:string;progress:number|null;steps:Step[];
  kind:"line"|"bar";unit:string;scale:number;series:Series[];explanation:string};
function label(status:string):string{return status.charAt(0).toUpperCase()+status.slice(1)}
function form(c:Component,theme:RFTheme):CardNode {
  const children=c.resolved_fields.map(({field:f,value})=>{
    const id=c.id+":"+f.id;const disabled=c.disabled||f.disabled;const event={};
    const text=typeof value==="string"?value:value.toString();
    let n=f.kind==="select"?RFCardSelect({id,label:f.label,value:text,options:f.options,disabled,event,theme}):
      f.kind==="toggle"?RFCardToggle({id,label:f.label,checked:value===true,disabled,event,theme}):
      RFCardField({id,label:f.label,value:text,required:f.required,disabled,error:f.error??undefined,event,theme});
    if(f.kind==="number")n.kind="number";
    n.attrs={...n.attrs,required:f.required,disabled,error:f.error??undefined,options:f.options,
      minimum:f.minimum??undefined,maximum:f.maximum??undefined};return n;
  });
  children.push(RFCardButton({id:c.id+":submit",label:c.submit,kind:"primary",disabled:c.disabled,event:{action:c.submit},theme}));
  return node("form",c.id,c.title,"",children);
}
function task(c:Component,theme:RFTheme):CardNode {
  const status=label(c.status);
  const progress=RFCardProgress({id:c.id+":progress",label:status,value:c.progress??undefined,theme});
  progress.attrs={...progress.attrs,status};
  return node("task",c.id,c.title,c.task_ref,[
    RFCardText({id:c.id+":people",text:"Reported requester: "+c.requester+" · Reported owner: "+c.owner,theme}),progress,
    ...c.steps.map(s=>{const n=RFCardText({id:c.id+":step-"+s.id,text:s.text,theme});n.attrs={...n.attrs,status:label(s.status)};return n})]);
}
function scaled(value:number,scale:number,unit:string):string {
  return (scale===1?value.toString():value.toString()+" / "+scale.toString())+(unit?" "+unit:"");
}
function chart(c:Component,theme:RFTheme):CardNode {
  const first=c.series[0];
  if(!first)return node("chart",c.id,c.title);
  const columns=[{id:"label",label:"Label"},...c.series.map((s,index)=>({id:index===0?"first":"second",label:s.label}))];
  const second=c.series[1];
  const rows=first.points.map((point,index)=>{const other=second?.points.find((_p,i)=>i===index);return {id:point.label,
    cells:{label:point.label,first:scaled(point.value,c.scale,c.unit),second:other?scaled(other.value,c.scale,c.unit):""}}});
  const table=RFCardTable({id:c.id+":table",label:c.title+" — data table",columns,rows,theme});
  const design=RFCardText({id:c.id+":design",text:"Chart design pending · data table available",theme});
  const n=RFCardChartFrame({id:c.id,title:c.title,summary:"Data table available",content:[design,table],theme});
  n.attrs={...n.attrs,style:{...n.attrs?.style,color:theme.primary},plot:{kind:c.kind,unit:c.unit,scale:c.scale,series:c.series}};return n;
}
export function render(input:string):void {
  const data=JSON.parse(input) as {theme:"light"|"dark";components:Component[]};
  const theme=data.theme==="dark"?dark:light;
  const children=data.components.map(c=>{
    if(c.component==="rf.form")return form(c,theme);
    if(c.component==="rf.task")return task(c,theme);
    if(c.component==="rf.chart")return chart(c,theme);
    return node("approval_info",c.id,"Request message","",c.explanation?[RFCardText({id:c.id+":explanation",text:c.explanation,theme})]:[]);
  });
  __rf_commit(JSON.stringify({root:node("column","root","","",children)}));
}

// SPDX-License-Identifier: BSD-3-Clause
import { RFCardField, RFCardSelect, RFCardToggle, RFCardButton, RFCardProgress, RFCardText, RFCardTable, RFCardChartFrame } from "../../../src/generated/RFCardComponents";
import type { HostPresentation, Strings } from "./presentation-types";
import { format, grouped } from "./format";
import { setTokens } from "./primitives";
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
function label(status:string,strings:Strings):string{switch(status){case "pending":return strings.task_pending;case "delivered":return strings.task_delivered;case "running":return strings.task_running;case "completed":return strings.task_completed;case "refused":return strings.task_refused;case "cancelled":return strings.task_cancelled;default:return ""}}
function form(c:Component,theme:RFTheme,strings:Strings):CardNode {
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
  children.push(RFCardButton({id:c.id+":submit",label:strings.form_submit,kind:"primary",disabled:c.disabled,event:{action:c.submit},theme}));
  return node("form",c.id,c.title,"",children);
}
function task(c:Component,theme:RFTheme,strings:Strings):CardNode {
  const status=label(c.status,strings);
  const progress=RFCardProgress({id:c.id+":progress",label:status,value:c.progress??undefined,theme});
  progress.attrs={...progress.attrs,status};
  return node("task",c.id,c.title,c.task_ref,[
    RFCardText({id:c.id+":people",text:format(strings.task_people,[["requester",c.requester],["owner",c.owner]]),theme}),progress,
    ...c.steps.map(s=>{const n=RFCardText({id:c.id+":step-"+s.id,text:s.text,theme});n.attrs={...n.attrs,status:label(s.status,strings)};return n})]);
}
function scaled(value:number,scale:number,unit:string,strings:Strings):string {
 return format(scale===1?strings.number_unit:strings.number_scaled,[["value",grouped(value,strings.number_group)],["scale",grouped(scale,strings.number_group)],["unit",unit]]).trim();
}
function chart(c:Component,theme:RFTheme,strings:Strings):CardNode {
  const first=c.series[0];
  if(!first)return node("chart",c.id,c.title);
  const columns=[{id:"@label",label:strings.chart_label},...c.series.map((s,index)=>({id:s.id,label:s.label}))];
  const rows=first.points.map((point,index)=>({id:point.label,cells:c.series.reduce((cells:Record<string,string>,series)=>{
    const current=series.points.find((_p,i)=>i===index);return {...cells,[series.id]:current?scaled(current.value,c.scale,c.unit,strings):""};
  },{"@label":point.label})}));
  const table=RFCardTable({id:c.id+":table",label:format(strings.chart_table,[["title",c.title]]),columns,rows,theme});
  const design=RFCardText({id:c.id+":design",text:strings.chart_pending,theme});
  const n=RFCardChartFrame({id:c.id,title:c.title,summary:strings.chart_summary,content:[design,table],theme});
  n.attrs={...n.attrs,style:{...n.attrs?.style,color:theme.chart_1},plot:{kind:c.kind,unit:c.unit,scale:c.scale,series:c.series}};return n;
}
export function render(input:string):void {
  const data=JSON.parse(input) as {presentation:HostPresentation;components:Component[]};
  const theme=data.presentation.tokens,strings=data.presentation.strings;setTokens(theme);
  const children=data.components.map(c=>{
    if(c.component==="rf.form")return form(c,theme,strings);
    if(c.component==="rf.task")return task(c,theme,strings);
    if(c.component==="rf.chart")return chart(c,theme,strings);
    return node("approval_info",c.id,strings.approval_heading,"",c.explanation?[RFCardText({id:c.id+":explanation",text:c.explanation,theme})]:[]);
  });
  __rf_commit(JSON.stringify({root:node("column","root","","",children)}));
}

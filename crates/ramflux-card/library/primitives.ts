// SPDX-License-Identifier: BSD-3-Clause
// Fixed semantic primitives consumed by the generated presentation catalog.
export type CardAction = Readonly<{ action?: string }>;
export type Attrs = { required?: boolean; disabled?: boolean; error?: string; options?: readonly {id:string;label:string}[];
  minimum?:number; maximum?:number; progress?:number; status?:string; columns?:string[]; rows?:string[][];
  plot?:unknown; style?:{color?:string;background?:string;border?:string;gap?:number;padding?:number} };
export type CardNode = {key:string;kind:string;text:string;value:string;action:string|null;children:CardNode[];attrs?:Attrs};
type Props = {id:string;label?:string;title?:string;text?:string;value?:string|number;checked?:boolean;
  required?:boolean;disabled?:boolean;error?:string;event?:CardAction;options?:readonly {id:string;label:string}[];
  color?:string;background?:string;border?:string;gap?:number;padding?:number;summary?:string;
  columns?:readonly {id:string;label:string}[];rows?:readonly {id:string;cells:Readonly<Record<string,string>>}[];
  items?:readonly {id:string;text:string}[];subtitle?:string;variant?:string;style?:Readonly<Record<string,string|number>>;
  actionsCount?:number;legendCount?:number;leadingCount?:number;seriesColors?:readonly string[]};
export function node(kind:string, id:string, text="", value="", children:CardNode[]=[]):CardNode {
  return {key:id,kind,text,value,action:null,children};
}
function control(kind:string,p:Props):CardNode {
  const n=node(kind,p.id,p.label??p.text??p.title??"",typeof p.value==="number"?p.value.toString():p.value??"");
  n.attrs={required:p.required,disabled:p.disabled,error:p.error,options:p.options,
    style:{color:p.color,background:p.background,border:p.border,gap:p.gap,padding:p.padding}};
  return n;
}
export function Text(p:Props):CardNode{return control("text",p)}
export function TextField(p:Props):CardNode{return control("text_field",p)}
export function Select(p:Props):CardNode{return control("select",p)}
export function Toggle(p:Props):CardNode{const n=control("toggle",p);n.value=p.checked?"true":"false";return n}
export function Submit(p:Props):CardNode{const n=control("submit",p);n.action=p.event?.action??null;return n}
export function Progress(p:Props):CardNode{const n=control("progress",p);n.value="";n.attrs={...n.attrs,progress:typeof p.value==="number"?p.value:undefined};return n}
export function Table(p:Props):CardNode{
  const n=control("table",p);const columns=p.columns??[];
  n.attrs={...n.attrs,columns:columns.map(c=>c.label),rows:(p.rows??[]).map(r=>columns.map(c=>(c.id==="label"?r.cells.label:c.id==="first"?r.cells.first:r.cells.second)??""))};return n;
}
export function List(p:Props):CardNode{const n=control("column",p);n.children=(p.items??[]).map(i=>Text({id:i.id,text:i.text,color:p.color}));return n}
export function ChartFrame(p:Props,...children:CardNode[]):CardNode{const n=control("chart",p);n.children=children;return n}
export function Form(p:Props,...children:CardNode[]):CardNode{const n=control("form",p);n.children=children;return n}
export function createNode(component:(props:Props,...children:CardNode[])=>CardNode,props:Props,...children:CardNode[]):CardNode{return component(props,...children)}

// These catalog families are not admitted by the closed production card profile.
// Keep their generated signatures typechecked without introducing new controls.
export function Header(_props:Props,..._children:CardNode[]):CardNode{throw new Error("header is not admitted by the card profile")}
export function SearchField(_props:Props):CardNode{throw new Error("search is not admitted by the card profile")}

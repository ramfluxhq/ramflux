// SPDX-License-Identifier: BSD-3-Clause
import type {HostPresentation,Strings} from "./settings";
import {format} from "../library/format";
// A fixed DOM mutation adapter. Rust in the dedicated worker owns card validation.
export type HostSlot={component:string;request_ref:string;task_binding:string|null};
type Node={key:string;kind:string;text:string;value:string;action:string|null;children:Node[];attrs?:{
  required?:boolean;disabled?:boolean;error?:string;options?:{id:string;label:string}[];minimum?:number;maximum?:number;
  progress?:number;status?:string;columns?:string[];rows?:string[][];
  plot?:{kind:"line"|"bar";unit:string;scale:number;series:{label:string;points:{label:string;value:number}[]}[]};
  style?:{color?:string;background?:string;border?:string;gap?:number;padding?:number}}};
type Mutation={op:"remove";key:string}|{op:"upsert";parent:string|null;index:number;node:Node};
type Batch={previous_version:number;version:number;mutations:Mutation[];host_slots?:HostSlot[]};
type Reply={session:number;version:number;value:Batch|{result:string;batch?:Batch;action?:string;fields?:unknown}|null};
type Edit={key:string;version:number};
type Pending={edit?:Edit;presentation?:HostPresentation;resolve:(value:Reply|null)=>void;reject:(reason:Error)=>void};
// Each WASM instance has its own Rust resident counter. Bound worker instances
// at the app adapter too, so separate heaps cannot bypass the two-VM policy.
let workers=0;
let nextView=0;
let workerPolicy:{createScriptURL:(value:string)=>unknown}|undefined;
function createWorker(url:URL,strings:Strings):Worker {
  const expected=new URL("./worker.js",import.meta.url).href;
  if(url.href!==expected)throw Error(strings.runtime_unavailable);
  const trusted=(globalThis as typeof globalThis & {trustedTypes?:{createPolicy:(name:string,rules:{createScriptURL:(value:string)=>string})=>{createScriptURL:(value:string)=>unknown}}}).trustedTypes;
  if(trusted&&!workerPolicy)workerPolicy=trusted.createPolicy("rf-card-worker",{createScriptURL:value=>{if(value!==expected)throw Error(strings.runtime_unavailable);return value}});
  const source=workerPolicy?workerPolicy.createScriptURL(expected) as URL:url;
  if(workers>=2)throw Error(strings.capacity);
  const worker=new Worker(source,{type:"module",name:"card-renderer"});workers++;return worker;
}
export class CardView {
  private readonly worker:Worker;
  private readonly port:MessagePort;
  private readonly nodes=new Map<string,HTMLElement>();
  private readonly pending=new Map<number,Pending>();
  private readonly displayed=new Map<string,Node>();
  private readonly invalidDraft=new Set<string>();
  private sequence=0;
  private readonly view=++nextView;
  private session=0;
  private version=0;
  private disposed=false;
  private released=false;
  private readonly ready:Promise<void>;
  private rejectReady:(reason:Error)=>void=()=>{};
  constructor(private readonly root:HTMLElement, workerURL:URL,
    private readonly intent:(action:string,fields:unknown)=>void,
    private readonly hostSlots:(slots:readonly HostSlot[])=>void,
    private readonly failure:(message:string)=>void,private presentation:HostPresentation) {
    if(this.root.childElementCount)throw Error(this.ui("root_not_empty"));
    this.worker=createWorker(workerURL,presentation.strings);this.root.inert=false;
    const channel=new MessageChannel();this.port=channel.port1;
    this.ready=new Promise((resolve,reject)=>{
      this.rejectReady=reject;
      this.port.onmessage=event=>{
        if(event.data?.ready){resolve();return}
        if(event.data?.seq===undefined){const error=Error(this.ui("runtime_unavailable"));reject(error);this.abort(error);return}
        this.receive(event.data);
      };
      this.worker.onerror=()=>{const error=Error(this.ui("runtime_unavailable"));reject(error);this.abort(error)};
    });
    void this.ready.catch(()=>undefined);
    this.worker.postMessage({port:channel.port2,presentation},[channel.port2]);this.port.start();
  }
  private ui(key:keyof Strings):string{return this.presentation.strings[key]}
  present(presentation:HostPresentation):Promise<Reply|null>{return this.request("present",JSON.stringify(presentation),undefined,presentation)}
  open(selectedJSON:string):Promise<Reply|null>{return this.request("open",selectedJSON)}
  update(selectedJSON:string):Promise<Reply|null>{return this.request("update",selectedJSON)}
  suspend():Promise<Reply|null>{return this.request("suspend")}
  resume():Promise<Reply|null>{return this.request("resume")}
  dispose():void {
    if(this.disposed)return;this.disposed=true;
    this.abort(Error(this.ui("disposed")),false);this.port.close();this.releaseWorker();
    this.nodes.clear();this.displayed.clear();this.root.replaceChildren();this.hostSlots([]);
  }
  private releaseWorker():void {
    if(this.released)return;this.released=true;this.worker.terminate();workers--;
  }
  private abort(error:Error,notify=true):void {
    this.rejectReady(error);
    for(const pending of this.pending.values())pending.reject(error);this.pending.clear();
    if(notify){this.port.close();this.releaseWorker();this.root.inert=true;this.hostSlots([]);this.failure(error.message)}
  }
  private async request(op:string,json?:string,edit?:Edit,presentation?:HostPresentation):Promise<Reply|null> {
    if(this.disposed||this.released)throw Error(this.ui("disposed"));
    if(json!==undefined && (typeof json!=="string" || json.length>16384))throw Error(this.ui("input_bound"));
    if(this.pending.size>=32)throw Error(this.ui("busy"));
    // Reserve before awaiting readiness so the pre-init queue is bounded too.
    const seq=++this.sequence;
    const response=new Promise<Reply|null>((resolve,reject)=>this.pending.set(seq,{resolve,reject,edit,presentation}));
    this.refreshButtons();
    try {await this.ready;if(this.disposed)throw Error(this.ui("disposed"));this.port.postMessage({seq,op,json})}
    catch(error){this.pending.get(seq)?.reject(error instanceof Error?error:Error(this.ui("runtime_unavailable")));this.pending.delete(seq)}
    return response;
  }
  private receive(message:{seq:number;json?:string;error?:string;terminal?:boolean;disposed?:boolean}):void {
    const pending=this.pending.get(message.seq);if(!pending)return;this.pending.delete(message.seq);
    if(message.error){const failure=Error(this.ui(message.error==="runtime_unavailable"?"runtime_unavailable":"content_unavailable"));pending.reject(failure);if(message.terminal)this.abort(failure);this.refreshButtons();return}
    try {
      if(message.disposed){pending.resolve(null);return}
      if(typeof message.json!=="string"||message.json.length>131072)throw Error(this.ui("output_unavailable"));
      const reply=JSON.parse(message.json) as Reply;
      if(pending.presentation)this.presentation=pending.presentation;
      this.session=reply.session;
      const value=reply.value;
      if(value && "mutations" in value)this.apply(value);
      else if(value && "batch" in value && value.batch){
        this.apply(value.batch);
        if(value.result==="submit" && value.action)this.intent(value.action,value.fields);
      }
      if(value && "result" in value && value.result==="stale_dropped" && pending.edit){
        this.reconcile(pending.edit.key);this.localError(pending.edit.key,this.ui("stale_edit"));this.failure(this.ui("stale_edit"));
      }
      this.refreshButtons();pending.resolve(reply);
    } catch(error){const failure=error instanceof Error?error:Error(this.ui("output_unavailable"));pending.reject(failure);this.abort(failure)}
  }
  private editsPending():boolean{return [...this.pending.values()].some(pending=>pending.edit!==undefined)}
  private refreshButtons():void{
    for(const [key,node] of this.displayed)if(node.kind==="submit"){
      const button=this.nodes.get(key)?.querySelector("button");if(button)button.disabled=!!node.attrs?.disabled||this.editsPending()||this.invalidDraft.size>0;
    }
  }
  private reconcile(key:string):void{const element=this.nodes.get(key),shown=this.displayed.get(key);if(element&&shown)this.draw(element,shown)}
  private localError(key:string,message:string):void{
    const element=this.nodes.get(key),content=element?.querySelector<HTMLElement>(":scope > [data-content]"),control=content?.querySelector("input,select");if(!content||!control)return;
    content.querySelector("[role=alert]")?.remove();const alert=document.createElement("p");alert.textContent=message;alert.setAttribute("role","alert");
    alert.id="card-error-"+this.view+"-"+key;content.append(alert);control.setAttribute("aria-invalid","true");control.setAttribute("aria-describedby",alert.id);
  }
  private event(key:string,event:{kind:string;value?:unknown}):void {
    if(event.kind==="submit"&&(this.editsPending()||this.invalidDraft.size)){this.failure(this.ui("busy"));return}
    const edit=event.kind==="submit"?undefined:{key,version:this.version};
    void this.request("event",JSON.stringify({token:{session:this.session,version:this.version,key},event}),edit)
      .catch(error=>{this.reconcile(key);this.failure(error instanceof Error?error.message:this.ui("content_unavailable"))}).finally(()=>this.refreshButtons());
    this.refreshButtons();
  }
  private drop(key:string):void {
    const element=this.nodes.get(key);if(!element)return;
    for(const [other,child] of this.nodes)if(element.contains(child)){this.nodes.delete(other);this.displayed.delete(other);this.invalidDraft.delete(other)}
    element.remove();
  }
  private apply(batch:Batch):void {
    if(batch.previous_version!==this.version)throw Error(this.ui("resync"));
    for(const mutation of batch.mutations){
      if(mutation.op==="remove"){this.drop(mutation.key);continue}
      const {node,index,parent}=mutation;
      let element=this.nodes.get(node.key);
      if(element?.dataset.kind!==node.kind){this.drop(node.key);element=undefined}
      if(!element){element=document.createElement("div");element.dataset.kind=node.kind;element.dataset.cardKey=node.key;this.nodes.set(node.key,element)}
      this.draw(element,node);
      const target=parent===null?this.root:this.nodes.get(parent);
      if(!target)throw Error(this.ui("parent_unavailable"));
      const siblings=Array.from(target.children).filter(child=>(child as HTMLElement).dataset.cardKey!==undefined);
      const before=siblings[index]??null;if(before!==element)target.insertBefore(element,before);
    }
    this.version=batch.version;this.hostSlots(batch.host_slots??[]);
  }
  private draw(element:HTMLElement,node:Node):void {
    this.displayed.set(node.key,node);
    this.invalidDraft.delete(node.key);
    this.root.lang=this.presentation.locale;this.root.dir=this.presentation.direction;
    this.root.style.color=this.presentation.tokens.text;this.root.style.backgroundColor=this.presentation.tokens.surface_white;
    this.root.style.fontFamily=this.presentation.tokens.font;this.root.style.fontSize=this.presentation.tokens.size_body+"px";
    // Content and native child mounts live in separate containers; no HTML parsing.
    let content=element.querySelector<HTMLElement>(":scope > [data-content]");
    if(!content){content=document.createElement("div");content.dataset.content="";element.prepend(content)}
    const a=node.attrs??{};
    element.style.color=a.style?.color??"";element.style.backgroundColor=a.style?.background??"";
    element.style.borderColor=a.style?.border??"";element.style.padding=(a.style?.padding??0)+"px";
    element.style.display="flex";element.style.flexDirection="column";element.style.gap=(a.style?.gap??this.presentation.tokens.gap)+"px";
    element.style.minWidth="0";element.style.overflowWrap="anywhere";
    const text=(tag:string,value:string)=>{const child=document.createElement(tag);child.textContent=value;content?.append(child);return child};
    if(["text_field","number","select","toggle"].includes(node.kind)){
      this.control(content,node);return;
    }
    content.replaceChildren();
    if(node.kind==="submit"){const button=document.createElement("button");button.type="button";button.textContent=node.text;button.disabled=a.disabled??false;button.style.color=this.presentation.tokens.on_primary;button.style.backgroundColor=this.presentation.tokens.primary;button.style.borderRadius=this.presentation.tokens.radius_button+"px";button.style.padding=this.presentation.tokens.gap/2+"px";button.onclick=()=>this.event(node.key,{kind:"submit"});content.append(button);return}
    if(node.text)text(node.kind==="text"?"p":"h3",node.text);
    if(node.kind==="progress"&&a.progress!==undefined){const progress=document.createElement("progress");progress.max=100;progress.value=a.progress;progress.setAttribute("aria-label",node.text);content.append(progress)}
    if(node.kind==="table"){
      const table=document.createElement("table");const caption=document.createElement("caption");caption.textContent=node.text;table.append(caption);
      const head=document.createElement("thead");const header=document.createElement("tr");for(const value of a.columns??[]){const cell=document.createElement("th");cell.scope="col";cell.textContent=value;header.append(cell)}head.append(header);table.append(head);
      const body=document.createElement("tbody");for(const row of a.rows??[]){const tr=document.createElement("tr");for(const value of row){const td=document.createElement("td");td.textContent=value;tr.append(td)}body.append(tr)}table.append(body);content.append(table);
    }
    if(node.kind==="chart"&&a.plot)this.plot(content,a.plot);
    if(a.status){element.setAttribute("role","group");element.setAttribute("aria-label",format(this.ui("status_accessibility"),[["text",node.text],["status",a.status]]));}else element.removeAttribute("aria-label");
    if(node.kind==="approval_info")element.setAttribute("role","group");
    if(node.kind==="approval_info")element.setAttribute("aria-label",this.ui("approval_untrusted"));
  }
  private control(content:HTMLElement,node:Node):void {
    const a=node.attrs??{};
    let label=content.querySelector("label");
    let control=content.querySelector<HTMLInputElement|HTMLSelectElement>("input,select");
    if(!label||!control){
      content.replaceChildren();label=document.createElement("label");label.append(document.createElement("span"));
      control=node.kind==="select"?document.createElement("select"):document.createElement("input");
      if(control instanceof HTMLInputElement)control.type=node.kind==="toggle"?"checkbox":node.kind==="number"?"number":"text";
      const native=control;
      native.addEventListener("change",()=>{
        if(node.kind==="number"){
          const value=Number(native.value);
          if(native.value.trim()===""||!Number.isSafeInteger(value)){this.invalidDraft.add(node.key);this.localError(node.key,this.ui("form_number"));this.refreshButtons();return}
          this.invalidDraft.delete(node.key);this.event(node.key,{kind:"number",value});return;
        }
        this.invalidDraft.delete(node.key);
        this.event(node.key,native instanceof HTMLInputElement&&node.kind==="toggle"?{kind:"toggle",value:native.checked}:{kind:node.kind==="select"?"select":"text",value:native.value});
      });
      label.append(native);content.append(label);
    }
    const caption=label.querySelector("span");if(caption)caption.textContent=node.text;
    if(control instanceof HTMLInputElement){
      if(control.value!==node.value)control.value=node.value;
      control.checked=node.value==="true";control.min=a.minimum?.toString()??"";control.max=a.maximum?.toString()??"";
    }else{
      const choices=a.options??[];
      if(control.options.length!==choices.length||choices.some((option,index)=>control.options[index]?.value!==option.id||control.options[index]?.textContent!==option.label)){
        control.replaceChildren();for(const option of choices){const child=document.createElement("option");child.value=option.id;child.textContent=option.label;control.append(child)}
      }
      control.value=node.value;
    }
    control.style.color=this.presentation.tokens.text;control.style.backgroundColor=this.presentation.tokens.surface_white;
    control.style.borderColor=this.presentation.tokens.secondary;control.style.borderRadius=this.presentation.tokens.radius_input+"px";
    control.style.fontFamily=this.presentation.tokens.font;control.style.fontSize=this.presentation.tokens.size_body+"px";
    control.style.accentColor=this.presentation.tokens.primary;
    control.disabled=a.disabled??false;control.required=a.required??false;control.setAttribute("aria-invalid",a.error?"true":"false");
    content.querySelector("[role=alert]")?.remove();
    if(a.error){const error=document.createElement("p");error.textContent=a.error;error.id="card-error-"+this.view+"-"+this.session+"-"+node.key;error.setAttribute("role","alert");content.append(error);control.setAttribute("aria-describedby",error.id)}
    else control.removeAttribute("aria-describedby");
  }
  private plot(content:HTMLElement,plot:NonNullable<NonNullable<Node["attrs"]>["plot"]>):void {
    const canvas=document.createElement("canvas");const width=this.presentation.tokens.column_max,height=this.presentation.tokens.gap*10,pad=this.presentation.tokens.gap;canvas.width=width;canvas.height=height;canvas.style.width="100%";canvas.style.maxWidth=width+"px";
    canvas.setAttribute("role","img");canvas.setAttribute("aria-label",this.ui(plot.kind==="line"?"chart_line":"chart_bar"));
    const ctx=canvas.getContext("2d");if(!ctx)return;
    const values=plot.series.flatMap(series=>series.points.map(point=>point.value));
    const low=Math.min(0,...values),high=Math.max(0,...values),range=high-low||1;
    const y=(v:number)=>height-pad-(v-low)/range*(height-pad*2);
    plot.series.forEach((series,seriesIndex)=>{
      ctx.strokeStyle=seriesIndex===0?this.presentation.tokens.chart_1:this.presentation.tokens.chart_2;ctx.fillStyle=ctx.strokeStyle;ctx.globalAlpha=seriesIndex===0?1:0.6;ctx.setLineDash(seriesIndex===0?[]:[pad/2,pad/4]);ctx.lineWidth=Math.max(1,this.presentation.tokens.gap/8);ctx.beginPath();
      series.points.forEach((point,index)=>{const x=pad+index*(width-pad*2)/Math.max(1,series.points.length-1);
        if(plot.kind==="bar")ctx.fillRect(pad+index*(width-pad*2)/series.points.length+seriesIndex*pad,Math.min(y(0),y(point.value)),pad/2,Math.max(1,Math.abs(y(0)-y(point.value))));
        else if(index===0)ctx.moveTo(x,y(point.value));else ctx.lineTo(x,y(point.value));
      });if(plot.kind==="line")ctx.stroke();
    });content.append(canvas);
  }
}

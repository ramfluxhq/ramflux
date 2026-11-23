// SPDX-License-Identifier: BSD-3-Clause
import type {HostPresentation,Strings} from "./settings";
// A fixed DOM mutation adapter. Rust in the dedicated worker owns card validation.
export type Token={session:number;signedVersion:number;editSeq:number;treeVersion:number;key:string};
export type HostSlot={id:string;kind:"approval"|"modal"|"link_open"|"image";key:string;token:Token;[field:string]:unknown};
type Node={key:string;kind:string;component_id:string;source_instance:string[];scope:string;parent_key:string|null;slot:{slot:string;position?:number};children:string[];attrs:Record<string,unknown>};
type Mutation={op:"remove";key:string}|{op:"upsert";parent:string|null;index:number;node:Node};
type Batch={schema:string;session:number;previous_version:number;version:number;signed_version:number;signed_hash:string;edit_seq:number;mutations:Mutation[];host_slots:HostSlot[]};
type Reply={session:number;version:number;value:Batch|{result:string;batch?:Batch;action?:unknown}|null};
type Edit={key:string;version:number};
type Pending={op:string;edit?:Edit;presentation?:HostPresentation;resolve:(value:Reply|null)=>void;reject:(reason:Error)=>void};
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
  private mountedSession=0;
  private signedVersion=0;
  private editSeq=0;
  private readonly selected=new Map<string,number>();
  private disposed=false;
  private released=false;
  private readonly ready:Promise<void>;
  private rejectReady:(reason:Error)=>void=()=>{};
  constructor(private readonly root:HTMLElement, workerURL:URL,
    private readonly intent:(action:unknown,fields?:unknown)=>void,
    private readonly hostSlots:(slots:readonly HostSlot[])=>void,
    private readonly failure:(message:string)=>void,private presentation:HostPresentation,
    private readonly observe?:(entry:{op:string;request?:unknown;reply?:unknown;refusal?:unknown})=>void) {
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
  preview(input:string,model:string):Promise<Reply|null>{return this.request("open_preview",input,undefined,undefined,model)}
  tree():Promise<Reply|null>{return this.request("tree")}
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
  private async request(op:string,json?:string,edit?:Edit,presentation?:HostPresentation,model?:string):Promise<Reply|null> {
    if(this.disposed||this.released)throw Error(this.ui("disposed"));
    if(json!==undefined && (typeof json!=="string" || new TextEncoder().encode(json).length>32768))throw Error(this.ui("input_bound"));
    if(this.pending.size>=32)throw Error(this.ui("busy"));
    // Reserve before awaiting readiness so the pre-init queue is bounded too.
    const seq=++this.sequence;
    const response=new Promise<Reply|null>((resolve,reject)=>this.pending.set(seq,{op,resolve,reject,edit,presentation}));
    this.refreshButtons();
    try {await this.ready;if(this.disposed)throw Error(this.ui("disposed"));this.observe?.({op,request:op==="event"&&json!==undefined?JSON.parse(json):json});this.port.postMessage({seq,op,json,model})}
    catch(error){this.pending.get(seq)?.reject(error instanceof Error?error:Error(this.ui("runtime_unavailable")));this.pending.delete(seq)}
    return response;
  }
  private receive(message:{seq:number;json?:string;error?:string;terminal?:boolean;disposed?:boolean;refusal?:unknown}):void {
    const pending=this.pending.get(message.seq);if(!pending)return;this.pending.delete(message.seq);
    if(message.error){this.observe?.({op:"refused",refusal:message.refusal});const failure=Error(this.ui(message.error==="runtime_unavailable"?"runtime_unavailable":"content_unavailable"));pending.reject(failure);if(message.terminal)this.abort(failure);this.refreshButtons();return}
    try {
      if(message.disposed){pending.resolve(null);return}
      if(typeof message.json!=="string"||new TextEncoder().encode(message.json).length>263168)throw Error(this.ui("output_unavailable"));
      const reply=JSON.parse(message.json) as Reply;
      this.observe?.({op:pending.op,reply});
      if(pending.presentation)this.presentation=pending.presentation;
      this.session=reply.session;
      const value=reply.value;
      if(value && "mutations" in value)this.apply(value);
      else if(value && "batch" in value && value.batch){
        this.apply(value.batch);
        if(value.result==="submit" && value.action)this.intent(value.action);
      }
      if(value && "result" in value && value.result==="stale_dropped" && pending.edit){
        this.reconcile(pending.edit.key);this.localError(pending.edit.key,this.ui("stale_edit"));this.failure(this.ui("stale_edit"));
      }
      this.refreshButtons();pending.resolve(reply);
    } catch(error){const failure=error instanceof Error?error:Error(this.ui("output_unavailable"));pending.reject(failure);this.abort(failure)}
  }
  private editsPending():boolean{return [...this.pending.values()].some(pending=>pending.edit!==undefined)}
  private refreshButtons():void{
    for(const [key,node] of this.displayed)if(node.kind==="Button"){
      const button=this.nodes.get(key)?.querySelector("button");if(button)button.disabled=!!node.attrs.disabled||this.editsPending()||this.invalidDraft.size>0;
    }
  }
  private reconcile(key:string):void{const element=this.nodes.get(key),shown=this.displayed.get(key);if(element&&shown)this.draw(element,shown)}
  private localError(key:string,message:string):void{
    const element=this.nodes.get(key),content=element?.querySelector<HTMLElement>(":scope > [data-content]"),control=content?.querySelector("input,select");if(!content||!control)return;
    content.querySelector("[role=alert]")?.remove();const alert=document.createElement("p");alert.textContent=message;alert.setAttribute("role","alert");
    alert.id="card-error-"+this.view+"-"+key;content.append(alert);control.setAttribute("aria-invalid","true");control.setAttribute("aria-describedby",alert.id);
  }
  private event(key:string,event:{kind:string;value?:unknown;index?:number}):void {
    if(event.kind==="activate"&&(this.editsPending()||this.invalidDraft.size)){this.failure(this.ui("busy"));return}
    const edit=event.kind==="activate"?undefined:{key,version:this.version};
    void this.request("event",JSON.stringify({token:{session:this.session,signedVersion:this.signedVersion,editSeq:this.editSeq,treeVersion:this.version,key},event}),edit)
      .catch(error=>{this.reconcile(key);this.failure(error instanceof Error?error.message:this.ui("content_unavailable"))}).finally(()=>this.refreshButtons());
    this.refreshButtons();
  }
  private drop(key:string):void {
    const element=this.nodes.get(key);if(!element)return;
    for(const [other,child] of this.nodes)if(element.contains(child)){this.nodes.delete(other);this.displayed.delete(other);this.invalidDraft.delete(other)}
    element.remove();
  }

  private apply(batch:Batch):void {
    const reset=batch.previous_version===0&&batch.session!==this.mountedSession;
    if(batch.schema!=="ramflux.card.mutations.v1"||(!reset&&(batch.session!==this.mountedSession||batch.previous_version!==this.version)))throw Error(this.ui("resync"));
    const next=new Map<string,Node>();if(!reset)for(const [key,node]of this.displayed)next.set(key,{...node,children:[...node.children]});
    // Stage the complete batch and edges before modifying mounted DOM or callbacks.
    for(const mutation of batch.mutations){
      const key=mutation.op==="remove"?mutation.key:mutation.node.key;
      for(const node of next.values())node.children=node.children.filter(child=>child!==key);
      if(mutation.op==="remove"){next.delete(key);continue}
      const existing=next.get(key),node={...mutation.node,children:existing?.children??[]};next.set(key,node);
      if(mutation.parent!==null){const parent=next.get(mutation.parent);if(!parent||mutation.index>parent.children.length)throw Error(this.ui("parent_unavailable"));parent.children.splice(mutation.index,0,key)}
    }
    for(const node of next.values())if(node.children.some(key=>!next.has(key)))throw Error(this.ui("parent_unavailable"));
    const active=document.activeElement as HTMLInputElement|null,focused=active?.dataset.controlKey;
    const start=active?.selectionStart,end=active?.selectionEnd;
    for(const key of this.selected.keys())if(!next.has(key))this.selected.delete(key);
    const prior=new Map(this.displayed);this.displayed.clear();for(const [key,node]of next)this.displayed.set(key,node);
    const fragment=document.createDocumentFragment();this.nodes.clear();
    try{for(const node of next.values())if(node.parent_key===null)fragment.append(this.element(node))}
    catch(error){this.displayed.clear();for(const [key,node]of prior)this.displayed.set(key,node);throw error}
    this.root.replaceChildren(fragment);this.version=batch.version;this.mountedSession=batch.session;
    this.signedVersion=batch.signed_version;this.editSeq=batch.edit_seq;
    this.root.lang=this.presentation.locale;this.root.dir=this.presentation.direction;
    const t=this.presentation.tokens;this.root.style.color=t.text;this.root.style.backgroundColor=t.surface_white;this.root.style.fontFamily=t.font;this.root.style.fontSize=t.size_body+"px";
    if(focused){const input=Array.from(this.root.querySelectorAll<HTMLInputElement>("[data-control-key]")).find(input=>input.dataset.controlKey===focused);input?.focus();if(input?.type==="text"&&start!==null&&end!==null)input.setSelectionRange(start??0,end??0)}
    this.hostSlots(batch.host_slots);
  }
  private element(node:Node):HTMLElement{const e=document.createElement("div");e.dataset.cardKey=node.key;e.dataset.kind=node.kind;this.nodes.set(node.key,e);this.draw(e,node);return e}
  private label(node:Node):string{const a=node.attrs;return typeof a.text==="string"?a.text:typeof a.label==="string"?a.label:typeof a.title==="string"?a.title:""}
  private draw(element:HTMLElement,node:Node):void {
    const a=node.attrs,t=this.presentation.tokens;element.replaceChildren();
    element.style.display="flex";element.style.flexDirection=node.kind==="Row"?"row":"column";element.style.gap=t.gap+"px";
    const text=(value:string)=>{const e=document.createElement("span");e.textContent=value;element.append(e)};
    const label=this.label(node);if(label)text(label);
    if(["TextField","CheckBox","ChoicePicker","Slider","DateTimeInput"].includes(node.kind))this.control(element,node);
    if(node.kind==="Tabs"){
      const tabs=a.tabs as {title:string}[],prior=this.selected.get(node.key)??0,selected=prior<tabs.length?prior:0;this.selected.set(node.key,selected);
      const list=document.createElement("div");list.setAttribute("role","tablist");
      tabs.forEach((tab,index)=>{const button=document.createElement("button");button.type="button";button.textContent=tab.title;button.setAttribute("role","tab");button.setAttribute("aria-selected",(index===selected).toString());button.onclick=()=>{if(this.pending.size){this.failure(this.ui("busy"));return}this.selected.set(node.key,index);this.event(node.key,{kind:"select_tab",index})};list.append(button)});element.append(list);
      const child=this.displayed.get(node.children[selected]??"");if(child)element.append(this.element(child));return;
    }
    if(node.kind==="Modal")return; // Host slot owns its trigger, sheet and content mounting.
    if(node.kind==="Image")text(typeof a.description==="string"?a.description:this.ui("content_unavailable"));
    if(node.kind==="Approval")text(typeof a.explanation==="string"?a.explanation:"");
    if(node.kind==="Icon")text(typeof a.name==="string"?a.name:"");
    if(node.kind==="Divider")element.append(document.createElement("hr"));
    if(node.kind==="Table")this.table(element,a.columns as {label:string}[],(a.rows as {cells:unknown[]}[]).map(row=>row.cells));
    if(node.kind==="Chart"){
      const rows:unknown[][]=[];for(const series of a.series as {label:string;points:{label:string;value:number}[]}[])for(const point of series.points)rows.push([series.label,point.label,point.value+"/"+a.scale+" "+a.unit]);
      this.table(element,[{label:this.ui("chart_label")},{label:this.ui("chart_label")},{label:typeof a.unit==="string"?a.unit:""}],rows);
    }
    if(node.kind==="Task"){
      text(typeof a.status==="string"?a.status:"");for(const step of a.steps as {text:string;status:string}[])text(step.text+" "+step.status);
      if(typeof a.progress==="number"){const progress=document.createElement("progress");progress.max=100;progress.value=a.progress;element.append(progress)}
    }
    let target=element;if(node.kind==="Button"){const button=document.createElement("button");button.type="button";button.disabled=a.disabled===true;button.onclick=()=>this.event(node.key,{kind:"activate"});button.style.color=t.on_primary;button.style.backgroundColor=t.primary;element.append(button);target=button}
    for(const key of node.children){const child=this.displayed.get(key);if(child)target.append(this.element(child))}
    const accessibility=a.accessibility as {label?:string;hidden?:boolean;live?:string}|undefined;
    if(accessibility?.label)element.setAttribute("aria-label",accessibility.label);if(accessibility?.hidden)element.setAttribute("aria-hidden","true");if(accessibility?.live)element.setAttribute("aria-live",accessibility.live);
  }
  private control(element:HTMLElement,node:Node):void {
    const a=node.attrs,value=a.value;let control:HTMLInputElement|HTMLSelectElement;
    if(node.kind==="ChoicePicker"){
      const select=document.createElement("select");select.multiple=true;
      for(const choice of a.options as {label:string;value:string}[]){const option=document.createElement("option");option.textContent=choice.label;option.value=choice.value;option.selected=Array.isArray(value)&&value.includes(choice.value);select.append(option)}control=select;
    }else{
      const input=document.createElement("input");input.type=node.kind==="CheckBox"?"checkbox":node.kind==="Slider"?"range":node.kind==="DateTimeInput"?(a.enableTime===true?"datetime-local":"date"):"text";
      if(node.kind==="CheckBox")input.checked=value===true;else input.value=typeof value==="string"||typeof value==="number"?value.toString():"";
      if(typeof a.min==="number"||typeof a.min==="string")input.min=a.min.toString();if(typeof a.max==="number"||typeof a.max==="string")input.max=a.max.toString();control=input;
    }
    control.dataset.controlKey=node.key;control.disabled=a.disabled===true;control.setAttribute("aria-label",this.label(node));
    control.onchange=()=>{const value=control instanceof HTMLSelectElement?Array.from(control.selectedOptions).map(option=>option.value):control.type==="checkbox"?control.checked:control.type==="range"?Number(control.value):control.value;this.event(node.key,{kind:"input",value})};element.append(control);
    for(const message of a.errors as string[]??[]){const e=document.createElement("p");e.setAttribute("role","alert");e.textContent=message;element.append(e)}
  }
  private table(element:HTMLElement,columns:{label:string}[],rows:unknown[][]):void{
    const table=document.createElement("table"),head=document.createElement("tr");for(const column of columns){const cell=document.createElement("th");cell.scope="col";cell.textContent=column.label;head.append(cell)}table.append(head);
    for(const row of rows){const tr=document.createElement("tr");for(const value of row){const cell=document.createElement("td");cell.textContent=typeof value==="string"?value:JSON.stringify(value);tr.append(cell)}table.append(tr)}element.append(table);
  }
}

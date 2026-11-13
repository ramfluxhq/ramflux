// SPDX-License-Identifier: BSD-3-Clause
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
type Pending={resolve:(value:Reply|null)=>void;reject:(reason:Error)=>void};
export class CardView {
  private readonly worker:Worker;
  private readonly port:MessagePort;
  private readonly nodes=new Map<string,HTMLElement>();
  private readonly pending=new Map<number,Pending>();
  private readonly displayed=new Map<string,Node>();
  private sequence=0;
  private session=0;
  private version=0;
  private disposed=false;
  private readonly ready:Promise<void>;
  constructor(private readonly root:HTMLElement, workerURL:URL,
    private readonly intent:(action:string,fields:unknown)=>void,
    private readonly hostSlots:(slots:readonly HostSlot[])=>void,
    private readonly failure:(message:string)=>void) {
    this.worker=new Worker(workerURL,{type:"module",name:"card-renderer"});
    const channel=new MessageChannel();this.port=channel.port1;
    this.ready=new Promise((resolve,reject)=>{
      this.port.onmessage=event=>{
        if(event.data?.ready){resolve();return}
        if(event.data?.seq===undefined){reject(Error("Card runtime unavailable"));return}
        this.receive(event.data);
      };
      this.worker.onerror=()=>{const error=Error("Card runtime unavailable");reject(error);this.abort(error)};
    });
    this.worker.postMessage({port:channel.port2},[channel.port2]);this.port.start();
  }
  open(selectedJSON:string):Promise<Reply|null>{return this.request("open",selectedJSON)}
  update(selectedJSON:string):Promise<Reply|null>{return this.request("update",selectedJSON)}
  suspend():Promise<Reply|null>{return this.request("suspend")}
  resume():Promise<Reply|null>{return this.request("resume")}
  dispose():void {
    if(this.disposed)return;this.disposed=true;
    this.abort(Error("Card disposed"),false);this.port.close();this.worker.terminate();
    this.nodes.clear();this.displayed.clear();this.root.replaceChildren();this.hostSlots([]);
  }
  private abort(error:Error,notify=true):void {
    for(const pending of this.pending.values())pending.reject(error);this.pending.clear();
    if(notify){this.root.inert=true;this.failure(error.message)}
  }
  private async request(op:string,json?:string):Promise<Reply|null> {
    if(this.disposed)throw Error("Card disposed");
    if(json!==undefined && (typeof json!=="string" || json.length>16384))throw Error("Card transport bound");
    if(this.pending.size>=32)throw Error("Card busy");
    // Reserve before awaiting readiness so the pre-init queue is bounded too.
    const seq=++this.sequence;
    const response=new Promise<Reply|null>((resolve,reject)=>this.pending.set(seq,{resolve,reject}));
    try {await this.ready;if(this.disposed)throw Error("Card disposed");this.port.postMessage({seq,op,json})}
    catch(error){this.pending.get(seq)?.reject(error instanceof Error?error:Error("Card runtime unavailable"));this.pending.delete(seq)}
    return response;
  }
  private receive(message:{seq:number;json?:string;error?:string;disposed?:boolean}):void {
    const pending=this.pending.get(message.seq);if(!pending)return;this.pending.delete(message.seq);
    try {
      if(message.error)throw Error(message.error);
      if(message.disposed){pending.resolve(null);return}
      if(typeof message.json!=="string"||message.json.length>131072)throw Error("Card output unavailable");
      const reply=JSON.parse(message.json) as Reply;
      this.session=reply.session;
      const value=reply.value;
      if(value && "mutations" in value)this.apply(value);
      else if(value && "batch" in value && value.batch){
        this.apply(value.batch);
        if(value.result==="submit" && value.action)this.intent(value.action,value.fields);
      }
      pending.resolve(reply);
    } catch(error){pending.reject(error instanceof Error?error:Error("Card output unavailable"))}
  }
  private event(key:string,event:unknown):void {
    void this.request("event",JSON.stringify({token:{session:this.session,version:this.version,key},event}))
      .catch(()=>{const element=this.nodes.get(key),shown=this.displayed.get(key);if(element&&shown)this.draw(element,shown);this.failure("Card content unavailable")});
  }
  private drop(key:string):void {
    const element=this.nodes.get(key);if(!element)return;
    for(const [other,child] of this.nodes)if(element.contains(child)){this.nodes.delete(other);this.displayed.delete(other)}
    element.remove();
  }
  private apply(batch:Batch):void {
    if(batch.previous_version!==this.version)throw Error("Card requires resynchronization");
    for(const mutation of batch.mutations){
      if(mutation.op==="remove"){this.drop(mutation.key);continue}
      const {node,index,parent}=mutation;
      let element=this.nodes.get(node.key);
      if(element?.dataset.kind!==node.kind){this.drop(node.key);element=undefined}
      if(!element){element=document.createElement("div");element.dataset.kind=node.kind;element.dataset.cardKey=node.key;this.nodes.set(node.key,element)}
      this.draw(element,node);
      const target=parent===null?this.root:this.nodes.get(parent);
      if(!target)throw Error("Card parent unavailable");
      const siblings=Array.from(target.children).filter(child=>(child as HTMLElement).dataset.cardKey!==undefined);
      const before=siblings[index]??null;if(before!==element)target.insertBefore(element,before);
    }
    this.version=batch.version;this.hostSlots(batch.host_slots??[]);
  }
  private draw(element:HTMLElement,node:Node):void {
    this.displayed.set(node.key,node);
    // Content and native child mounts live in separate containers; no HTML parsing.
    let content=element.querySelector<HTMLElement>(":scope > [data-content]");
    if(!content){content=document.createElement("div");content.dataset.content="";element.prepend(content)}
    const a=node.attrs??{};
    element.style.color=a.style?.color??"";element.style.backgroundColor=a.style?.background??"";
    element.style.borderColor=a.style?.border??"";element.style.padding=(a.style?.padding??0)+"px";
    element.style.display="flex";element.style.flexDirection="column";element.style.gap=(a.style?.gap??8)+"px";
    element.style.minWidth="0";element.style.overflowWrap="anywhere";
    const text=(tag:string,value:string)=>{const child=document.createElement(tag);child.textContent=value;content?.append(child);return child};
    if(["text_field","number","select","toggle"].includes(node.kind)){
      this.control(content,node);return;
    }
    content.replaceChildren();
    if(node.kind==="submit"){const button=document.createElement("button");button.type="button";button.textContent=node.text;button.disabled=a.disabled??false;button.onclick=()=>this.event(node.key,{kind:"submit"});content.append(button);return}
    if(node.text)text(node.kind==="text"?"p":"h3",node.text);
    if(node.kind==="progress"&&a.progress!==undefined){const progress=document.createElement("progress");progress.max=100;progress.value=a.progress;progress.setAttribute("aria-label",node.text);content.append(progress)}
    if(node.kind==="table"){
      const table=document.createElement("table");const caption=document.createElement("caption");caption.textContent=node.text;table.append(caption);
      const head=document.createElement("thead");const header=document.createElement("tr");for(const value of a.columns??[]){const cell=document.createElement("th");cell.scope="col";cell.textContent=value;header.append(cell)}head.append(header);table.append(head);
      const body=document.createElement("tbody");for(const row of a.rows??[]){const tr=document.createElement("tr");for(const value of row){const td=document.createElement("td");td.textContent=value;tr.append(td)}body.append(tr)}table.append(body);content.append(table);
    }
    if(node.kind==="chart"&&a.plot)this.plot(content,a.plot);
    if(a.status)element.setAttribute("aria-label",node.text+" — "+a.status);else element.removeAttribute("aria-label");
    if(node.kind==="approval_info")element.setAttribute("aria-label","Untrusted request message");
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
      native.addEventListener("change",()=>this.event(node.key,native instanceof HTMLInputElement&&node.kind==="toggle"?{kind:"toggle",value:native.checked}:
        node.kind==="number"?{kind:"number",value:Number(native.value)}:{kind:node.kind==="select"?"select":"text",value:native.value}));
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
    control.disabled=a.disabled??false;control.required=a.required??false;control.setAttribute("aria-invalid",a.error?"true":"false");
    content.querySelector("[role=alert]")?.remove();
    if(a.error){const error=document.createElement("p");error.textContent=a.error;error.id="card-error-"+this.session+"-"+node.key;error.setAttribute("role","alert");content.append(error);control.setAttribute("aria-describedby",error.id)}
    else control.removeAttribute("aria-describedby");
  }
  private plot(content:HTMLElement,plot:NonNullable<NonNullable<Node["attrs"]>["plot"]>):void {
    const canvas=document.createElement("canvas");canvas.width=640;canvas.height=240;canvas.style.width="100%";canvas.style.maxWidth="640px";
    canvas.setAttribute("role","img");canvas.setAttribute("aria-label",plot.kind+" chart; complete data table follows");
    const ctx=canvas.getContext("2d");if(!ctx)return;
    const values=plot.series.flatMap(series=>series.points.map(point=>point.value));
    const low=Math.min(0,...values),high=Math.max(0,...values),range=high-low||1;
    const y=(v:number)=>220-(v-low)/range*200;
    plot.series.forEach((series,seriesIndex)=>{
      ctx.strokeStyle=content.parentElement?.style.color||"currentColor";ctx.fillStyle=ctx.strokeStyle;ctx.globalAlpha=seriesIndex===0?1:0.6;ctx.setLineDash(seriesIndex===0?[]:[6,4]);ctx.lineWidth=2;ctx.beginPath();
      series.points.forEach((point,index)=>{const x=30+index*580/Math.max(1,series.points.length-1);
        if(plot.kind==="bar")ctx.fillRect(20+index*580/series.points.length+seriesIndex*10,Math.min(y(0),y(point.value)),8,Math.max(1,Math.abs(y(0)-y(point.value))));
        else if(index===0)ctx.moveTo(x,y(point.value));else ctx.lineTo(x,y(point.value));
      });if(plot.kind==="line")ctx.stroke();
    });content.append(canvas);
  }
}

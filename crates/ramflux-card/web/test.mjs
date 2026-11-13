// SPDX-License-Identifier: BSD-3-Clause
import {createRequire} from 'node:module';
import {readFile,writeFile,mkdtemp,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const require=createRequire(new URL('../library/package.json',import.meta.url));
const {build}=require('esbuild');const {Window}=require('happy-dom');
const deadline=setTimeout(()=>{process.stderr.write('DOM test deadline exceeded\n');process.exit(1)},30000);
// Match Node ESM's canonical module location, including macOS temporary-directory aliases.
const directory=await realpath(await mkdtemp(join(tmpdir(),'rf-card-dom #%-')));
try{
 const bundle=await build({entryPoints:[fileURLToPath(new URL('./adapter.ts',import.meta.url))],bundle:true,format:'esm',write:false,platform:'browser'});
 const settings=await build({entryPoints:[fileURLToPath(new URL('./settings.ts',import.meta.url))],bundle:true,format:'esm',write:false,platform:'browser'});
 await writeFile(join(directory,'adapter.mjs'),bundle.outputFiles[0].text);await writeFile(join(directory,'settings.mjs'),settings.outputFiles[0].text);
 const window=new Window({url:'https://cards.example.test/'});
 for(const key of ['document','HTMLElement','HTMLInputElement','HTMLSelectElement','MessageChannel'])if(window[key])globalThis[key]=window[key];
 window.HTMLCanvasElement.prototype.getContext=()=>null;
 const instances=[];
 class Port{onmessage=null;start(){}close(){this.closed=true}postMessage(data){this.sent.push(data)}sent=[];reply(data){this.onmessage?.({data})}}
 globalThis.MessageChannel=class{constructor(){this.port1=new Port();this.port2={owner:this.port1}}};
 globalThis.Worker=class{constructor(url){this.url=url;instances.push(this)}postMessage(data){this.port=data.port.owner;this.port.reply({ready:true})}terminate(){this.terminated=true}};
 const {CardView}=await import(pathToFileURL(join(directory,'adapter.mjs')).href);
 const {PresentationRegistry,HostSettings,contrast}=await import(pathToFileURL(join(directory,'settings.mjs')).href);
 const registry=new PresentationRegistry();const presentation=registry.resolve('en','light',false);
 assert.deepEqual(Object.keys(registry.resolve('zh-CN','dark',false).strings),Object.keys(presentation.strings));
 for(const name of ['light','dark']){const theme=registry.themes.get(name);assert(contrast(theme.text,theme.surface_white)>=4.5);assert(contrast(theme.on_primary,theme.primary)>=4.5);assert(contrast(theme.secondary,theme.surface_white)>=3)}
 const custom={...presentation.tokens,chart_1:'#123456'};registry.addTheme('custom',custom);assert.equal(registry.resolve('en','custom',false).tokens.chart_1,'#123456');
 assert.throws(()=>registry.addTheme('bad',{...custom,text:custom.surface_white}),/contrast/);assert.throws(()=>registry.addTheme('transparent',{...custom,text:'#00000000'}),/contrast/);
 registry.addLocale('pseudo','rtl',Object.fromEntries(Object.entries(presentation.strings).map(([k,v])=>[k,'［'+v+' extended extended］'])));
 assert.equal(registry.resolve('pseudo','custom',false).direction,'rtl');
 const storage=new Map();const system={matches:false,addEventListener(_,cb){this.cb=cb},removeEventListener(){}};
 const settingsStore=new HostSettings(registry,{getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v)},system);
 let selected;settingsStore.subscribe(p=>selected=p);settingsStore.select('zh-CN','system');system.matches=true;system.cb();assert.equal(selected.tokens.text,registry.themes.get('dark').text);
 const restored=new HostSettings(registry,{getItem:k=>storage.get(k)??null,setItem(){}},system);assert.equal(restored.current().locale,'zh-CN');settingsStore.dispose();restored.dispose();
 const workerURL=pathToFileURL(join(directory,'worker.js'));

 for(const rejected of [new URL('./other-worker.js',workerURL),new URL(workerURL.href+'?foreign'),new URL(workerURL.href+'#foreign'),new URL('https://foreign.example/worker.js')]){
  assert.throws(()=>new CardView(document.createElement('main'),rejected,()=>{},()=>{},()=>{},presentation),{message:presentation.strings.runtime_unavailable},'only the exact adjacent worker URL is accepted');
 }
 assert.equal(instances.length,0,'rejected worker URLs never allocate a worker');
 const failures=[],intents=[],slots=[];
 function view(){const root=document.createElement('main');document.body.append(root);return {root,card:new CardView(root,workerURL,(...a)=>intents.push(a),s=>slots.push(s),s=>failures.push(s),presentation),worker:instances.at(-1)}}
 const a=view(),b=view();assert.throws(()=>view(),new RegExp(presentation.strings.capacity));b.card.dispose();
 const n=(key,kind,value='',attrs={})=>({key,kind,value,text:key,action:null,children:[],attrs});
 const batch=(previous_version,version,mutations)=>({session:1,version,value:{previous_version,version,mutations}});
 const up=(node,parent=null,index=0)=>({op:'upsert',node,parent,index});
 const answer=(worker,value)=>{const request=worker.port.sent.shift();assert(request);worker.port.reply({seq:request.seq,json:JSON.stringify(value)});return request};
 const tick=async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve()};
 const opening=a.card.open('{}');await tick();answer(a.worker,batch(0,1,[up(n('root','column')),up(n('first','text_field','old'),'root'),up(n('second','number','20',{minimum:18,maximum:80}),'root',1),up(n('submit','submit'),'root',2)]));await opening;
 const first=a.root.querySelector('input[type=text]'),number=a.root.querySelector('input[type=number]'),button=a.root.querySelector('button');
 first.focus();first.value='new';first.dispatchEvent(new window.Event('change'));number.value='21';number.dispatchEvent(new window.Event('change'));await tick();assert.equal(a.worker.port.sent.length,2);assert(button.disabled);button.click();assert.equal(a.worker.port.sent.length,2);
 const firstEdit=answer(a.worker,batch(1,2,[up(n('first','text_field','new'),'root')]));assert.equal(JSON.parse(firstEdit.json).token.version,1);assert.equal(document.activeElement,first,'native input focus survives');
 const host=a.card.update('{}');await tick();const secondRequest=a.worker.port.sent.shift();const hostRequest=a.worker.port.sent.shift();assert(secondRequest&&hostRequest);
 a.worker.port.reply({seq:hostRequest.seq,json:JSON.stringify(batch(2,3,[up(n('second','number','40'),'root',1)]))});await host;
 a.worker.port.reply({seq:secondRequest.seq,json:JSON.stringify({session:1,version:3,value:{result:'stale_dropped'}})});await tick();assert.equal(number.value,'40');assert(failures.includes(presentation.strings.stale_edit));assert.equal(intents.length,0);
 for(const value of ['', '1.5']){number.value=value;number.dispatchEvent(new window.Event('change'));await tick();assert.equal(a.worker.port.sent.length,0);assert(button.disabled);assert.equal(a.root.querySelector('[role=alert]').textContent,presentation.strings.form_number)}
 number.value='17';number.dispatchEvent(new window.Event('change'));await tick();answer(a.worker,{session:1,version:4,value:{result:'validation',batch:{previous_version:3,version:4,mutations:[up(n('second','number','40',{error:presentation.strings.form_range}),'root',1)]}}});await tick();assert.equal(number.value,'40');assert.equal(a.root.querySelector('[role=alert]').textContent,presentation.strings.form_range);
 const changed=a.card.present(registry.resolve('zh-CN','dark',false));await tick();answer(a.worker,batch(4,5,[up(n('first','text_field','new'),'root')]));await changed;assert.equal(a.root.lang,'zh-CN');
 const requests=Array.from({length:32},()=>a.card.update('{}').catch(e=>e));await assert.rejects(a.card.update('{}'),new RegExp(registry.resolve('zh-CN','dark',false).strings.busy));await tick();
 const request=a.worker.port.sent.shift();a.worker.port.reply({seq:request.seq,json:JSON.stringify(batch(999,6,[]))});await Promise.all(requests);assert(a.root.inert);assert(a.worker.terminated);assert.deepEqual(slots.at(-1),[]);
 const replacement=view();const pending=replacement.card.open('{}').catch(e=>e);replacement.card.dispose();assert(await pending instanceof Error);assert(replacement.worker.terminated);a.card.dispose();
 const terminal=view();const pendingTerminal=terminal.card.open('{}').catch(e=>e);await tick();const terminalRequest=terminal.worker.port.sent.shift();terminal.worker.port.reply({seq:terminalRequest.seq,error:'content_unavailable',terminal:true});assert(await pendingTerminal instanceof Error);assert(terminal.root.inert);assert(terminal.worker.terminated);terminal.card.dispose();
 const recovery=view();const malformed=recovery.card.open('{').catch(e=>e);await tick();const malformedRequest=recovery.worker.port.sent.shift();recovery.worker.port.reply({seq:malformedRequest.seq,error:'content_unavailable',terminal:false});assert(await malformed instanceof Error);assert(!recovery.worker.terminated);recovery.card.dispose();
 for(const name of ['complete_form','task','chart','approval']){
  const fixture=view();let version=0;
  for(const suffix of ['mount','edit']){
   const mutations=JSON.parse(await readFile(new URL('../fixtures/'+name+'.'+suffix+'.json',import.meta.url)));
   const request=suffix==='mount'?fixture.card.open('{}'):fixture.card.update('{}');await tick();
   answer(fixture.worker,{session:1,version:mutations.version,value:mutations});await request;version=mutations.version;
   for(const mutation of mutations.mutations){
    const element=fixture.root.querySelector('[data-card-key="'+mutation.key+'"]');
    if(mutation.op==='remove'){assert(!element);continue}
    const node=mutation.node,shown=fixture.root.querySelector('[data-card-key="'+node.key+'"]');assert(shown,name+' '+node.key);
    if(node.text)assert(shown.textContent.includes(node.text),name+' fixture text');
   }
  }
  const removed=fixture.card.update('{}');await tick();answer(fixture.worker,batch(version,version+1,[{op:'remove',key:'root'}]));await removed;assert.equal(fixture.root.childElementCount,0);fixture.card.dispose();
 }
 await window.happyDOM.close();console.log('WEB_ADAPTER_TESTS_OK');
}finally{clearTimeout(deadline);await rm(directory,{recursive:true,force:true})}

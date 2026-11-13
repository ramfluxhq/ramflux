// SPDX-License-Identifier: BSD-3-Clause
// Run with a real Playwright page against the signed WASM preview HTTP origin.
// The barrier intercepts replies, never replaces the renderer or its messages.
export async function regression(page,origin,artifacts){
 await page.addInitScript(()=>{
  const Native=MessageChannel;let held=false,queue=[],waiters=[];
  window.replyBarrier={hold(){held=true},wait(count){return queue.length>=count?Promise.resolve():new Promise((resolve,reject)=>{const deadline=setTimeout(()=>reject(Error("reply barrier deadline")),10000);waiters.push({count,resolve:()=>{clearTimeout(deadline);resolve()}})})},release(){held=false;const replies=queue;queue=[];for(const run of replies)run()}};
  window.MessageChannel=class extends Native{constructor(){super();const setter=Object.getOwnPropertyDescriptor(MessagePort.prototype,'onmessage').set;
   Object.defineProperty(this.port1,'onmessage',{set(callback){setter.call(this,event=>{if(held&&event.data?.seq!==undefined){queue.push(()=>callback(event));for(const waiter of waiters.filter(w=>queue.length>=w.count))waiter.resolve();waiters=waiters.filter(w=>queue.length<w.count)}else callback(event)})}})
  }};
 });
 await page.goto(origin+'/tests/web-host.html');await page.waitForFunction(()=>window.card&&document.querySelector('input[type=text]')&&document.querySelector('[data-kind=approval_info]'));
 await page.evaluate(async()=>{
  replyBarrier.hold();const first=document.querySelector('input[type=text]'),second=document.querySelector('input[type=number]');
  first.value='Grace';first.dispatchEvent(new Event('change'));second.value='31';second.dispatchEvent(new Event('change'));
  if(!document.querySelector('button').disabled)throw Error('submit not fenced');document.querySelector('button').click();
  const host=structuredClone(selected);host.model.age=40;window.hostUpdate=card.update(JSON.stringify(host));await replyBarrier.wait(3);replyBarrier.release();await hostUpdate;
 });
 await page.waitForFunction(()=>document.querySelector('input[type=number]').value==='40'&&!document.querySelector('button').disabled);
 const state=await page.evaluate(()=>({first:document.querySelector('input[type=text]').value,second:document.querySelector('input[type=number]').value,notified:failures.length,intents:intents.length}));
 if(state.second!=='40'||!state.notified||state.intents)throw Error('stale reconciliation failed');
 await page.locator('button').click();await page.waitForFunction(()=>intents.length===1);
 const submission=await page.evaluate(()=>({intent:intents[0].fields,name:document.querySelector('input[type=text]').value,age:Number(document.querySelector('input[type=number]').value)}));
 if(submission.intent.name!==submission.name||submission.intent.age!==submission.age)throw Error('visible model differs from submitted intent');
 const security=await page.evaluate(async()=>{
  let markup=false,url=false;try{document.querySelector('#host').innerHTML='<img src=x onerror=alert(1)>'}catch{markup=true}
  try{new Worker('data:text/javascript,postMessage(1)')}catch{url=true}
  let rejected=false;try{await card.update('{')}catch{rejected=true}
  return {markup,url,rejected,inert:document.querySelector('#card').inert};
 });
 if(!security.markup||!security.url||!security.rejected||security.inert)throw Error('CSP/admission preservation failed');
 for(const locale of ['zh-CN','pseudo'])for(const theme of ['light','dark']){
  await page.goto(origin+'/tests/web-host.html?locale='+locale+'&theme='+theme+(locale==='pseudo'?'&rtl':''));
  await page.waitForFunction(()=>window.card&&document.querySelector('table')&&document.querySelector('button'));
  if(await page.locator('#card').getAttribute('lang')!==locale)throw Error('locale preview failed');
  if(artifacts)await page.screenshot({path:artifacts+'/rf-card-'+locale+'-'+theme+'.png',fullPage:true});
 }
 return 'SIGNED_WASM_DOM_REGRESSION_OK';
}
export async function terminalRegression(page,origin){
 await page.goto(origin+'/tests/web-host.html');await page.waitForFunction(()=>window.card&&document.querySelector('input[type=text]')&&document.querySelector('[data-kind=approval_info]'));
 const result=await page.evaluate(async()=>{
  const waiting=[card.update(JSON.stringify(selected)),card.update(JSON.stringify(selected))];
  const settled=await Promise.allSettled(waiting);
  return {settled:settled.every(result=>result.status==='rejected'),inert:document.querySelector('#card').inert,slots:slots.length,failures:failures.length,intents:intents.length};
 });
 if(!result.settled||!result.inert||result.slots||!result.failures||result.intents)throw Error('terminal VM cleanup failed');
 // Slot reuse is exercised by the DOM suite; here create the real worker again.
 await page.evaluate(async()=>{
  card.dispose();const CardView=window.CardView;
  const make=()=>{const root=document.createElement('main');document.body.append(root);return new CardView(root,new URL('../web/dist/worker.js',location.href),()=>{},()=>{},()=>{},settings.current())};
  const first=make(),second=make();try{await Promise.all([first.open(JSON.stringify(selected)),second.open(JSON.stringify(selected))])}finally{first.dispose();second.dispose()}
 });
 return 'SIGNED_WASM_TERMINAL_REGRESSION_OK';
}
export async function admissionRegression(page,origin){
 await page.goto(origin+'/tests/web-host.html');await page.waitForFunction(()=>window.card&&document.querySelector('input[type=text]')&&document.querySelector('[data-kind=approval_info]'));
 const result=await page.evaluate(async()=>{
  // Fixed bounded burst exercises the runtime's 128-admission window, no retry loop.
  const small=structuredClone(selected);small.components=small.components.filter(c=>c.component==='rf.form');
  await card.update(JSON.stringify(small));let refused=0;
  for(let group=0;group<5;group++){
   const results=await Promise.allSettled(Array.from({length:32},()=>card.update(JSON.stringify(small))));
   refused+=results.filter(result=>result.status==='rejected').length;
  }
  return {refused,inert:document.querySelector('#card').inert};
 });
 if(!result.refused||result.inert)throw Error('pre-execution admission refusal did not preserve view');
 return 'SIGNED_WASM_ADMISSION_REGRESSION_OK';
}

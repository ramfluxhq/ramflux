// SPDX-License-Identifier: BSD-3-Clause
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const {build}=createRequire(new URL('../library/package.json',import.meta.url))('esbuild');
const result=await build({entryPoints:[fileURLToPath(new URL('./worker.ts',import.meta.url))],write:false,bundle:true,format:'iife',define:{'import.meta.url':'"https://cards.example.test/worker.js"'},plugins:[{name:'typed-runtime-seam',setup(build){build.onResolve({filter:/^\.\/(pkg|release)\.js$/},args=>({path:args.path,namespace:'fixture'}));build.onLoad({filter:/.*/,namespace:'fixture'},args=>({contents:args.path.includes('release')?'export default {bytecode:[],descriptor:[],signature:[],publicKey:[],policy:"{}"}':`export default async function init(){};export class CardWorker{active=false;is_active(){return this.active}open(){this.active=true;return '{}'}update(input){if(input==='die'){this.active=false;throw Error('budget')}if(input==='reject')throw Error('input');return '{}'}event(){return '{}'}present(){return '{}'}suspend(){this.active=false;return '{}'}resume(){this.active=true;return '{}'}dispose(){this.active=false}}`}))}}]});
let connect;class Port{messages=[];postMessage(message){this.messages.push(message)}start(){}close(){this.closed=true}}
vm.runInNewContext(result.outputFiles[0].text,{URL,Uint8Array,WebAssembly,MessagePort:Port,self:{addEventListener(_kind,callback){connect=callback}}});
const port=new Port();await connect({data:{port,presentation:{}}});assert.deepEqual(port.messages.map(m=>m.ready),[true]);
function request(seq,op,json){port.onmessage({data:{seq,op,json}});return port.messages.at(-1)}
assert.equal(request(1,'open','{}').json,'{}');assert.equal(request(2,'update','reject').terminal,false);assert.equal(request(3,'update','{}').json,'{}');assert.equal(request(4,'update','die').terminal,true);
console.log('WORKER_LIVENESS_TESTS_OK');

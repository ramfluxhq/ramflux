// SPDX-License-Identifier: BSD-3-Clause
// Import the approved presentation specification, removing its provenance notes.
import {readFile,writeFile} from 'node:fs/promises';
const [source]=process.argv.slice(2);
if(!source)throw Error('usage: generate-render-metrics.mjs <approved-spec.json>');
const spec=JSON.parse(await readFile(source,'utf8'));
function values(value){
 if(Array.isArray(value))return value.map(values);
 if(!value||typeof value!=='object')return value;
 if('v' in value)return values(value.v);
 if('token' in value)return value.token;
 return Object.fromEntries(Object.entries(value).filter(([key])=>key!=='src').map(([key,child])=>[key,values(child)]));
}
await writeFile(new URL('./card/render-metrics.json',import.meta.url),JSON.stringify(values(Object.fromEntries(['foundations','card_frame','kinds'].map(key=>[key,spec[key]]))),null,2)+'\n');

// SPDX-License-Identifier: BSD-3-Clause
import {readFile} from 'node:fs/promises';
import {parse} from 'acorn';
import {fullAncestor} from 'acorn-walk';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
const en=JSON.parse(await readFile(new URL('../locales/en.json',import.meta.url))),zh=JSON.parse(await readFile(new URL('../locales/zh-CN.json',import.meta.url)));
assert.deepEqual(Object.keys(en).sort(),Object.keys(zh).sort());
for(const key of Object.keys(en))assert.deepEqual([...en[key].matchAll(/\{([^}]+)\}/g)].map(m=>m[1]).sort(),[...zh[key].matchAll(/\{([^}]+)\}/g)].map(m=>m[1]).sort(),key+' placeholders');
function check(code){fullAncestor(parse(code,{ecmaVersion:2022,sourceType:'module'}),(node,_state,ancestors)=>{
 if(node.type!=="Literal"||typeof node.value!=="string"||!node.value.length)return;
 const parent=ancestors.at(-2);
 const visibleAssignment=parent?.type==='AssignmentExpression'&&parent.left.type==='MemberExpression'&&['textContent','innerText','ariaLabel'].includes(parent.left.property.name);
 const visibleProperty=parent?.type==='Property'&&['text','label','title','error'].includes(parent.key.name);
 if(/\b[A-Za-z]+ [A-Za-z]+\b/.test(node.value)||visibleAssignment||visibleProperty)throw Error('hard-coded UI text: '+node.value);
})}
for(const code of ['const label="Save changes"','element.textContent="Submit"','const props={label:"Submit"}'])assert.throws(()=>check(code),/hard-coded/);
for(const file of ['../web/adapter.ts','../web/preview.ts','form.tsx']){const result=await build({entryPoints:[new URL(file,import.meta.url).pathname],bundle:false,write:false,format:'esm'});check(result.outputFiles[0].text)}
const generated=await build({entryPoints:[new URL('../../../src/generated/rf-tokens.ts',import.meta.url).pathname],bundle:true,write:false,format:'esm'});
const tokens=await import('data:text/javascript;base64,'+Buffer.from(generated.outputFiles[0].text).toString('base64'));
for(const name of ['light','dark'])assert.deepEqual(JSON.parse(await readFile(new URL('../themes/'+name+'.json',import.meta.url))),tokens[name],name+' tokens must match the generated source');
console.log('PRESENTATION_LINT_OK');

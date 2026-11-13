// SPDX-License-Identifier: BSD-3-Clause
// Run after wasm-bindgen --target web --out-dir web/pkg <ramflux_card.wasm>.
import {open,writeFile,mkdir,cp} from "node:fs/promises";
import {resolve,dirname} from "node:path";
import {fileURLToPath} from "node:url";
import {build} from "../library/node_modules/esbuild/lib/main.js";
const [prefix,policyPath,outputPath]=process.argv.slice(2);
if(!prefix || !policyPath)throw Error("usage: node web/build-web.mjs <release-prefix> <independently-pinned-host-policy.json>");
const root=dirname(fileURLToPath(import.meta.url));
const output=outputPath?resolve(outputPath):resolve(root,"dist");
async function bounded(path,limit){const file=await open(path,"r");try{const buffer=Buffer.alloc(limit+1);let size=0;
  while(size<buffer.length){const {bytesRead}=await file.read(buffer,size,buffer.length-size,null);if(!bytesRead)break;size+=bytesRead}
  if(size>limit)throw Error("public release artifact exceeds bound");return buffer.subarray(0,size)
}finally{await file.close()}}
const release={
  bytecode:[...await bounded(prefix+".qjb",65536)],
  descriptor:[...await bounded(prefix+".descriptor.json",4096)],
  signature:[...await bounded(prefix+".sig",64)],
  publicKey:[...await bounded(prefix+".pub",32)],
  policy:(await bounded(policyPath,4096)).toString("utf8")
};
if(release.signature.length!==64 || release.publicKey.length!==32)throw Error("release key/signature size");
await writeFile(resolve(root,"release.js"),"// App-pinned public release material; no private signing keys.\nexport default "+JSON.stringify(release)+";\n");
await mkdir(output,{recursive:true});
await build({entryPoints:[resolve(root,"worker.ts"),resolve(root,"adapter.ts")],outdir:output,
  bundle:true,format:"esm",platform:"browser",target:"es2022",alias:{env:resolve(root,"env.ts")}});
await cp(resolve(root,"pkg"),resolve(output,"pkg"),{recursive:true});
console.log("WEB_BUNDLE_OK");

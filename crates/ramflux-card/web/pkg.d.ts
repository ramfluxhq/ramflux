// SPDX-License-Identifier: BSD-3-Clause
export default function init(input?:{module_or_path:URL}):Promise<unknown>;
export class CardWorker {
 constructor(bytecode:Uint8Array,descriptor:Uint8Array,signature:Uint8Array,key:Uint8Array,policy:string,presentation:string);
 open(json:string):string; update(json:string):string; event(json:string):string; present(json:string):string;
 is_active():boolean; suspend():string;resume():string;dispose():void;
}

// SPDX-License-Identifier: BSD-3-Clause
import type {KindRenderer} from '../types';
import {el,button} from '../parts/primitives';
export const render:KindRenderer=(n,c)=>{
 const e=el('div','rf-modal'),slot=c.slots.find(s=>s.kind==='modal'&&s.key===n.key);
 const key=String(slot?.trigger_key??n.children[0]??''),content=String(slot?.content_key??n.children[1]??'');
 const child=c.render(key);
 const trigger=child.tagName==='BUTTON'?child as HTMLButtonElement:button('',()=>{},'default');
 if(child!==trigger)trigger.append(child);
 trigger.onclick=()=>c.modal(n.key,trigger,content);
 trigger.dataset.controlKey=n.key+'-trigger';trigger.disabled=c.readOnly;e.append(trigger);return e;
};

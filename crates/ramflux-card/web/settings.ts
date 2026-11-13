// SPDX-License-Identifier: BSD-3-Clause
import en from "../locales/en.json";
import zh from "../locales/zh-CN.json";
import light from "../themes/light.json";
import dark from "../themes/dark.json";
import type {HostPresentation,Strings} from "../library/presentation-types";
import type {RFTheme} from "../../../src/generated/rf-tokens";
export type {HostPresentation,Strings};
export type ThemeChoice=string;
export class PresentationRegistry {
  readonly themes=new Map<string,RFTheme>();
  readonly locales=new Map<string,{strings:Strings;direction:"ltr"|"rtl"}>();
  constructor(){this.addTheme("light",light);this.addTheme("dark",dark);this.addLocale("en","ltr",en);this.addLocale("zh-CN","ltr",zh)}
  addTheme(name:string,value:unknown):void {
    if(!/^[a-zA-Z0-9-]{1,64}$/.test(name)||name==="system")throw Error("invalid_theme");
    const data=value as Record<string,unknown>;
    if(!data||Object.keys(data).sort().join()!==Object.keys(light).sort().join())throw Error("theme_keys");
    for(const [key,reference] of Object.entries(light)){
      const token=data[key];
      if(typeof reference==="number"?typeof token!=="number"||!Number.isFinite(token)||token<0||token>2048:
        typeof token!=="string"||token.length>256||(reference.startsWith("#")?!/^#[a-fA-F0-9]{6}([a-fA-F0-9]{2})?$/.test(token):/[;{}()]/.test(token)))throw Error("theme_token");
    }
    const theme=Object.freeze({...data}) as unknown as RFTheme;
    if(!Number.isInteger(theme.gap)||theme.gap>64)throw Error("theme_geometry");
    if([theme.text,theme.surface_white,theme.on_primary,theme.primary,theme.secondary].some(value=>value.length===9&&!value.toLowerCase().endsWith("ff")))throw Error("theme_contrast");
    if(contrast(theme.text,theme.surface_white)<4.5||contrast(theme.on_primary,theme.primary)<4.5||contrast(theme.secondary,theme.surface_white)<3)throw Error("theme_contrast");
    this.themes.set(name,theme);
  }
  addLocale(locale:string,direction:"ltr"|"rtl",value:unknown):void{
    const data=value as Record<string,unknown>;
    if(!/^[a-zA-Z0-9-]{1,35}$/.test(locale)||!data||Object.keys(data).sort().join()!==Object.keys(en).sort().join()||
      Object.values(data).some(v=>typeof v!=="string"||!v.length||new TextEncoder().encode(v).length>1024)||new TextEncoder().encode(JSON.stringify(data)).length>8192)throw Error("locale_table");
    this.locales.set(locale,{direction,strings:Object.freeze({...data}) as Strings});
  }
  resolve(locale:string,theme:string,systemDark:boolean):HostPresentation {
    const language=this.locales.get(locale),tokens=this.themes.get(theme==="system"?(systemDark?"dark":"light"):theme);
    if(!language||!tokens)throw Error("presentation_selection");
    return {locale,direction:language.direction,strings:language.strings,tokens};
  }
}
export class HostSettings {
  private choice="system";private locale="en";
  private readonly listeners=new Set<(presentation:HostPresentation)=>void>();
  private readonly changed=()=>this.publish();
  constructor(readonly registry:PresentationRegistry,private readonly storage:Pick<Storage,"getItem"|"setItem">,private readonly system:Pick<MediaQueryList,"matches"|"addEventListener"|"removeEventListener">){
    try{const saved=JSON.parse(storage.getItem("rf.card.presentation")??"null");if(saved&&registry.locales.has(saved.locale)&&(saved.theme==="system"||registry.themes.has(saved.theme))){this.locale=saved.locale;this.choice=saved.theme}}catch{}
    system.addEventListener("change",this.changed);
  }
  selection():Readonly<{locale:string;theme:string}>{return {locale:this.locale,theme:this.choice}}
  current():HostPresentation{return this.registry.resolve(this.locale,this.choice,this.system.matches)}
  select(locale:string,theme:string):void{this.registry.resolve(locale,theme,this.system.matches);this.locale=locale;this.choice=theme;try{this.storage.setItem("rf.card.presentation",JSON.stringify({locale,theme}))}catch{}this.publish()}
  subscribe(listener:(presentation:HostPresentation)=>void):()=>void{this.listeners.add(listener);listener(this.current());return()=>this.listeners.delete(listener)}
  dispose():void{this.system.removeEventListener("change",this.changed);this.listeners.clear()}
  private publish():void{const value=this.current();for(const listener of this.listeners)listener(value)}
}
export function contrast(a:string,b:string):number{
  const luminance=(color:string)=>{const values=[1,3,5].map(index=>parseInt(color.slice(index,index+2),16)/255).map(v=>v<=0.04045?v/12.92:((v+0.055)/1.055)**2.4);return (values[0]??0)*0.2126+(values[1]??0)*0.7152+(values[2]??0)*0.0722};
  const first=luminance(a),second=luminance(b);return (Math.max(first,second)+0.05)/(Math.min(first,second)+0.05);
}

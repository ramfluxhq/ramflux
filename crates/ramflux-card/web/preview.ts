// SPDX-License-Identifier: BSD-3-Clause
import {CardView} from './adapter';
import {HostSettings,PresentationRegistry} from './settings';
const registry=new PresentationRegistry();
const query=new URLSearchParams(location.search);
if(query.get('locale')==='pseudo'){
 const source=registry.resolve('en','light',false).strings;
 registry.addLocale('pseudo',query.has('rtl')?'rtl':'ltr',Object.fromEntries(Object.entries(source).map(([k,v])=>[k,'［'+v.repeat(3)+'］'])));
}
const settings=new HostSettings(registry,localStorage,matchMedia('(prefers-color-scheme: dark)'));
if(query.has('locale')||query.has('theme'))settings.select(query.get('locale')??'en',query.get('theme')??'system');
const root=document.querySelector<HTMLElement>('#card')!,status=document.querySelector<HTMLElement>('#status')!,host=document.querySelector<HTMLElement>('#host')!,controls=document.querySelector<HTMLElement>('#settings')!;
const language=document.createElement('select'),theme=document.createElement('select');
for(const name of registry.locales.keys()){const option=document.createElement('option');option.value=name;option.textContent=name;language.append(option)}
for(const name of ['system',...registry.themes.keys()]){const option=document.createElement('option');option.value=name;theme.append(option)}
const languageLabel=document.createElement('label'),themeLabel=document.createElement('label'),languageText=document.createElement('span'),themeText=document.createElement('span');
languageLabel.append(languageText,language);themeLabel.append(themeText,theme);controls.append(languageLabel,themeLabel);
const intents:unknown[]=[],failures:string[]=[];let slots:unknown=[];
const card=new CardView(root,new URL('./worker.js',import.meta.url),(action,fields)=>{intents.push({action,fields});status.textContent=settings.current().strings.preview_submitted},value=>{slots=value;host.textContent=value.length?settings.current().strings.preview_host:''},error=>{failures.push(error);status.textContent=error},settings.current());
let opened=false;
settings.subscribe(p=>{
 const tokens=p.tokens;document.body.style.color=tokens.text;document.body.style.backgroundColor=tokens.surface_white;document.body.style.fontFamily=tokens.font;document.body.style.fontSize=tokens.size_body+'px';document.body.style.padding=tokens.gap+'px';
 controls.style.display='flex';controls.style.flexWrap='wrap';controls.style.gap=tokens.gap+'px';
 for(const select of [language,theme]){select.style.color=tokens.text;select.style.backgroundColor=tokens.surface_white;select.style.borderColor=tokens.secondary;select.style.borderRadius=tokens.radius_input+'px';select.style.fontFamily=tokens.font;select.style.fontSize=tokens.size_body+'px'}
 document.title=p.strings.preview_title;document.documentElement.lang=p.locale;document.documentElement.dir=p.direction;
 status.textContent=p.strings.preview_starting;root.setAttribute('aria-label',p.strings.preview_title);host.setAttribute('aria-label',p.strings.preview_host);
 languageText.textContent=p.strings.locale_label;themeText.textContent=p.strings.theme_label;
 language.setAttribute('aria-label',p.strings.locale_label);theme.setAttribute('aria-label',p.strings.theme_label);language.value=p.locale;theme.value=settings.selection().theme;
 for(const option of Array.from(theme.options))option.textContent=p.strings[('theme_'+option.value) as 'theme_light']??option.value;
 if(opened)void card.present(p).then(()=>{status.textContent=p.strings.preview_ready}).catch(()=>{status.textContent=p.strings.content_unavailable});
});
language.onchange=theme.onchange=()=>settings.select(language.value,theme.value);
const fixtures=await Promise.all(['complete_form','task','chart','approval'].map(async name=>await(await fetch('../fixtures/'+name+'.json')).json()));
const selected={catalog:'rf-card/v1',model:fixtures[0].model,components:fixtures.flatMap(f=>f.components)};
Object.assign(window,{card,CardView,intents,failures,selected,settings});Object.defineProperty(window,"slots",{get:()=>slots});
await card.open(JSON.stringify(selected));opened=true;status.textContent=settings.current().strings.preview_ready;
window.addEventListener('pagehide',()=>{settings.dispose();card.dispose()},{once:true});

// SPDX-License-Identifier: BSD-3-Clause
// Build-time story inventory. IDs are a public cross-host capture contract.
import { readFile } from 'node:fs/promises';
const load = async (path) => JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'));
function expandText(value) {
    if (Array.isArray(value)) {
        for (const item of value)
            expandText(item);
        return;
    }
    if (!value || typeof value !== 'object')
        return;
    for (const [key, child] of Object.entries(value)) {
        if (['text', 'label', 'title', 'description', 'explanation'].includes(key) && typeof child === 'string')
            value[key] = (child + ' — A longer reference message for reviewing wrapping and reading order.').repeat(3).slice(0,key==='label'?48:key==='title'?96:key==='description'?200:512);
        else if (key !== 'action' && key !== '@checks')
            expandText(child);
    }
}
// The generated gallery inputs are author examples, independent of test snapshots.
function realistic(input) {
 const labels={input:'Project name',age:'Review effort',agree:'Include archived notes',color:'Sources',date:'Review date'};
 for(const c of input.snapshot.components){
  if(c.label==='Name')c.label=labels[c.id]??'Project name';
  if(c.component==='TextField'){c.label+=' *';c.placeholder='Enter a project name';c['@checks']=[{condition:{'@call':'required',args:{value:c.value}},message:'Enter a project name'}]}
  if(c.component==='Slider')c.steps=10;
  if(c.component==='Tabs')c.tabs.forEach((t,i)=>t.title=['Overview','Activity'][i]??t.title);
  if(c.component==='Text'&&['First','Second','Sheet','Open'].includes(c.text))c.text=({First:'Project notes and reference files.',Second:'Changes shared with the project today.',Sheet:'Review the project scope before saving your changes.',Open:'Review details'})[c.text];
  if(c.component==='Image')c.description='Research summary · reference attachment';
  if(c.component==='Text'&&c.text==='Save')c.text='Save project';
  if(c.component==='Text'&&c.text==='Item')c.text='Research notes · updated today';
  if(c.component==='ChoicePicker'){c.options=[{label:'Current channel',value:'blue'},{label:'Selected files',value:'red'}]}
  if(c.component==='Approval')c.explanation='Read the selected notes to prepare a release summary. Only the requested folder is needed.';
  if(c.component==='Task'){c.title='Prepare release notes';c.progress=64;c.steps=[{id:'collect',text:'Collect merged changes',status:'completed'},{id:'review',text:'Review compatibility notes',status:'completed'},{id:'write',text:'Draft release summary',status:'running'},{id:'publish',text:'Share for approval',status:'pending'}]}
  if(c.component==='Table'){c.columns=[{key:'resource',label:'Resource'},{key:'owner',label:'Owner'},{key:'ready',label:'Ready'},{key:'items',label:'Items'}];c.rows=[{key:'research',cells:['Research notes','Lin',true,24]},{key:'design',cells:['Design review','Ada',true,12]},{key:'release',cells:['Release summary','Nova',false,8]}]}
  if(c.component==='Chart'){c.series=[{id:'a',label:'This week',points:[{label:'Mon',value:32},{label:'Tue',value:44},{label:'Wed',value:38},{label:'Thu',value:58},{label:'Fri',value:52}]},{id:'b',label:'Last week',points:[{label:'Mon',value:24},{label:'Tue',value:35},{label:'Wed',value:30},{label:'Thu',value:40},{label:'Fri',value:36}]}]}
 }
 const form=input.snapshot.components.find(c=>c.id==='form'&&c.component==='Column');if(form&&form.children.includes('button')){form.children=[...form.children.filter(id=>id!=='button'),'actions'];input.snapshot.components.push({id:'actions',component:'Row',justify:'end',children:['button']});const submit=input.snapshot.components.find(c=>c.id==='button');submit.variant='primary'}
 for(const c of input.snapshot.components)if(c.component==='Button'&&input.snapshot.components.some(x=>x.id==='input'))c['@checks']=[{condition:{'@call':'required',args:{value:{'@path':'/name'}}},message:'Enter a project name'}];
 return input;
}
export async function galleryData() {
    const index = await load('../host-fixtures/index.json');
    const catalog = await load('../../ramflux-protocol/catalogs/rf-card-v1.json');
    const common = await load('../../ramflux-protocol/vendor/a2ui/specification/v1_0/json/common_types.json');
    const stories = [];
    const add = (id, kind, variant, state, group, input, source, outcome = 'tree') => {input.snapshot.components.sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);return stories.push({ id, kind, variant, state, group, input, source, outcome })};
    for (const row of index.cases) {
        const input = realistic(await load('../host-fixtures/' + row.fixture)), variant = row.variant ?? 'unset';
        const base = `component/${row.kind}/${variant}`;
        add(base + '/default', row.kind, variant, 'default', 'Components', input, row.fixture, row.outcome);
        if (row.outcome === 'refused')
            continue;
        const states = ['Icon', 'Divider'].includes(row.kind) ? [] : ['long-text'];
        if(row.kind==='Icon')states.push('all-icons');
        if(row.kind==='Text'&&row.variant==='body')states.push('markdown');
        if (row.kind === 'Button') states.push('disabled','hover','pressed','focus','busy','consumed');
        if(row.kind==='Button'&&row.variant==='borderless')states.push('link');
        if (['TextField','CheckBox','ChoicePicker','Slider','DateTimeInput'].includes(row.kind)) states.push('disabled','closed','stale');
        if (row.kind === 'Approval') states.push('pending','approved','denied','expired','superseded','withdrawn','medium-risk','high-risk','other-owner');
        if (row.kind === 'Image') states.push('loading','failed','loaded');
        if (row.kind === 'Chart') states.push('bar','loading','failed');
        if (row.kind === 'Task') states.push('pending','delivered','running','completed','refused','cancelled');
        if (row.kind === 'ChoicePicker') states.push('chips','menu','filterable');
        if (row.kind === 'List') states.push('horizontal','overflow');
        if (row.kind === 'Tabs') states.push('many-tabs');
        if (row.kind === 'Table') states.push('overflow');
        if (row.kind === 'Divider') states.push('vertical');
        if (row.kind === 'DateTimeInput') states.push('time-only','date-time','read-only');
        if (['TextField', 'CheckBox', 'ChoicePicker', 'Slider', 'DateTimeInput'].includes(row.kind))
            states.push('error');
        if (['Text', 'TextField', 'List', 'Table', 'Chart'].includes(row.kind))
            states.push('empty');
        if (row.kind === 'Task')
            states.push('loading');
        for (const state of states) {
            const value = structuredClone(input), root = value.snapshot.components.find(c => c.id === 'root');
            if (state === 'long-text')
                expandText(value.snapshot.components);
            if(state==='markdown')root.text='**Ready for review**\nThe release includes *compatibility notes* and `local-only` drafts.\n- Review the changes\n- Share the summary';
            if(state==='link')root.action={functionCall:{'@call':'openUrl',args:{url:'https://example.com/research'}}};
            if(state==='bar')root.kind='bar';
            if(state==='chips')root.displayStyle='chips';
            if(['menu','filterable'].includes(state)){root.options=Array.from({length:8},(_,i)=>({label:['Design notes','Research','Engineering','Release','Support','Archive','Roadmap','Operations'][i],value:String(i)}));root.filterable=true;value.snapshot.dataModel.color=['1']}
            if(state==='many-tabs'){root.tabs=Array.from({length:6},(_,i)=>({title:['Overview','Activity','Files','People','History','Notes'][i],child:'tab'+i}));value.snapshot.components=[root,...root.tabs.map((t,i)=>({id:t.child,component:'Text',text:'Project '+t.title.toLowerCase()+' · '+(i+1)+' entries to review.'}))]}
            if(state==='horizontal'){root.direction='horizontal';root.children=Array.from({length:5},(_,i)=>'tile'+i);value.snapshot.components=[root,...root.children.flatMap((id,i)=>[{id,component:'Column',children:[id+'icon',id+'label']},{id:id+'icon',component:'Icon',name:['folder','photo','event','info','check'][i]},{id:id+'label',component:'Text',text:['Research','Designs','Schedule','Release notes','Ready for review'][i]}])]}
            if(state==='vertical')root.axis='vertical';
            if(state==='overflow'&&row.kind==='Table')root.rows=Array.from({length:12},(_,i)=>({key:'row'+i,cells:['Milestone '+(i+1),'Lin',i%2===0,i*3]}));
            if(state==='overflow'&&row.kind==='List'){root.children=Array.from({length:8},(_,i)=>'entry'+i);value.snapshot.components=[root,...root.children.map((id,i)=>({id,component:'Text',text:'Release checklist item '+(i+1)}))]}
            if(['pending','delivered','running','completed','refused','cancelled'].includes(state)&&row.kind==='Task')root.status=state;
            if(state==='time-only'){root.enableDate=false;root.enableTime=true;value.snapshot.dataModel.when='14:30'}
            if(state==='date-time'){root.enableDate=true;root.enableTime=true;value.snapshot.dataModel.when='2026-11-24T14:30:00Z'}
            // Read-only is a host presentation state; the admitted temporal type is kept.
            if (state === 'disabled' || state === 'error') {
                value.snapshot.dataModel.galleryValid = false;
                root['@checks'] = [{ condition: { '@path': '/galleryValid' }, message: 'Review the required value before continuing.' }];
            }
            if (state === 'empty') {
                if(row.kind==='Text')root.text='';
                if (row.kind === 'TextField')
                    value.snapshot.dataModel.name = '';
                if (row.kind === 'List') {
                    root.children = [];
                    value.snapshot.components = [root];
                }
                if (row.kind === 'Table')
                    root.rows = [];
                if (row.kind === 'Chart')
                    for (const series of root.series)
                        series.points = [];
            }
            if (state === 'loading' && row.kind==='Task') {
                root.status = 'pending';
                root.progress = null;
                root.steps = [];
            }
            add(base + '/' + state, row.kind, variant, state, 'Components', value, row.fixture);
        }
    }
    for (const name of ['approval', 'chart', 'form', 'complete_form', 'task'])
        add(`example/${name}`, 'Example', name, 'default', 'Composed examples', realistic(await load('../fixtures/' + name + '.json')), 'fixtures/' + name + '.json');
    for (const [variant, file] of [['approval-request', 'approval'], ['permission-request', 'approval'], ['task-progress', 'task']]) {
        const input = realistic(await load('../fixtures/' + file + '.json')), root = input.snapshot.components.find(c => c.id === 'root');
        if (file === 'approval') {
            root.requestRef = 'gallery-' + variant;
            root.explanation = variant === 'permission-request' ? 'The agent requests permission to read a selected project folder. Host-verified facts and approval controls belong to the native host.' : 'The agent requests approval to publish the prepared release. Review the host-owned request record before deciding.';
        }
        else {
            root.title = 'Prepare release notes';
            root.progress = 64;
            root.steps = [{ id: 'collect', text: 'Collect changes', status: 'completed' }, { id: 'summarize', text: 'Summarize changes', status: 'running' }];
        }
        add(`agent/${variant}`, 'Agent', variant, 'default', 'Agent scenarios', input, 'fixtures/' + file + '.json');
    }
    for(const state of ['streaming','superseded','out-of-sync','draft-replaced','failed']){const input=realistic(await load('../fixtures/complete_form.json'));add('example/complete_form/'+state,'Example','complete_form',state,'Composed examples',input,'fixtures/complete_form.json')}
    return { schema: 'ramflux.card.stories.v1', stories, catalog, common };
}

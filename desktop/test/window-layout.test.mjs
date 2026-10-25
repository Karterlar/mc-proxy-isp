import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir,mkdtemp,rm,writeFile } from 'node:fs/promises';
import { windowLayout,createWindowLayoutStore } from '../window-layout.mjs';
import { fitWindow,WINDOW_LAYOUTS } from '../window-policy.mjs';

test('presets and saved custom dimensions fit a small or displaced display without locking the aspect ratio',()=>{
  const area={x:-800,y:40,width:800,height:700};
  for(const size of [...Object.values(WINDOW_LAYOUTS),{width:1200,height:1100},{width:NaN,height:800}]){
    const b=fitWindow(area,size);assert.ok(b.x>=area.x&&b.y>=area.y&&b.x+b.width<=0&&b.y+b.height<=740);assert.ok(b.width>=380&&b.height>=650);
  }
  assert.equal(fitWindow({x:0,y:0,width:2000,height:1200},WINDOW_LAYOUTS.tall).width,480);
  for(const value of [null,{bounds:{}},{bounds:{x:0,y:0,width:Infinity,height:800}},{bounds:{x:0,y:0,width:400,height:400}}])assert.equal(windowLayout(value),null);
  assert.equal(windowLayout({preset:'unexpected',bounds:{x:0,y:0,width:600,height:900}}).preset,'custom');
});
test('latest custom window bounds survive restart, invalid saved settings are ignored',async t=>{
  const base=path.resolve('.cache');await mkdir(base,{recursive:true});const folder=await mkdtemp(path.join(base,'window-layout-'));t.after(()=>rm(folder,{recursive:true,force:true}));
  const file=path.join(folder,'window-layout.json'),store=createWindowLayoutStore(file);
  const bounds={x:-100,y:60,width:580,height:820};
  await Promise.all([store.write({preset:'wide',bounds:{...bounds,width:1080}}),store.write({preset:'custom',bounds})]);
  assert.deepEqual(await createWindowLayoutStore(file).read(),{version:1,preset:'custom',bounds});
  await writeFile(file,'{"preset":"wide","bounds":{"width":999999}}');assert.equal(await store.read(),null);
});

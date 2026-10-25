import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { WINDOW_LAYOUTS } from './window-policy.mjs';

export function windowLayout(value) {
  const bounds=value?.bounds;
  if(!bounds||![bounds.x,bounds.y,bounds.width,bounds.height].every(Number.isInteger)
    ||bounds.width<380||bounds.width>4096||bounds.height<650||bounds.height>2160||Math.abs(bounds.x)>100000||Math.abs(bounds.y)>100000)return null;
  return {version:1,preset:Object.hasOwn(WINDOW_LAYOUTS,value.preset)?value.preset:'custom',bounds:{x:bounds.x,y:bounds.y,width:bounds.width,height:bounds.height}};
}
export function createWindowLayoutStore(file) {
  let writing=Promise.resolve();
  return {
    async read(){try{return windowLayout(JSON.parse(await readFile(file,'utf8')));}catch{return null;}},
    write(value){
      const data=windowLayout(value);if(!data)return Promise.resolve();
      writing=writing.catch(()=>{}).then(async()=>{await mkdir(path.dirname(file),{recursive:true});await writeFile(file+'.tmp',JSON.stringify(data),'utf8');await rename(file+'.tmp',file);});
      return writing;
    },
  };
}

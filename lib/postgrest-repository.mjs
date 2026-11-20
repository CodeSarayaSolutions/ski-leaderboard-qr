// Node-only transport. The production entry point additionally imports server-only.
import {Buffer} from 'node:buffer';
import {Rejected} from './receipt.mjs';
export const API_SCHEMA='alpine_qr_api';
const names=new Set(['lookup_key','receipt_status','submit','list_scores','list_keys','register_key','revoke_key']);
function config(env){
 try {
  if(env.NEXT_PUBLIC_SUPABASE_DB_SCHEMA!=='velo-leaderboard')throw 0;
  const raw=env.NEXT_PUBLIC_SUPABASE_URL,u=new URL(raw);
  if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||!['','/'].includes(u.pathname)||u.hostname.endsWith('.invalid'))throw 0;
  const key=env.SUPABASE_SERVICE_ROLE_KEY;
  if(typeof key!=='string'||key.length<32||key.length>8192||/[\s\r\n]/.test(key))throw 0;
  // Legacy Supabase service_role JWT only. This check is not signature validation;
  // the configured Supabase gateway verifies the credential. Never fall back to anon.
  const parts=key.split('.');if(parts.length!==3||parts.some(x=>! /^[A-Za-z0-9_-]+$/.test(x)))throw 0;
  const claims=JSON.parse(Buffer.from(parts[1],'base64url'));
  if(claims.role!=='service_role'||(claims.exp!==undefined&&(!Number.isFinite(claims.exp)||claims.exp*1000<=Date.now())))throw 0;
  return {origin:u.origin,key};
 }catch{throw new Rejected('Service not configured',503);}
}
export function createRepository({env=process.env,fetchImpl=globalThis.fetch,timeoutMs=5000}={}){
 async function rpc(name,args){
  if(!names.has(name))throw new Rejected('Service not configured',503);
  const {origin,key}=config(env);
  try {
   const response=await fetchImpl(origin+'/rest/v1/rpc/'+name,{
    method:'POST',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(timeoutMs),
    headers:{'Content-Type':'application/json',Accept:'application/json','Content-Profile':API_SCHEMA,'Accept-Profile':API_SCHEMA,apikey:key,Authorization:'Bearer '+key},body:JSON.stringify(args)
   });
   if(!response.ok)throw 0;
   // Bound private response buffering; never include response details in errors/logs.
   const reader=response.body?.getReader();if(!reader)throw 0;let chunks=[],size=0;
   for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>1048576){await reader.cancel();throw 0;}chunks.push(value);}
   return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }catch{throw new Rejected('Service temporarily unavailable',503);}
 }
 const array=v=>{if(!Array.isArray(v))throw new Rejected('Service temporarily unavailable',503);return v;};
 return {
  async key(kid){return array(await rpc('lookup_key',{k:kid}))[0];},
  async status(run,hash){const v=await rpc('receipt_status',{r:run,h:hash});if(!['new','saved','conflict'].includes(v))throw new Rejected('Service temporarily unavailable',503);return v;},
  async insert(p,hash,c){const v=await rpc('submit',{r:p.run,k:p.kid,d:p.device,e:p.event,n:p.name,t:p.ms,a:p.at,s:p.scope,h:hash,em:c.email,ph:c.phone});if(v!=='saved')throw new Rejected('Run cannot be submitted',409);},
  async scores(page){return array(await rpc('list_scores',{skip:page*50,take:50}));},
  async keys(){return array(await rpc('list_keys',{}));},
  async register(k,device,event){await rpc('register_key',{k:k.kid,p:k.pem,d:device,e:event});},
  async revoke(kid){await rpc('revoke_key',{k:kid});}
 };
}

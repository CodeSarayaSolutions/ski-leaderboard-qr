import {createHash,createHmac,timingSafeEqual,randomBytes} from 'node:crypto';
import {Rejected} from './receipt.mjs';
const equal=(a,b)=>timingSafeEqual(createHash('sha256').update(a||'').digest(),createHash('sha256').update(b||'').digest());
export class Limiter{constructor(limit=8,window=900000){this.limit=limit;this.window=window;this.entries=new Map();}take(key,now=Date.now()){for(const [k,v]of this.entries)if(v.until<=now)this.entries.delete(k);let v=this.entries.get(key);if(!v){if(this.entries.size>5000)throw new Rejected('Try again later',429);v={count:0,until:now+this.window};this.entries.set(key,v);}if(++v.count>this.limit)throw new Rejected('Try again later',429);}}
export const loginLimiter=new Limiter(8),submitLimiter=new Limiter(300,60000);
export function configuration(env,headers){
 if(!env.SESSION_SECRET||env.SESSION_SECRET.length<32)throw new Rejected('Admin not configured',503);
 if(env.ADMIN_MODE==='local'){
  if(!env.INTERNAL_LOOPBACK_TOKEN||!equal(headers.get('x-internal-loopback'),env.INTERNAL_LOOPBACK_TOKEN)||!env.ADMIN_LOCAL_PIN)throw new Rejected('Local admin unavailable',403);
  return {credential:env.ADMIN_LOCAL_PIN,secure:false};
 }
 if(env.ADMIN_MODE!=='public'||!env.APP_ORIGIN?.startsWith('https://')||!env.ADMIN_PUBLIC_CREDENTIAL||env.ADMIN_PUBLIC_CREDENTIAL.length<16||/^\d{4}$/.test(env.ADMIN_PUBLIC_CREDENTIAL))throw new Rejected('Public admin not configured',503);
 return {credential:env.ADMIN_PUBLIC_CREDENTIAL,secure:true};
}
function mac(value,env){return createHmac('sha256',env.SESSION_SECRET).update(value).digest('base64url');}
export function signIn(value,env,headers,now=Date.now(),limiter=loginLimiter){const c=configuration(env,headers);limiter.take('admin-global',now);if(typeof value!=='string'||value.length>256||!equal(value,c.credential))throw new Rejected('Sign-in failed',401);const body=Buffer.from(JSON.stringify({exp:now+3600000,nonce:randomBytes(16).toString('hex'),mode:env.ADMIN_MODE})).toString('base64url');return {token:body+'.'+mac(body,env),secure:c.secure};}
export function authorize(token,env,headers,now=Date.now()){configuration(env,headers);try{const [body,sig,...extra]=(token||'').split('.');if(extra.length||!sig||!equal(sig,mac(body,env)))throw 0;const p=JSON.parse(Buffer.from(body,'base64url'));if(p.mode!==env.ADMIN_MODE||!Number.isSafeInteger(p.exp)||p.exp<=now||p.exp>now+3600000)throw 0;return true;}catch{throw new Rejected('Sign in required',401);}}
export function sameOrigin(request,env){if(!env.APP_ORIGIN||request.headers.get('origin')!==env.APP_ORIGIN)throw new Rejected('Request origin rejected',403);}

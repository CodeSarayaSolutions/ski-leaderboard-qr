import {createPublicKey,createHash,verify} from 'node:crypto';
export const scope='fast/summit-competition-v2-r3-5s-r1';
const fields=['v','kid','device','event','run','name','ms','at','scope'];
export class Rejected extends Error {constructor(message='Invalid or unavailable receipt',status=400){super(message);this.status=status;}}
export function publicKey(pem){try{const k=createPublicKey(pem);if(k.asymmetricKeyType!=='ec'||k.asymmetricKeyDetails.namedCurve!=='prime256v1')throw 0;const der=k.export({type:'spki',format:'der'});return {key:k,kid:createHash('sha256').update(der).digest('hex').slice(0,32),pem:k.export({type:'spki',format:'pem'})};}catch{throw new Rejected('A P-256 public key is required');}}
export async function validate(receipt,repo,{event,now=Date.now(),maxAgeDays=7}={}){
 if(typeof receipt!=='string'||receipt.length>2200)throw new Rejected();
 const parts=receipt.split('.');if(parts.length!==2||parts.some(x=>! /^[A-Za-z0-9_-]+$/.test(x)))throw new Rejected();
 const raw=Buffer.from(parts[0],'base64url'),sig=Buffer.from(parts[1],'base64url');if(raw.toString('base64url')!==parts[0]||sig.toString('base64url')!==parts[1]||sig.length<68||sig.length>72)throw new Rejected();
 let p;try{p=JSON.parse(raw.toString('utf8'));}catch{throw new Rejected();}
 if(!p||Array.isArray(p)||Object.keys(p).join(',')!==fields.join(',')||JSON.stringify(p)!==raw.toString('utf8'))throw new Rejected();
 if(p.v!==1||! /^[a-f0-9]{32}$/.test(p.kid)||! /^[a-f0-9]{32}$/.test(p.device)||! /^[a-f0-9]{32}$/.test(p.run)||typeof p.event!=='string'||! /^[a-zA-Z0-9_-]{1,64}$/.test(p.event)||!event||p.event!==event||p.scope!==scope||typeof p.name!=='string'||p.name.trim()!==p.name||p.name.length<1||p.name.length>24||/[\u0000-\u001f\u007f]/.test(p.name)||!Number.isSafeInteger(p.ms)||p.ms<1||p.ms>3725000||!Number.isSafeInteger(p.at)||p.at<1577836800000||p.at>now+120000)throw new Rejected();
 const key=await repo.key(p.kid);if(!key||!key.active||key.device.replaceAll('-','')!==p.device||key.event!==p.event||p.at<Number(key.not_before_ms))throw new Rejected();
 const k=publicKey(key.public_pem);if(k.kid!==p.kid||!verify('sha256',raw,k.key,sig))throw new Rejected();
 const hash=createHash('sha256').update(raw).digest('hex');
 const existing=await repo.status(p.run,hash);if(existing==='conflict')throw new Rejected('Run cannot be submitted',409);
 if(existing!=='saved'&&p.at<now-Math.min(30,Math.max(1,maxAgeDays))*86400000)throw new Rejected('Receipt expired');
 return {payload:p,hash,saved:existing==='saved'};
}
export function contacts(email,phone){if(typeof email!=='string'||typeof phone!=='string')throw new Rejected('Enter email and phone');email=email.trim().toLowerCase();phone=phone.replace(/[ ()-]/g,'');if(email.length>254||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||! /^\+[1-9][0-9]{6,14}$/.test(phone))throw new Rejected('Enter a valid email and international phone number');return {email,phone};}
export async function preview(body,repo,options){if(Object.keys(body).join(',')!=='receipt')throw new Rejected();const r=await validate(body.receipt,repo,options);return {name:r.payload.name,time:(r.payload.ms/1000).toFixed(3),saved:r.saved};}
export async function submit(body,repo,options){if(Object.keys(body).sort().join(',')!=='email,phone,receipt')throw new Rejected();const c=contacts(body.email,body.phone);const r=await validate(body.receipt,repo,options);if(!r.saved)await repo.insert(r.payload,r.hash,c);return {saved:true};}
export function compareScores(a,b){return a.time_ms-b.time_ms||a.completed_at_ms-b.completed_at_ms||a.run_id.localeCompare(b.run_id);}

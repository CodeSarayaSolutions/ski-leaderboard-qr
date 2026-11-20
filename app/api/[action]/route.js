import {NextResponse} from 'next/server';
import {preview,submit,publicKey,Rejected} from '../../../lib/receipt.mjs';
import {repository} from '../../../lib/repository.mjs';
import {signIn,authorize,sameOrigin,submitLimiter} from '../../../lib/auth.mjs';
export const runtime='nodejs';export const dynamic='force-dynamic';
const headers={'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer'};
export async function POST(request,{params}){try{
 sameOrigin(request,process.env);const {action}=await params;const size=Number(request.headers.get('content-length')||0);if(size>4096)throw new Rejected('Request too large',413);
 const reader=request.body?.getReader();let text='',bytes=0;const decoder=new TextDecoder();if(!reader)throw new Rejected();for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.length;if(bytes>4096){await reader.cancel();throw new Rejected('Request too large',413);}text+=decoder.decode(value,{stream:true});}text+=decoder.decode();let body;try{body=JSON.parse(text);}catch{throw new Rejected();}if(!body||typeof body!=='object'||Array.isArray(body))throw new Rejected();
 const options={event:process.env.EVENT_ID,maxAgeDays:Number(process.env.RECEIPT_MAX_AGE_DAYS)||7};let data;
 if(action==='preview'||action==='submit'){submitLimiter.take('claim-global');data=await(action==='preview'?preview:submit)(body,repository,options);}
 else if(action==='login'){const s=signIn(body.credential,process.env,request.headers);const response=NextResponse.json({ok:true},{headers});response.cookies.set('slalom_admin',s.token,{httpOnly:true,secure:s.secure,sameSite:'strict',maxAge:3600,path:'/'});return response;}
 else {authorize(request.cookies.get('slalom_admin')?.value,process.env,request.headers);
  if(action==='scores'){const page=Number(body.page||0);if(!Number.isSafeInteger(page)||page<0||page>100000)throw new Rejected();data={scores:await repository.scores(page)};}
  else if(action==='keys')data={keys:await repository.keys()};
  else if(action==='register'){if(! /^[a-f0-9]{32}$/.test(body.device)||body.event!==process.env.EVENT_ID)throw new Rejected();const k=publicKey(body.pem);await repository.register(k,body.device,body.event);data={ok:true,kid:k.kid};}
  else if(action==='revoke'){if(! /^[a-f0-9]{32}$/.test(body.kid))throw new Rejected();await repository.revoke(body.kid);data={ok:true};}
  else if(action==='logout'){const response=NextResponse.json({ok:true},{headers});response.cookies.set('slalom_admin','',{httpOnly:true,maxAge:0,path:'/'});return response;}
  else throw new Rejected('Not found',404);
 }
 return NextResponse.json(data,{headers});
 }catch(error){return NextResponse.json({error:error instanceof Rejected?error.message:'Service temporarily unavailable'},{status:error instanceof Rejected?error.status:503,headers});}}

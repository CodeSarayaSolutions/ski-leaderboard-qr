import pg from 'pg';
import {Rejected} from './receipt.mjs';
const pools=new Map();function pool(role){const url=process.env[role==='admin'?'DATABASE_URL_ADMIN':'DATABASE_URL_CLAIM'];if(!url)throw new Rejected('Service not configured',503);if(!pools.has(role))pools.set(role,new pg.Pool({connectionString:url,max:4,connectionTimeoutMillis:5000,statement_timeout:5000}));return pools.get(role);}
async function query(fn,args=[],role='claim'){const result=await pool(role).query(`select * from "velo-leaderboard".${fn}(${args.map((_,i)=>'$'+(i+1)).join(',')})`,args);return result.rows;}
export const repository={
 async key(kid){return (await query('qr_v2_lookup_key',[kid]))[0];},
 async status(run,hash){return (await query('qr_v2_receipt_status',[run,hash]))[0].qr_v2_receipt_status;},
 async insert(p,hash,c){const r=(await query('qr_v2_submit',[p.run,p.kid,p.device,p.event,p.name,p.ms,p.at,p.scope,hash,c.email,c.phone]))[0].qr_v2_submit;if(r!=='saved')throw new Rejected('Run cannot be submitted',409);},
 async scores(page){return query('qr_v2_list_scores',[page*50,50],'admin');},
 async keys(){return query('qr_v2_list_keys',[],'admin');},
 async register(k,device,event){return query('qr_v2_register_key',[k.kid,k.pem,device,event],'admin');},
 async revoke(kid){return query('qr_v2_revoke_key',[kid],'admin');}
};

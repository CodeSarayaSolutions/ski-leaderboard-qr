import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {generateKeyPairSync,randomUUID,sign} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {createRepository,API_SCHEMA} from '../lib/postgrest-repository.mjs';
import {publicKey,scope,preview,submit} from '../lib/receipt.mjs';
const first=readFileSync(new URL('../migrations/001_official_qr.sql',import.meta.url),'utf8');
const second=readFileSync(new URL('../migrations/002_server_rpc.sql',import.meta.url),'utf8');
const token=role=>[Buffer.from('{"alg":"HS256"}').toString('base64url'),Buffer.from(JSON.stringify({role})).toString('base64url'),Buffer.alloc(32).toString('base64url')].join('.');
const env={NEXT_PUBLIC_SUPABASE_URL:'https://test.example.org',NEXT_PUBLIC_SUPABASE_DB_SCHEMA:'velo-leaderboard',SUPABASE_SERVICE_ROLE_KEY:token('service_role')};
const args={lookup_key:['k'],receipt_status:['r','h'],submit:['r','k','d','e','n','t','a','s','h','em','ph'],list_scores:['skip','take'],list_keys:[],register_key:['k','p','d','e'],revoke_key:['k']};
async function database(){const db=new PGlite();await db.exec('CREATE ROLE service_role NOLOGIN BYPASSRLS;CREATE ROLE anon NOLOGIN;CREATE ROLE authenticated NOLOGIN;');await db.exec(first);await db.exec(second);return db;}
test('configuration fails closed before HTTP; no anon fallback; only HTTPS clean origin and exact data schema',async()=>{
 for(const e of [{},{...env,SUPABASE_SERVICE_ROLE_KEY:''},{...env,SUPABASE_SERVICE_ROLE_KEY:token('anon')},{...env,SUPABASE_SERVICE_ROLE_KEY:'',NEXT_PUBLIC_SUPABASE_ANON_KEY:token('anon')},{...env,NEXT_PUBLIC_SUPABASE_DB_SCHEMA:'public'},...['http://test.example.org','https://test.example.org/rest/v1','https://user:pass@test.example.org','https://test.example.org?x=1','https://test.example.org#x'].map(u=>({...env,NEXT_PUBLIC_SUPABASE_URL:u}))]){
  let calls=0;await assert.rejects(createRepository({env:e,fetchImpl:async()=>{calls++;}}).keys(),e=>e.status===503&&e.message==='Service not configured');assert.equal(calls,0);
 }
});
test('transport uses exact RPCs/profile/server credential; redirects/cache/errors/timeouts fail safely',async()=>{
 let calls=[];const repo=createRepository({env,fetchImpl:async(url,options)=>{calls.push({url,options});return new Response('[]');}});await repo.keys();await repo.scores(2);
 for(const {url,options:o} of calls){assert.ok(url.startsWith(env.NEXT_PUBLIC_SUPABASE_URL+'/rest/v1/rpc/'));assert.equal(o.method,'POST');assert.equal(o.redirect,'error');assert.equal(o.cache,'no-store');assert.equal(o.headers['Content-Profile'],API_SCHEMA);assert.equal(o.headers['Accept-Profile'],API_SCHEMA);assert.equal(o.headers.Authorization,'Bearer '+env.SUPABASE_SERVICE_ROLE_KEY);assert.equal(o.headers.apikey,env.SUPABASE_SERVICE_ROLE_KEY);assert.ok(o.signal);}
 assert.deepEqual(JSON.parse(calls[1].options.body),{skip:100,take:50});
 for(const fetchImpl of [async()=>new Response('private upstream detail',{status:401}),async()=>{throw Error('private transport detail');},async()=>new Response('not json'),async()=>new Response('x'.repeat(1048577))])await assert.rejects(createRepository({env,fetchImpl}).keys(),e=>e.status===503&&e.message==='Service temporarily unavailable');
 await assert.rejects(createRepository({env,timeoutMs:5,fetchImpl:async(u,o)=>new Promise((resolve,reject)=>{const timer=setTimeout(()=>resolve(new Response('[]')),100);o.signal.addEventListener('abort',()=>{clearTimeout(timer);reject(o.signal.reason);});})}).keys(),e=>e.status===503);
});
test('additive wrappers rerun; no anon/authenticated/ordinary RPC or private table access; owner defaults deny',async()=>{
 const db=await database();try{
  await db.exec(`INSERT INTO "velo-leaderboard".entries(participant_name,time_ms,entry_date) VALUES('Legacy Racer',12345,'2020-01-01');`);const before=(await db.query('SELECT * FROM "velo-leaderboard".entries')).rows;await db.exec(first);await db.exec(second);assert.deepEqual((await db.query('SELECT * FROM "velo-leaderboard".entries')).rows,before);
  assert.equal((await db.query(`SELECT count(*)::int n FROM pg_proc WHERE pronamespace='alpine_qr_api'::regnamespace`)).rows[0].n,7);
  await db.exec('CREATE ROLE ordinary NOLOGIN');
  for(const role of ['anon','authenticated','ordinary']){await db.exec('SET ROLE '+role);await assert.rejects(db.query('SELECT * FROM alpine_qr_api.list_scores(0,50)'));await assert.rejects(db.query('SELECT * FROM "velo-leaderboard".qr_signed_claims'));await assert.rejects(db.query('SELECT * FROM "velo-leaderboard".qr_v2_list_keys()'));await db.exec('RESET ROLE');}
  await db.exec('SET ROLE service_role');assert.deepEqual((await db.query('SELECT * FROM alpine_qr_api.list_scores(0,50)')).rows,[]);await assert.rejects(db.query('SELECT * FROM "velo-leaderboard".qr_signed_claims'));await db.exec('RESET ROLE');
  const f=(await db.query(`SELECT prosecdef,proconfig,pg_get_userbyid(proowner) owner FROM pg_proc WHERE pronamespace='alpine_qr_api'::regnamespace`)).rows;assert.ok(f.every(x=>x.prosecdef&&x.proconfig.includes('search_path=pg_catalog')&&x.owner==='qr_api_owner'));
  // Temporary test schema proves future functions created as the wrapper owner lack PUBLIC EXECUTE.
  await db.exec('CREATE SCHEMA test_defaults AUTHORIZATION qr_api_owner;SET ROLE qr_api_owner;CREATE FUNCTION test_defaults.probe() RETURNS int LANGUAGE sql AS $$SELECT 1$$;RESET ROLE;');assert.equal((await db.query(`SELECT has_function_privilege('ordinary','test_defaults.probe()','EXECUTE') allowed`)).rows[0].allowed,false);
 }finally{await db.close();}
});
test('real SQL wrappers behind mocked HTTP preserve signature-before-write, first write, read-only scan, contacts, revocation',async()=>{
 const db=await database();const calls=[];try{
  const repo=createRepository({env,fetchImpl:async(url,o)=>{const name=new URL(url).pathname.split('/').at(-1);assert.ok(Object.hasOwn(args,name));assert.equal(o.headers['Content-Profile'],API_SCHEMA);const body=JSON.parse(o.body);assert.deepEqual(Object.keys(body),args[name]);calls.push(name);await db.exec('SET ROLE service_role');try{const a=args[name],q=await db.query(`SELECT * FROM alpine_qr_api.${name}(${a.map((_,i)=>'$'+(i+1)).join(',')})`,a.map(k=>body[k]));const value=['receipt_status','submit'].includes(name)?q.rows[0][name]:['register_key','revoke_key'].includes(name)?null:q.rows;return Response.json(value);}finally{await db.exec('RESET ROLE');}}});
  const {publicKey:pub,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),key=publicKey(pub.export({type:'spki',format:'pem'})),device=randomUUID().replaceAll('-','');await repo.register(key,device,'test-event');const p={v:1,kid:key.kid,device,event:'test-event',run:randomUUID().replaceAll('-',''),name:'Test Racer',ms:12345,at:Date.now()+100,scope};const raw=Buffer.from(JSON.stringify(p)),receipt=raw.toString('base64url')+'.'+sign('sha256',raw,privateKey).toString('base64url'),options={event:'test-event',now:p.at+1000};
  calls.length=0;await preview({receipt},repo,options);assert.deepEqual(calls,['lookup_key','receipt_status']);assert.equal((await db.query('SELECT count(*)::int n FROM "velo-leaderboard".entries')).rows[0].n,0);
  const bad=Buffer.from(JSON.stringify({...p,name:'Tampered'})).toString('base64url')+'.'+receipt.split('.')[1];calls.length=0;await assert.rejects(submit({receipt:bad,email:'sample@example.org',phone:'+12025550101'},repo,options));assert.deepEqual(calls,['lookup_key']);
  calls.length=0;await submit({receipt,email:'sample@example.org',phone:'+12025550101'},repo,options);assert.equal(calls.filter(x=>x==='submit').length,1);await submit({receipt,email:'changed@example.org',phone:'+12025550102'},repo,options);assert.equal(calls.filter(x=>x==='submit').length,1);
  // Lost-response retry reaches the same atomic SQL function and keeps the first contact data.
  const {createHash}=await import('node:crypto');await repo.insert(p,createHash('sha256').update(raw).digest('hex'),{email:'changed@example.org',phone:'+12025550102'});
  const rows=await repo.scores(0);assert.equal(rows.length,1);assert.equal(rows[0].email,'sample@example.org');assert.equal((await db.query('SELECT phone_number FROM "velo-leaderboard".entries')).rows[0].phone_number,null);const view=await preview({receipt},repo,options);assert.deepEqual(Object.keys(view),['name','time','saved']);await repo.revoke(key.kid);await assert.rejects(preview({receipt},repo,options));
 }finally{await db.close();}
});
test('follow-up refuses missing prerequisite and colliding schema, no data deletion or legacy exposure grants',async()=>{
 const db=new PGlite();try{await assert.rejects(db.exec(second));await db.exec('ROLLBACK');await db.exec('CREATE ROLE service_role NOLOGIN;');await db.exec(first);await db.exec('CREATE SCHEMA alpine_qr_api;CREATE TABLE alpine_qr_api.unrelated(id int);INSERT INTO alpine_qr_api.unrelated VALUES(1)');await assert.rejects(db.exec(second));await db.exec('ROLLBACK');assert.equal((await db.query('SELECT count(*)::int n FROM alpine_qr_api.unrelated')).rows[0].n,1);}finally{await db.close();}
 assert.equal(/\b(?:DELETE|TRUNCATE|DROP)\b/i.test(second.replace(/--[^\n]*/g,'')),false);
 assert.equal(/GRANT[^;]*ON SCHEMA "velo-leaderboard" TO service_role/i.test(second),false);
 const entry=readFileSync(new URL('../lib/repository.mjs',import.meta.url),'utf8');assert.match(entry,/import 'server-only'/);assert.doesNotMatch(entry,/\bpg\b|DATABASE_URL/);
});


test('unexpected inherited anonymous access fails migration without changing scores',async()=>{const db=await database();try{await db.exec('GRANT qr_claim TO anon');await assert.rejects(db.exec(second));await db.exec('ROLLBACK');assert.equal((await db.query('SELECT count(*)::int n FROM "velo-leaderboard".entries')).rows[0].n,0);}finally{await db.close();}});

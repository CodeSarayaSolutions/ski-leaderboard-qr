import {createServer} from 'node:http';
import {randomBytes} from 'node:crypto';
import next from 'next';
import nextEnv from '@next/env';
const {loadEnvConfig}=nextEnv;
loadEnvConfig(process.cwd());
const local=process.env.ADMIN_MODE==='local';
process.env.INTERNAL_LOOPBACK_TOKEN=randomBytes(32).toString('hex');
const app=next({dev:process.argv.includes('--dev')});await app.prepare();
const handler=app.getRequestHandler();const port=Number(process.env.PORT||3000);
createServer((req,res)=>{
 delete req.headers['x-internal-loopback'];
 if(local){const address=req.socket.remoteAddress;const host=req.headers.host;
  if(req.headers.forwarded||req.headers['x-forwarded-for']||req.headers['x-forwarded-host']||!['127.0.0.1','::1','::ffff:127.0.0.1'].includes(address)||!['127.0.0.1:'+port,'localhost:'+port,'[::1]:'+port].includes(host)){res.writeHead(403);res.end();return;}
  req.headers['x-internal-loopback']=process.env.INTERNAL_LOOPBACK_TOKEN;
 }
 handler(req,res);
}).listen(port,local?'127.0.0.1':process.env.HOST||'127.0.0.1');

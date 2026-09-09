import { json, nowIso, randomBytes, b64url, pbkdf2, requireAdmin } from './_utils.js';

async function ensureTables(env){
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS admin_config (id INTEGER PRIMARY KEY CHECK (id=1), pin_hash TEXT NOT NULL, salt TEXT NOT NULL, iterations INTEGER NOT NULL DEFAULT 100000, updated_at TEXT NOT NULL)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)').run();
}

export async function onRequestPost({request,env}){
  try{
    await ensureTables(env);
    if(!(await requireAdmin(request,env)))return json({error:'No autorizado.'},401);
    const body=await request.json().catch(()=>({}));const pin=String(body.pin||'').trim();
    if(!/^\d{4,8}$/.test(pin))return json({error:'El PIN debe tener entre 4 y 8 números.'},400);
    const salt=randomBytes(16),iterations=100000,hash=await pbkdf2(pin,salt,iterations);
    await env.DB.prepare('INSERT INTO admin_config(id,pin_hash,salt,iterations,updated_at) VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET pin_hash=excluded.pin_hash,salt=excluded.salt,iterations=excluded.iterations,updated_at=excluded.updated_at').bind(b64url(hash),b64url(salt),iterations,nowIso()).run();
    return json({ok:true});
  }catch(e){return json({error:'No se pudo actualizar el PIN.'},500)}
}

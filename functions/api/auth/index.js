import { json, nowIso, randomBytes, b64url, fromB64url, sha256, pbkdf2, parseCookies, sessionCookie, clearSessionCookie, cleanSessions } from '../_utils.js';

async function ensureTables(env){
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS admin_config (id INTEGER PRIMARY KEY CHECK (id=1), pin_hash TEXT NOT NULL, salt TEXT NOT NULL, iterations INTEGER NOT NULL DEFAULT 100000, updated_at TEXT NOT NULL)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)').run();
}

async function savePinConfig(env,pin){
  const salt=randomBytes(16), iterations=100000, hash=await pbkdf2(pin,salt,iterations);
  await env.DB.prepare('INSERT INTO admin_config(id,pin_hash,salt,iterations,updated_at) VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET pin_hash=excluded.pin_hash,salt=excluded.salt,iterations=excluded.iterations,updated_at=excluded.updated_at')
    .bind(b64url(hash),b64url(salt),iterations,nowIso()).run();
}

export async function onRequestGet({request,env}){
  try{await ensureTables(env);await cleanSessions(env);const cookies=parseCookies(request);const token=cookies.copa_admin;if(!token)return json({authenticated:false});const hash=b64url(await sha256(new TextEncoder().encode(token)));const row=await env.DB.prepare('SELECT expires_at FROM admin_sessions WHERE token_hash=?').bind(hash).first();return json({authenticated:!!row&&Number(row.expires_at)>Date.now()});}
  catch(e){return json({authenticated:false,error:'No se pudo verificar la sesión.'},500)}
}

export async function onRequestPost({request,env}){
  try{
    await ensureTables(env);await cleanSessions(env);
    const body=await request.json().catch(()=>({}));
    const action=body.action;
    if(action==='logout')return new Response(null,{status:204,headers:{'Set-Cookie':clearSessionCookie()}});
    if(action!=='login')return json({error:'Acción no válida.'},400);
    const pin=String(body.pin||'').trim();
    if(!/^\d{4,8}$/.test(pin))return json({error:'El PIN debe tener entre 4 y 8 números.'},400);

    let cfg=await env.DB.prepare('SELECT * FROM admin_config WHERE id=1').first();
    let valid=false;

    // If ADMIN_PIN is configured in Cloudflare, it acts as a safe bootstrap/recovery PIN.
    // When it is used successfully, D1 is synchronized to it so the old/stale hash stops causing login failures.
    if(env.ADMIN_PIN && pin===String(env.ADMIN_PIN)){
      valid=true;
      if(!cfg || cfg.pin_hash){ await savePinConfig(env,pin); cfg=await env.DB.prepare('SELECT * FROM admin_config WHERE id=1').first(); }
    }

    if(!valid && cfg){
      const iterations=Number(cfg.iterations)||100000;
      if(iterations>100000){
        return json({error:'La configuración anterior del PIN usa demasiadas iteraciones. Configurá ADMIN_PIN en Cloudflare para migrar el acceso a 100000 iteraciones.'},500);
      }
      const hash=await pbkdf2(pin,fromB64url(cfg.salt),iterations);
      valid=b64url(hash)===cfg.pin_hash;
    }

    if(!valid)return json({error:'PIN incorrecto. Si este era el PIN configurado originalmente, verificá que ADMIN_PIN esté cargado en Cloudflare Pages > Settings > Variables and Secrets.'},401);

    const token=b64url(randomBytes(32));
    const tokenHash=b64url(await sha256(new TextEncoder().encode(token)));
    const expires=Date.now()+7*24*60*60*1000;
    await env.DB.prepare('INSERT INTO admin_sessions(token_hash,expires_at) VALUES(?,?)').bind(tokenHash,expires).run();
    return json({ok:true},200,{'Set-Cookie':sessionCookie(token)});
  }catch(e){return json({error:'Error interno de autenticación.'},500)}
}

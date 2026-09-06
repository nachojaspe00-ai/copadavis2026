import { json, nowIso, randomBytes, b64url, sha256, pbkdf2, parseCookies, sessionCookie, clearSessionCookie, requireAdmin, cleanSessions } from './_utils.js';

export async function onRequestGet({request,env}){
  return json({authenticated: !!(await requireAdmin(request,env))});
}

export async function onRequestPost({request,env}){
  const body=await request.json().catch(()=>({}));
  const action=body.action;
  await cleanSessions(env);
  if(action==='logout') return new Response(null,{status:204,headers:{'Set-Cookie':clearSessionCookie()}});
  if(action==='login'){
    const pin=String(body.pin||''); if(!/^\d{4,8}$/.test(pin)) return json({error:'El PIN debe tener entre 4 y 8 números.'},400);
    let cfg=await env.DB.prepare('SELECT * FROM admin_config WHERE id=1').first();
    if(!cfg){
      if(!env.ADMIN_PIN) return json({error:'ADMIN_PIN no está configurado en Cloudflare.'},500); const initial=String(env.ADMIN_PIN);
      const salt=randomBytes(16), hash=await pbkdf2(initial,salt);
      await env.DB.prepare('INSERT OR IGNORE INTO admin_config(id,pin_hash,salt,iterations,updated_at) VALUES(1,?,?,?,?,?)').bind(b64url(hash),b64url(salt),120000,nowIso()).run();
      cfg=await env.DB.prepare('SELECT * FROM admin_config WHERE id=1').first();
    }
    const hash=await pbkdf2(pin, (await import('./_utils.js')).fromB64url(cfg.salt), cfg.iterations);
    if(b64url(hash)!==cfg.pin_hash) return json({error:'PIN incorrecto.'},401);
    const token=b64url(randomBytes(32)); const tokenHash=b64url(await sha256(new TextEncoder().encode(token))); const exp=Date.now()+7*86400000;
    await env.DB.prepare('INSERT INTO admin_sessions(token_hash,expires_at) VALUES(?,?)').bind(tokenHash,exp).run();
    return json({ok:true},200,{'Set-Cookie':sessionCookie(token)});
  }
  return json({error:'Acción no válida.'},400);
}

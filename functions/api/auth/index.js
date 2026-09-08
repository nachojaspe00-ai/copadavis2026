import { json, nowIso, randomBytes, b64url, sha256, pbkdf2, fromB64url, sessionCookie, clearSessionCookie, requireAdmin, cleanSessions } from '../_utils.js';

async function ensureTables(env) {
  if (!env?.DB) throw new Error('D1 binding DB no disponible');
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_config (id INTEGER PRIMARY KEY CHECK (id=1), pin_hash TEXT NOT NULL, salt TEXT NOT NULL, iterations INTEGER NOT NULL DEFAULT 120000, updated_at TEXT NOT NULL)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at)`).run();
}

function detail(error){ return String(error?.message || error || 'Error desconocido').slice(0,300); }

export async function onRequestGet({request,env}) {
  try {
    await ensureTables(env);
    return json({authenticated: !!(await requireAdmin(request,env))});
  } catch (e) {
    return json({error:'No se pudo acceder a la autenticación.', detail:detail(e)},500);
  }
}

export async function onRequestPost({request,env}) {
  try {
    await ensureTables(env);
    const body = await request.json().catch(()=>({}));
    const action = body.action;
    await cleanSessions(env);

    if (action === 'logout') {
      return new Response(null,{status:204,headers:{'Set-Cookie':clearSessionCookie()}});
    }

    if (action === 'login') {
      const pin = String(body.pin || '');
      if (!/^\d{4,8}$/.test(pin)) return json({error:'El PIN debe tener entre 4 y 8 números.'},400);

      let cfg = await env.DB.prepare('SELECT * FROM admin_config WHERE id=1').first();
      if (!cfg) {
        if (!env.ADMIN_PIN) return json({error:'Falta configurar ADMIN_PIN en Cloudflare.'},500);
        const initial = String(env.ADMIN_PIN);
        const salt = randomBytes(16);
        const hash = await pbkdf2(initial,salt,120000);
        await env.DB.prepare('INSERT OR IGNORE INTO admin_config(id,pin_hash,salt,iterations,updated_at) VALUES(1,?,?,?,?,?)')
          .bind(b64url(hash),b64url(salt),120000,nowIso()).run();
        cfg = await env.DB.prepare('SELECT * FROM admin_config WHERE id=1').first();
      }

      const hash = await pbkdf2(pin,fromB64url(cfg.salt),cfg.iterations);
      if (b64url(hash) !== cfg.pin_hash) return json({error:'PIN incorrecto.'},401);

      const token = b64url(randomBytes(32));
      const tokenHash = b64url(await sha256(new TextEncoder().encode(token)));
      const exp = Date.now()+7*86400000;
      await env.DB.prepare('INSERT INTO admin_sessions(token_hash,expires_at) VALUES(?,?)').bind(tokenHash,exp).run();
      return json({ok:true},200,{'Set-Cookie':sessionCookie(token)});
    }

    return json({error:'Acción no válida.'},400);
  } catch (e) {
    return json({error:'Error en autenticación.',detail:detail(e)},500);
  }
}

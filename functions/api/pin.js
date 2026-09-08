import { json, nowIso, randomBytes, b64url, pbkdf2, requireAdmin } from './_utils.js';

export async function onRequestPost({request,env}) {
  try {
    if (!(await requireAdmin(request,env))) return json({error:'No autorizado.'},401);
    const body = await request.json().catch(()=>({}));
    const pin = String(body.pin || '');
    if (!/^\d{4,8}$/.test(pin)) return json({error:'El PIN debe tener entre 4 y 8 números.'},400);
    const salt=randomBytes(16);
    const hash=await pbkdf2(pin,salt,120000);
    await env.DB.prepare(`INSERT INTO admin_config(id,pin_hash,salt,iterations,updated_at) VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET pin_hash=excluded.pin_hash,salt=excluded.salt,iterations=excluded.iterations,updated_at=excluded.updated_at`)
      .bind(b64url(hash),b64url(salt),120000,nowIso()).run();
    return json({ok:true});
  } catch(e) {
    return json({error:'No se pudo actualizar el PIN.',detail:String(e?.message||e).slice(0,300)},500);
  }
}

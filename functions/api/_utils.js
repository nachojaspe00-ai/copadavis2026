export function json(data, status=200, extraHeaders={}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...extraHeaders
    }
  });
}

export function nowIso() { return new Date().toISOString(); }

export function randomBytes(n=32) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

export function b64url(bytes) {
  let s='';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

export function fromB64url(s) {
  s = String(s).replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}

export async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export async function pbkdf2(pin, salt, iterations=120000) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(pin)),
    {name:'PBKDF2'},
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {name:'PBKDF2', salt, iterations, hash:'SHA-256'},
    key,
    256
  );
  return new Uint8Array(bits);
}

export function parseCookies(request) {
  const raw = request.headers.get('Cookie') || '';
  const out = {};
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0,i).trim()] = decodeURIComponent(part.slice(i+1).trim());
  }
  return out;
}

export function sessionCookie(token) {
  return `copa_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7*86400}`;
}

export function clearSessionCookie() {
  return 'copa_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
}

export async function requireAdmin(request, env) {
  try {
    if (!env?.DB) return false;
    const token = parseCookies(request).copa_session;
    if (!token) return false;
    const tokenHash = b64url(await sha256(new TextEncoder().encode(token)));
    const row = await env.DB.prepare(
      'SELECT token_hash FROM admin_sessions WHERE token_hash=? AND expires_at>?'
    ).bind(tokenHash, Date.now()).first();
    return !!row;
  } catch {
    return false;
  }
}

export async function cleanSessions(env) {
  if (!env?.DB) return;
  await env.DB.prepare('DELETE FROM admin_sessions WHERE expires_at<=?').bind(Date.now()).run();
}

const COOKIE = 'cd_admin';
const SESSION_DAYS = 7;

export function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra }
  });
}

export function nowIso() { return new Date().toISOString(); }
export function randomBytes(n=32) { const a=new Uint8Array(n); crypto.getRandomValues(a); return a; }
export function b64url(bytes) { return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
export function fromB64url(s) { s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); }
export async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
export async function hmac(secret, value) { const key=await crypto.subtle.importKey('raw',secret,{name:'HMAC',hash:'SHA-256'},false,['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC',key,value)); }
export function timingSafeEqual(a,b){ if(a.length!==b.length)return false; let x=0; for(let i=0;i<a.length;i++)x|=a[i]^b[i]; return x===0; }
export async function pbkdf2(pin, salt, iterations=100000) { const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(pin),{name:'PBKDF2'},false,['deriveBits']); return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations,hash:'SHA-256'},key,256)); }
export function parseCookies(request){ const out={}; for(const part of (request.headers.get('Cookie')||'').split(';')){const i=part.indexOf('=');if(i>0)out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim())} return out; }
export function sessionCookie(token){ return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS*86400}`; }
export function clearSessionCookie(){ return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`; }
export async function requireAdmin(request, env){
  const token=parseCookies(request)[COOKIE]; if(!token) return null;
  const hash=b64url(await sha256(new TextEncoder().encode(token)));
  const row=await env.DB.prepare('SELECT token_hash, expires_at FROM admin_sessions WHERE token_hash=? AND expires_at>?').bind(hash,Date.now()).first();
  return row?token:null;
}
export async function cleanSessions(env){ await env.DB.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?').bind(Date.now()).run(); }

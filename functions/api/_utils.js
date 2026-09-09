export function json(data,status=200,extra={}){
  return new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8',...extra}});
}
export function nowIso(){return new Date().toISOString()}
export function randomBytes(n){const a=new Uint8Array(n);crypto.getRandomValues(a);return a}
export function b64url(bytes){let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
export function fromB64url(s){s=String(s||'').replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const bin=atob(s);return Uint8Array.from(bin,c=>c.charCodeAt(0))}
export async function sha256(bytes){return new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))}
export async function pbkdf2(pin,salt,iterations=120000){const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(String(pin)),{name:'PBKDF2'},false,['deriveBits']);return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations,hash:'SHA-256'},key,256))}
export function parseCookies(request){const out={};for(const part of (request.headers.get('Cookie')||'').split(';')){const i=part.indexOf('=');if(i<0)continue;out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim())}return out}
export function sessionCookie(token){return `copa_admin=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`}
export function clearSessionCookie(){return 'copa_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'}
export async function requireAdmin(request,env){
  if(!env?.DB)return false;
  const token=parseCookies(request).copa_admin;if(!token)return false;
  const hash=b64url(await sha256(new TextEncoder().encode(token)));
  const row=await env.DB.prepare('SELECT token_hash,expires_at FROM admin_sessions WHERE token_hash=?').bind(hash).first();
  return !!row && Number(row.expires_at)>Date.now();
}
export async function cleanSessions(env){if(env?.DB)await env.DB.prepare('DELETE FROM admin_sessions WHERE expires_at<=?').bind(Date.now()).run()}

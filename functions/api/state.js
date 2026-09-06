import { json, nowIso, requireAdmin } from './_utils.js';
const emptyState={teams:{},players:[],dates:[]};
export async function onRequestGet({env}){
  const row=await env.DB.prepare('SELECT data,updated_at FROM app_state WHERE id=1').first();
  if(!row){ await env.DB.prepare('INSERT OR IGNORE INTO app_state(id,data,updated_at) VALUES(1,?,?)').bind(JSON.stringify(emptyState),nowIso()).run(); return json({state:emptyState,updatedAt:nowIso()}); }
  let state; try{state=JSON.parse(row.data)}catch{state=emptyState}
  return json({state,updatedAt:row.updated_at});
}
export async function onRequestPost({request,env}){
  if(!(await requireAdmin(request,env))) return json({error:'No autorizado.'},401);
  const body=await request.json().catch(()=>({})); const state=body.state;
  if(!state||typeof state!=='object'||!state.teams||!Array.isArray(state.players)||!Array.isArray(state.dates)) return json({error:'Estado inválido.'},400);
  const updated=nowIso();
  await env.DB.prepare('INSERT INTO app_state(id,data,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at').bind(JSON.stringify(state),updated).run();
  return json({ok:true,updatedAt:updated});
}

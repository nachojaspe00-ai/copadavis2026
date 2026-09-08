import { json, nowIso, requireAdmin } from './_utils.js';

const emptyState={teams:{},players:[],dates:[]};

async function ensureAppState(env){
  if(!env?.DB) throw new Error('D1 binding DB no disponible');
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS app_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`).run();
}

function errorMessage(error){
  const msg=error?.message||String(error||'Error desconocido');
  return msg.length>300?msg.slice(0,300):msg;
}

export async function onRequestGet({env}){
  try{
    await ensureAppState(env);
    const row=await env.DB.prepare('SELECT data,updated_at FROM app_state WHERE id=1').first();
    if(!row){
      const updated=nowIso();
      await env.DB.prepare('INSERT INTO app_state(id,data,updated_at) VALUES(1,?,?)')
        .bind(JSON.stringify(emptyState),updated).run();
      return json({state:emptyState,updatedAt:updated});
    }
    let state;
    try{state=JSON.parse(row.data)}catch{state=emptyState}
    return json({state,updatedAt:row.updated_at});
  }catch(error){
    return json({error:'No se pudo leer la base de datos.',detail:errorMessage(error)},500);
  }
}

export async function onRequestPost({request,env}){
  try{
    if(!(await requireAdmin(request,env))) return json({error:'No autorizado.'},401);
    const body=await request.json().catch(()=>({}));
    const state=body.state;
    if(!state||typeof state!=='object'||!state.teams||!Array.isArray(state.players)||!Array.isArray(state.dates)){
      return json({error:'Estado inválido.'},400);
    }
    await ensureAppState(env);
    const updated=nowIso();
    await env.DB.prepare(`INSERT INTO app_state(id,data,updated_at)
      VALUES(1,?,?)
      ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at`)
      .bind(JSON.stringify(state),updated).run();
    return json({ok:true,updatedAt:updated});
  }catch(error){
    return json({error:'No se pudo guardar en D1.',detail:errorMessage(error)},500);
  }
}
